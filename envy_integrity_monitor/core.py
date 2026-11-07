"""Encrypted file-integrity baselines with change detection.

A self-contained engine for the ENVY BLACK VEIL Integrity Monitor, packaged as a
standalone app. A *baseline* records the SHA-256, size and path of every file
under a folder, sealed in the same AES-256-GCM envelope as ENVY Vault. A *check*
re-scans the folder and reports what has been added, removed or modified since.
Accepting the current state writes a new, hash-chained revision; earlier
revisions are never overwritten.

Honest by design: a hash proves a file's bytes changed since the baseline — not
who changed them, when (the OS clock is an assertion), or whether a change is
benign. It only sees files readable at scan time, and a file that changes and
changes back looks unchanged.

Standard library only, apart from ``cryptography`` for the encrypted envelope.
"""

from __future__ import annotations

import datetime
import hashlib
import html
import json
import os
import stat
import uuid
from pathlib import Path

# --- Shared errors and bounds ------------------------------------------------

MAGIC = b"ENVYVAULT2\x00"
MAX_ENVELOPE = 16 * 1024 * 1024        # the encrypted baseline
MAX_FILES = 50000
MAX_READ = 1024 * 1024 * 1024          # per-file hashing ceiling (1 GiB)
MAX_REVISIONS = 10000
MIN_PASSPHRASE = 12
CHUNK = 1024 * 1024


class IntegrityError(RuntimeError):
    """A clean, expected error: a bad passphrase, an invalid baseline, a chain mismatch."""


# --- Safe file primitives (never follow symlinks, never overwrite) -----------

def read_regular(path, limit: int = MAX_ENVELOPE) -> bytes:
    path = Path(path).expanduser()
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > limit:
            raise IntegrityError("Expected a regular file within the size limit")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise IntegrityError("File exceeded the size limit")
    return data


def new_file(path, data: bytes, mode: int = 0o600) -> Path:
    """Write a brand-new file. O_EXCL means an existing file is never overwritten."""
    path = Path(path).expanduser()
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError:
        raise IntegrityError(f"Refusing to overwrite an existing file: {path}") from None
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return path


# --- Encrypted envelope (byte-compatible with ENVY Vault) --------------------

def _key(secret: bytes, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(secret)


def encrypt_bytes(data: bytes, secret: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, nonce = os.urandom(16), os.urandom(12)
    return MAGIC + salt + nonce + AESGCM(_key(secret, salt)).encrypt(nonce, data, MAGIC)


def decrypt_bytes(data: bytes, secret: bytes) -> bytes:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not data.startswith(MAGIC) or len(data) < len(MAGIC) + 44:
        raise IntegrityError("Not an ENVY encrypted envelope")
    blob = data[len(MAGIC):]
    try:
        return AESGCM(_key(secret, blob[:16])).decrypt(blob[16:28], blob[28:], MAGIC)
    except InvalidTag:
        raise IntegrityError("Incorrect passphrase or modified encrypted data") from None


def check_passphrase(secret: bytes) -> bytes:
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < MIN_PASSPHRASE:
        raise IntegrityError(f"Use a passphrase of at least {MIN_PASSPHRASE} bytes")
    return bytes(secret)


# --- Canonical form and field validation -------------------------------------

def _canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _timestamp(value, field="recorded_utc"):
    if not isinstance(value, str) or len(value) > 64:
        raise IntegrityError("Invalid " + field)
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise IntegrityError(field + " must be ISO 8601 with a UTC offset") from None
    if parsed.tzinfo is None or parsed.utcoffset() != datetime.timedelta(0):
        raise IntegrityError(field + " must be expressed in UTC")
    return parsed.isoformat()


def _sha256(value, field="sha256"):
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise IntegrityError(field + " must be 64 lowercase hexadecimal characters")
    return value


def _rel_text(value):
    if not isinstance(value, str) or not value or len(value) > 4096 or "\x00" in value or "\\" in value:
        raise IntegrityError("Invalid file path in baseline")
    if value.startswith("/") or ".." in value.split("/"):
        raise IntegrityError("Baseline paths must be relative and contain no '..'")
    return value


def _validate_entry(value):
    if not isinstance(value, dict) or set(value) != {"path", "size", "sha256"}:
        raise IntegrityError("Invalid baseline file entry")
    size = value["size"]
    if type(size) is not int or not 0 <= size <= MAX_READ:
        raise IntegrityError("Invalid baseline file size")
    return {"path": _rel_text(value["path"]), "size": size, "sha256": _sha256(value["sha256"])}


def _validate_check(value):
    allowed = {"added", "removed", "modified", "unchanged", "scanned_utc"}
    if not isinstance(value, dict) or set(value) != allowed:
        raise IntegrityError("Invalid check summary")
    _timestamp(value["scanned_utc"], "scanned_utc")
    out = {"scanned_utc": value["scanned_utc"]}
    for key in ("added", "removed", "modified", "unchanged"):
        count = value[key]
        if type(count) is not int or count < 0:
            raise IntegrityError("Check counts must be non-negative integers")
        out[key] = count
    return out


def _validate_baseline(data):
    fields = {"schema", "monitor_id", "title", "root", "created_utc", "revision",
              "previous_envelope_sha256", "files", "journal"}
    if not isinstance(data, dict) or set(data) != fields or type(data["schema"]) is not int or data["schema"] != 1:
        raise IntegrityError("Unsupported encrypted baseline schema")
    if not isinstance(data["title"], str) or not data["title"].strip() or len(data["title"]) > 200:
        raise IntegrityError("Invalid monitor title")
    if not isinstance(data["root"], str) or not data["root"] or len(data["root"]) > 4096:
        raise IntegrityError("Invalid monitored root path")
    try:
        uuid.UUID(data["monitor_id"])
    except (ValueError, TypeError, AttributeError):
        raise IntegrityError("Invalid monitor identifier") from None
    _timestamp(data["created_utc"], "created_utc")
    files = data["files"]
    if not isinstance(files, list) or len(files) > MAX_FILES:
        raise IntegrityError("Invalid baseline file list")
    seen, previous_path = set(), None
    for entry in files:
        norm = _validate_entry(entry)
        if norm != entry:
            raise IntegrityError("Baseline file entry is not normalized")
        if entry["path"] in seen:
            raise IntegrityError("Duplicate baseline path")
        if previous_path is not None and entry["path"] < previous_path:
            raise IntegrityError("Baseline files must be sorted by path")
        seen.add(entry["path"]); previous_path = entry["path"]
    revision, journal = data["revision"], data["journal"]
    if type(revision) is not int or not 0 <= revision or revision > MAX_REVISIONS or len(journal) != revision:
        raise IntegrityError("Invalid revision or journal length")
    if not isinstance(data["previous_envelope_sha256"], str) or len(data["previous_envelope_sha256"]) != 64 \
            or any(c not in "0123456789abcdef" for c in data["previous_envelope_sha256"]):
        raise IntegrityError("Invalid previous encrypted revision digest")
    previous = "0" * 64
    for record in journal:
        meta = {"recorded_utc", "check", "previous_sha256", "record_sha256"}
        if not isinstance(record, dict) or set(record) != meta:
            raise IntegrityError("Invalid journal record")
        _timestamp(record["recorded_utc"])
        if _validate_check(record["check"]) != record["check"]:
            raise IntegrityError("Journal check summary is not normalized")
        core = {k: v for k, v in record.items() if k != "record_sha256"}
        if record["previous_sha256"] != previous or hashlib.sha256(_canonical(core)).hexdigest() != record["record_sha256"]:
            raise IntegrityError("Baseline journal hash chain mismatch")
        previous = record["record_sha256"]
    return data


# --- Scanning a directory tree ----------------------------------------------

def scan_tree(root) -> list:
    """Hash every regular file under ``root`` (no symlink following). Returns sorted entries."""
    root = Path(root).expanduser()
    if not root.is_dir():
        raise IntegrityError("The monitored root must be an existing directory")
    entries, count = [], 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            full = Path(dirpath) / name
            try:
                meta = full.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(meta.st_mode):
                continue  # skip symlinks, sockets, devices
            count += 1
            if count > MAX_FILES:
                raise IntegrityError(f"More than {MAX_FILES} files under the root; narrow the scope")
            rel = full.relative_to(root).as_posix()
            entries.append({"path": _rel_text(rel), "size": meta.st_size, "sha256": _hash_file(full)})
    entries.sort(key=lambda e: e["path"])
    return entries


def _hash_file(path) -> str:
    digest = hashlib.sha256()
    read = 0
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(fd, "rb") as stream:
            while True:
                chunk = stream.read(CHUNK)
                if not chunk:
                    break
                read += len(chunk)
                if read > MAX_READ:
                    raise IntegrityError(f"A file exceeds the {MAX_READ} byte hashing limit")
                digest.update(chunk)
    except OSError:
        raise IntegrityError("Could not read a file while scanning") from None
    return digest.hexdigest()


# --- Load / write ------------------------------------------------------------

def _load(source, secret):
    encrypted = read_regular(source, MAX_ENVELOPE)
    try:
        data = json.loads(decrypt_bytes(encrypted, secret))
    except (json.JSONDecodeError, UnicodeError, RecursionError):
        raise IntegrityError("Encrypted baseline does not contain valid JSON") from None
    return _validate_baseline(data), hashlib.sha256(encrypted).hexdigest()


def _write(destination, data, secret):
    check_passphrase(secret)
    encoded = _canonical(_validate_baseline(data))
    if len(encoded) + 128 > MAX_ENVELOPE:
        raise IntegrityError("Baseline exceeds the encrypted size limit")
    new_file(destination, encrypt_bytes(encoded, secret))
    return {"output": str(destination), "monitor_id": data["monitor_id"], "revision": data["revision"],
            "files": len(data["files"]), "encrypted": True, "previous_revision_preserved": True}


def create(destination, title, root, secret):
    files = scan_tree(root)
    data = {"schema": 1, "monitor_id": str(uuid.uuid4()),
            "title": _title(title), "root": str(Path(root).expanduser().resolve()),
            "created_utc": _utc(), "revision": 0, "previous_envelope_sha256": "0" * 64,
            "files": files, "journal": []}
    result = _write(destination, data, secret)
    return dict(result, baselined_files=len(files))


def _title(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 200 or "\x00" in value:
        raise IntegrityError("Invalid monitor title")
    return value


# --- Diff / check ------------------------------------------------------------

def diff(baseline_files, current_files):
    """Compare two sorted entry lists; return added/removed/modified/unchanged."""
    base = {e["path"]: e for e in baseline_files}
    cur = {e["path"]: e for e in current_files}
    added = [cur[p] for p in sorted(cur.keys() - base.keys())]
    removed = [base[p] for p in sorted(base.keys() - cur.keys())]
    modified, unchanged = [], 0
    for p in sorted(base.keys() & cur.keys()):
        if base[p]["sha256"] != cur[p]["sha256"] or base[p]["size"] != cur[p]["size"]:
            modified.append({"path": p, "old_sha256": base[p]["sha256"], "new_sha256": cur[p]["sha256"],
                             "old_size": base[p]["size"], "new_size": cur[p]["size"]})
        else:
            unchanged += 1
    return {"added": added, "removed": removed, "modified": modified, "unchanged": unchanged}


def check(source, secret, root=None):
    """Re-scan the root and report changes since the baseline. Read-only."""
    data, _ = _load(source, secret)
    current = scan_tree(root or data["root"])
    report = diff(data["files"], current)
    changed = len(report["added"]) + len(report["removed"]) + len(report["modified"])
    return {"monitor_id": data["monitor_id"], "title": data["title"], "root": root or data["root"],
            "revision": data["revision"], "scanned_utc": _utc(),
            "added": report["added"], "removed": report["removed"], "modified": report["modified"],
            "unchanged": report["unchanged"], "changed": changed, "clean": changed == 0,
            "basis": "A difference proves the bytes changed since the baseline — not who changed them, "
                     "when, or whether the change is benign."}


def accept(source, destination, secret, root=None):
    """Re-scan, record the change summary in the journal, and write a new baseline revision."""
    data, previous_envelope = _load(source, secret)
    current = scan_tree(root or data["root"])
    report = diff(data["files"], current)
    summary = {"scanned_utc": _utc(),
               "added": len(report["added"]), "removed": len(report["removed"]),
               "modified": len(report["modified"]), "unchanged": report["unchanged"]}
    record = {"recorded_utc": _utc(), "check": _validate_check(summary),
              "previous_sha256": data["journal"][-1]["record_sha256"] if data["journal"] else "0" * 64}
    record["record_sha256"] = hashlib.sha256(_canonical(
        {k: v for k, v in record.items() if k != "record_sha256"})).hexdigest()
    data["files"] = current
    data["journal"].append(record)
    data["revision"] += 1
    data["previous_envelope_sha256"] = previous_envelope
    result = _write(destination, data, secret)
    return dict(result, accepted_changes=summary)


def inspect(source, secret):
    data, envelope = _load(source, secret)
    return {"monitor_id": data["monitor_id"], "title": data["title"], "root": data["root"],
            "revision": data["revision"], "created_utc": data["created_utc"], "envelope_sha256": envelope,
            "files": data["files"],
            "journal": [{"recorded_utc": r["recorded_utc"], **r["check"]} for r in data["journal"]],
            "warning": "Hashes verify integrity since the baseline only. Times are operator/OS assertions, "
                       "and accepting a state trusts whatever is on disk at that moment."}


# --- Plaintext export --------------------------------------------------------

def export(source, destination, secret, format="html", root=None):
    if format not in ("html", "json"):
        raise IntegrityError("Export format must be html or json")
    data, envelope = _load(source, secret)
    report = check(source, secret, root)
    out = {"monitor": {"monitor_id": data["monitor_id"], "title": data["title"], "root": data["root"],
                       "revision": data["revision"], "created_utc": data["created_utc"]},
           "scanned_utc": report["scanned_utc"], "clean": report["clean"],
           "added": report["added"], "removed": report["removed"], "modified": report["modified"],
           "unchanged": report["unchanged"], "envelope_sha256": envelope,
           "limitations": "Plaintext export. A difference proves bytes changed since the baseline, not who "
                          "changed them or when; times are assertions and the hash chain does not establish "
                          "a trusted time."}
    if format == "json":
        output = (json.dumps(out, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    else:
        def esc(v):
            return html.escape(str(v), quote=True)

        def plain(items):
            return "".join("<tr><td>" + esc(e["path"]) + "</td><td>" + esc(e["size"]) +
                           "</td><td><code>" + esc(e["sha256"]) + "</code></td></tr>" for e in items)
        mod = "".join("<tr><td>" + esc(m["path"]) + "</td><td>" + esc(m["old_size"]) + " → " +
                      esc(m["new_size"]) + "</td><td><code>" + esc(m["old_sha256"][:16]) + "… → " +
                      esc(m["new_sha256"][:16]) + "…</code></td></tr>" for m in report["modified"])
        verdict = "CLEAN — no changes since the baseline" if report["clean"] else \
            f"{report['changed']} change(s) since the baseline"
        # No external content, executable script, clickable operator-supplied URLs, or active HTML.
        output = ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                  "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
                  "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                  "<title>" + esc(data["title"]) + "</title><style>body{max-width:72rem;margin:2rem auto;padding:0 1rem;font:16px system-ui;line-height:1.5}"
                  "table{border-collapse:collapse;width:100%;margin:0 0 2rem}th,td{border:1px solid #777;padding:.4rem .6rem;text-align:left;vertical-align:top}"
                  "th{background:#eee}code{word-break:break-all;font-size:.85em}</style></head><body><h1>" + esc(data["title"]) +
                  "</h1><p>" + esc(out["limitations"]) + "</p><p>Monitor: " + esc(data["monitor_id"]) +
                  " · Revision: " + str(data["revision"]) + " · Root: " + esc(data["root"]) +
                  "</p><p>Scanned UTC: " + esc(report["scanned_utc"]) + " · Encrypted baseline SHA-256: " + envelope +
                  "</p><h2>" + verdict + "</h2>"
                  "<h3>Added (" + str(len(report["added"])) + ")</h3><table><thead><tr><th>Path</th><th>Size</th><th>SHA-256</th></tr></thead><tbody>" + plain(report["added"]) + "</tbody></table>"
                  "<h3>Removed (" + str(len(report["removed"])) + ")</h3><table><thead><tr><th>Path</th><th>Size</th><th>SHA-256</th></tr></thead><tbody>" + plain(report["removed"]) + "</tbody></table>"
                  "<h3>Modified (" + str(len(report["modified"])) + ")</h3><table><thead><tr><th>Path</th><th>Size</th><th>SHA-256 old → new</th></tr></thead><tbody>" + mod + "</tbody></table>"
                  "<p>Unchanged: " + str(report["unchanged"]) + " file(s).</p></body></html>").encode("utf-8")
    new_file(destination, output)
    return {"output": str(destination), "format": format, "plaintext": True,
            "sha256": hashlib.sha256(output).hexdigest(), "clean": report["clean"], "changed": report["changed"]}
