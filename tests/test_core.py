"""Core Integrity Monitor tests: encrypted baselines, tree scanning, change
detection (added/removed/modified), revision-preserving accept, the journal hash
chain, export and the no-overwrite guarantee.
"""

import json
from pathlib import Path
import tempfile
import unittest

from envy_integrity_monitor import core
from envy_integrity_monitor.core import IntegrityError


class IntegrityTest(unittest.TestCase):
    SECRET = b"a long private integrity passphrase"

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="envy-integrity-"))
        self.addCleanup(__import__("shutil").rmtree, self.dir)
        self.tree = self.dir / "watched"
        self.tree.mkdir()
        (self.tree / "a.txt").write_text("alpha")
        (self.tree / "sub").mkdir()
        (self.tree / "sub" / "b.bin").write_bytes(b"\x00\x01\x02beta")

    def baseline(self, name="base.envymon", title="Project"):
        path = self.dir / name
        core.create(path, title, self.tree, self.SECRET)
        return path

    # ----- envelope / create -------------------------------------------
    def test_encrypted_round_trip_and_magic(self):
        blob = core.encrypt_bytes(b"x", self.SECRET)
        self.assertEqual(blob[:11], b"ENVYVAULT2\x00")
        self.assertEqual(core.decrypt_bytes(blob, self.SECRET), b"x")

    def test_create_baselines_the_tree(self):
        path = self.baseline(title="Night watch")
        data, _ = core._load(path, self.SECRET)
        self.assertEqual(data["revision"], 0)
        self.assertEqual(data["title"], "Night watch")
        paths = [e["path"] for e in data["files"]]
        self.assertEqual(paths, ["a.txt", "sub/b.bin"])  # sorted, relative, posix
        self.assertTrue(all(len(e["sha256"]) == 64 for e in data["files"]))

    def test_short_passphrase_rejected(self):
        with self.assertRaises(IntegrityError):
            core.create(self.dir / "s", "t", self.tree, b"short")

    def test_scan_skips_symlinks(self):
        target = self.tree / "a.txt"
        try:
            (self.tree / "link.txt").symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        paths = [e["path"] for e in core.scan_tree(self.tree)]
        self.assertNotIn("link.txt", paths)

    # ----- diff / check ------------------------------------------------
    def test_check_clean_when_unchanged(self):
        path = self.baseline()
        report = core.check(path, self.SECRET)
        self.assertTrue(report["clean"])
        self.assertEqual(report["changed"], 0)
        self.assertEqual(report["unchanged"], 2)

    def test_check_detects_added_removed_modified(self):
        path = self.baseline()
        (self.tree / "a.txt").write_text("ALPHA-changed")        # modified
        (self.tree / "sub" / "b.bin").unlink()                   # removed
        (self.tree / "c.new").write_text("new file")             # added
        report = core.check(path, self.SECRET)
        self.assertFalse(report["clean"])
        self.assertEqual([e["path"] for e in report["added"]], ["c.new"])
        self.assertEqual([e["path"] for e in report["removed"]], ["sub/b.bin"])
        self.assertEqual([m["path"] for m in report["modified"]], ["a.txt"])
        mod = report["modified"][0]
        self.assertNotEqual(mod["old_sha256"], mod["new_sha256"])

    def test_change_bitmask(self):
        path = self.baseline()
        self.assertEqual(core.change_bitmask(core.check(path, self.SECRET)), 0)
        # Only a modification -> MODIFIED bit (4).
        (self.tree / "a.txt").write_text("ALPHA-changed")
        self.assertEqual(core.change_bitmask(core.check(path, self.SECRET)), core.EXIT_MODIFIED)
        # Add a removal and an addition -> all three bits set (1|2|4 == 7).
        (self.tree / "sub" / "b.bin").unlink()
        (self.tree / "c.new").write_text("new file")
        code = core.change_bitmask(core.check(path, self.SECRET))
        self.assertEqual(code, core.EXIT_ADDED | core.EXIT_REMOVED | core.EXIT_MODIFIED)
        self.assertEqual(code, 7)

    def test_ignore_globs_suppress_changes(self):
        path = self.baseline()
        (self.tree / "app.log").write_text("noise")          # added, but should be ignored
        (self.tree / "cache").mkdir()
        (self.tree / "cache" / "x.tmp").write_text("junk")   # whole dir ignored
        # Without ignore: changes are seen.
        self.assertFalse(core.check(path, self.SECRET)["clean"])
        # With ignore globs: the folder looks clean.
        report = core.check(path, self.SECRET, ignore=["*.log", "cache"])
        self.assertTrue(report["clean"], report)

    def test_ignore_also_filters_baseline_side(self):
        # A file present at baseline but later ignored must not show as "removed".
        self.baseline()  # a.txt, sub/b.bin
        path = self.dir / "withlog.envymon"
        (self.tree / "keep.log").write_text("v1")
        core.create(path, "t", self.tree, self.SECRET)
        (self.tree / "keep.log").unlink()                    # removed since baseline
        self.assertFalse(core.check(path, self.SECRET)["clean"])
        self.assertTrue(core.check(path, self.SECRET, ignore=["*.log"])["clean"])

    def test_change_and_change_back_looks_unchanged(self):
        path = self.baseline()
        original = (self.tree / "a.txt").read_text()
        (self.tree / "a.txt").write_text("temporarily different")
        (self.tree / "a.txt").write_text(original)
        self.assertTrue(core.check(path, self.SECRET)["clean"])

    # ----- accept / journal --------------------------------------------
    def test_accept_writes_new_revision_and_chains(self):
        p0 = self.baseline()
        (self.tree / "c.new").write_text("added")
        p1 = self.dir / "base.r1.envymon"
        res = core.accept(p0, p1, self.SECRET)
        self.assertEqual(res["revision"], 1)
        self.assertTrue(p0.exists(), "previous revision preserved")
        data, _ = core._load(p1, self.SECRET)
        self.assertEqual(data["journal"][0]["check"]["added"], 1)
        # After accepting, a fresh check is clean.
        self.assertTrue(core.check(p1, self.SECRET)["clean"])
        # A second accept chains onto the first.
        (self.tree / "d.new").write_text("more")
        p2 = self.dir / "base.r2.envymon"
        core.accept(p1, p2, self.SECRET)
        data2, _ = core._load(p2, self.SECRET)
        self.assertEqual(data2["journal"][1]["previous_sha256"], data2["journal"][0]["record_sha256"])

    def test_tampered_baseline_breaks_chain(self):
        p0 = self.baseline()
        (self.tree / "c.new").write_text("x")
        p1 = self.dir / "base.r1.envymon"
        core.accept(p0, p1, self.SECRET)
        data, _ = core._load(p1, self.SECRET)
        data["journal"][0]["check"]["added"] = 999   # tamper without re-hashing
        forged = self.dir / "forged.envymon"
        forged.write_bytes(core.encrypt_bytes(core._canonical(data), self.SECRET))
        with self.assertRaises(IntegrityError):
            core.inspect(forged, self.SECRET)

    # ----- export -------------------------------------------------------
    def test_export_html_and_json(self):
        path = self.baseline()
        (self.tree / "a.txt").write_text("changed now")
        html_out = self.dir / "r.html"
        res = core.export(path, html_out, self.SECRET, "html")
        text = html_out.read_text()
        self.assertIn("Content-Security-Policy", text)
        self.assertIn("a.txt", text)
        self.assertFalse(res["clean"])
        json_out = self.dir / "r.json"
        core.export(path, json_out, self.SECRET, "json")
        report = json.loads(json_out.read_text())
        self.assertIn("limitations", report)
        self.assertEqual(len(report["modified"]), 1)

    def test_export_escapes_markup_in_paths(self):
        # Inject a baseline entry whose path contains markup (Windows forbids such a real
        # filename). Absent on disk, it shows as "removed" and must be HTML-escaped.
        path = self.baseline()
        data, _ = core._load(path, self.SECRET)
        data["files"].append({"path": "weird<name>.txt", "size": 1, "sha256": "ab" * 32})
        data["files"].sort(key=lambda e: e["path"])
        forged = self.dir / "crafted.envymon"
        forged.write_bytes(core.encrypt_bytes(core._canonical(data), self.SECRET))
        out = self.dir / "r.html"
        core.export(forged, out, self.SECRET, "html")
        body = out.read_text()
        self.assertNotIn("weird<name>", body)
        self.assertIn("&lt;name&gt;", body)

    # ----- no overwrite -------------------------------------------------
    def test_new_file_never_overwrites(self):
        keep = self.dir / "keep"
        keep.write_bytes(b"precious")
        with self.assertRaises(IntegrityError):
            core.new_file(keep, b"clobber")
        self.assertEqual(keep.read_bytes(), b"precious")

    def test_accept_refuses_to_overwrite(self):
        p0 = self.baseline()
        dest = self.dir / "exists.envymon"; dest.write_bytes(b"keep me")
        with self.assertRaises(IntegrityError):
            core.accept(p0, dest, self.SECRET)
        self.assertEqual(dest.read_bytes(), b"keep me")

    # ----- persisted ignore list (v0.2) --------------------------------
    def test_stored_ignore_is_honored_by_check_and_accept(self):
        path = self.dir / "b.envymon"
        core.create(path, "t", self.tree, self.SECRET, ignore=["*.log"])
        data, _ = core._load(path, self.SECRET)
        self.assertEqual(data["ignore"], ["*.log"])
        # A new .log must not count as a change, without re-passing the glob.
        (self.tree / "noise.log").write_text("noise")
        report = core.check(path, self.SECRET)
        self.assertTrue(report["clean"])
        self.assertIn("*.log", report["ignore"])
        # Accept keeps it out, and a later check stays clean.
        p2 = self.dir / "b.r1.envymon"
        core.accept(path, p2, self.SECRET)
        data2, _ = core._load(p2, self.SECRET)
        self.assertEqual(data2["ignore"], ["*.log"])
        self.assertFalse(any(f["path"] == "noise.log" for f in data2["files"]))
        self.assertTrue(core.check(p2, self.SECRET)["clean"])

    def test_accept_can_extend_the_ignore_list(self):
        path = self.dir / "b2.envymon"
        core.create(path, "t", self.tree, self.SECRET)
        (self.tree / "x.tmp").write_text("tmp")
        p2 = self.dir / "b2.r1.envymon"
        core.accept(path, p2, self.SECRET, ignore=["*.tmp"])
        data2, _ = core._load(p2, self.SECRET)
        self.assertEqual(data2["ignore"], ["*.tmp"])
        self.assertFalse(any(f["path"] == "x.tmp" for f in data2["files"]))

    def test_pre_ignore_baseline_migrates_on_load(self):
        path = self.dir / "b3.envymon"
        core.create(path, "t", self.tree, self.SECRET)
        data, _ = core._load(path, self.SECRET)
        del data["ignore"]                                   # simulate a pre-v0.2 baseline
        legacy = self.dir / "legacy.envymon"
        core.new_file(legacy, core.encrypt_bytes(core._canonical(data), self.SECRET))
        reloaded, _ = core._load(legacy, self.SECRET)        # must not raise
        self.assertEqual(reloaded["ignore"], [])


    # ----- Markdown change report (v0.2) -------------------------------
    def test_export_markdown_change_report(self):
        path = self.baseline(title="Project")
        (self.tree / "a.txt").write_text("changed content")
        (self.tree / "new.txt").write_text("brand new")
        (self.tree / "sub" / "b.bin").unlink()
        out = self.dir / "r.md"
        res = core.export(path, out, self.SECRET, "md")
        self.assertEqual(res["format"], "md")
        text = out.read_text()
        self.assertTrue(text.startswith("# Project — integrity check"))
        self.assertIn("## Added (1)", text)
        self.assertIn("new.txt", text)
        self.assertIn("## Removed (1)", text)
        self.assertIn("sub/b.bin", text)
        self.assertIn("## Modified (1)", text)
        self.assertIn("a.txt", text)
        self.assertIn("change(s)", text)

    def test_export_markdown_clean(self):
        path = self.baseline()
        out = self.dir / "c.md"
        core.export(path, out, self.SECRET, "md")
        self.assertIn("CLEAN", out.read_text())


if __name__ == "__main__":
    unittest.main()
