"""A native ENVY Integrity Monitor window: a real desktop app, not a web view.

Built with PyQt6 and styled in the ENVY palette with a live animated header.
Baseline a folder into an encrypted record, then check what has been added,
removed or modified since — and accept the current state as a new revision.
Every accepted revision is a new file; earlier revisions are never overwritten.

Nothing is sent: no network, no accounts.
"""

from __future__ import annotations

import math
import os
import sys
from pathlib import Path

from . import __version__
from . import core
from .core import IntegrityError

BG = "#050713"
PANEL = "#0a0e22"
PANEL_HI = "#121735"
INK = "#f2f4ff"
MUTED = "#b9c3df"
DIM = "#6f7898"
PINK = "#ff3db4"
CYAN = "#35e8ff"
LAVENDER = "#ac8cff"
VIOLET = "#8547e8"
AMBER = "#ffb347"
GREEN = "#49e3a6"
LINE = "#1f2547"

STATUS_COLOR = {"added": GREEN, "removed": PINK, "modified": AMBER}


def lerp(a, b, t):
    from PyQt6.QtGui import QColor
    ca, cb = QColor(a), QColor(b)
    return QColor(int(ca.red() + (cb.red() - ca.red()) * t),
                  int(ca.green() + (cb.green() - ca.green()) * t),
                  int(ca.blue() + (cb.blue() - ca.blue()) * t))


def _build():
    from PyQt6.QtCore import Qt, QTimer, QRectF, QPointF
    from PyQt6.QtGui import (QColor, QPainter, QLinearGradient, QRadialGradient, QFont,
                             QPen, QBrush)
    from PyQt6.QtWidgets import (QApplication, QWidget, QLabel, QPushButton, QPlainTextEdit,
                                 QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
                                 QAbstractItemView, QVBoxLayout, QHBoxLayout, QInputDialog,
                                 QFileDialog, QMessageBox, QLineEdit as QLE)

    class Header(QWidget):
        def __init__(self):
            super().__init__()
            self.setFixedHeight(172)
            self.phase = 0.0
            self.stars = [(((i * 139 + 37) % 1000) / 1000.0,
                           ((i * 83 + 19) % 172) / 172.0,
                           0.6 + (i % 3) * 0.5, (i % 7) / 7.0) for i in range(60)]

        def tick(self, phase):
            self.phase = phase
            self.update()

        def paintEvent(self, _event):
            p = QPainter(self)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            w, h = self.width(), self.height()
            p.fillRect(self.rect(), QColor(BG))
            for cx, cy, rad, col, a in ((w - 120, 60, 250, GREEN, 46),
                                        (60, h, 280, VIOLET, 52), (w * 0.5, -40, 240, CYAN, 42)):
                g = QRadialGradient(cx, cy, rad)
                c = QColor(col); c.setAlpha(a); g.setColorAt(0, c)
                c2 = QColor(col); c2.setAlpha(0); g.setColorAt(1, c2)
                p.setBrush(QBrush(g)); p.setPen(Qt.PenStyle.NoPen)
                p.drawEllipse(QPointF(cx, cy), rad, rad)
            for sx, sy, sr, ph in self.stars:
                tw = 0.5 + 0.5 * math.sin(self.phase / 0.5 + ph * 6.28)
                c = QColor(205, 217, 255); c.setAlphaF(0.15 + 0.6 * tw)
                p.setBrush(c); p.setPen(Qt.PenStyle.NoPen)
                p.drawEllipse(QPointF(sx * w, sy * h), sr, sr)
            pulse = 0.5 + 0.5 * math.sin(self.phase)
            p.setFont(QFont("Helvetica", 22))
            p.setPen(QColor(CYAN) if pulse > 0.5 else QColor(PINK))
            p.drawText(QRectF(22, 28, 44, 44), Qt.AlignmentFlag.AlignCenter, "◎")
            p.setFont(QFont("Helvetica", 30, QFont.Weight.Bold))
            grad = QLinearGradient(70, 0, 700, 0)
            grad.setColorAt(0, QColor(CYAN))
            grad.setColorAt(0.5, QColor(lerp(CYAN, "#ffffff", 0.2 * pulse)))
            grad.setColorAt(1, QColor(PINK))
            glow = QColor(VIOLET); glow.setAlpha(int(55 + 55 * pulse))
            p.setPen(QPen(glow, 1))
            for dx, dy in ((1.3, 1.3), (-1.3, 1.3), (1.3, -1.3)):
                p.drawText(QRectF(70 + dx, 38 + dy, 820, 48), Qt.AlignmentFlag.AlignVCenter, "ENVY INTEGRITY MONITOR")
            p.setPen(QPen(QBrush(grad), 1))
            p.drawText(QRectF(70, 38, 820, 48), Qt.AlignmentFlag.AlignVCenter, "ENVY INTEGRITY MONITOR")
            p.setFont(QFont("Courier New", 11, QFont.Weight.Bold))
            p.setPen(QColor(LAVENDER))
            p.drawText(QRectF(74, 92, 700, 20), Qt.AlignmentFlag.AlignVCenter,
                       "ENCRYPTED  ·  BASELINE  ·  TAMPER-EVIDENT")
            y = 126
            p.setPen(QPen(QColor(LINE), 2)); p.drawLine(74, y, w - 54, y)
            p.setPen(QPen(QColor(VIOLET), 3)); p.drawLine(74, y, 146, y)
            span = (w - 54) - 74
            x = 74 + span * ((self.phase * 0.12) % 1.0)
            halo = QRadialGradient(x, y, 15)
            hc = QColor(CYAN); hc.setAlpha(170); halo.setColorAt(0, hc)
            hc2 = QColor(CYAN); hc2.setAlpha(0); halo.setColorAt(1, hc2)
            p.setBrush(QBrush(halo)); p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QPointF(x, y), 15, 15)
            p.setBrush(QColor("#ffffff")); p.drawEllipse(QPointF(x, y), 2.5, 2.5)
            p.end()

    def make_table(headers):
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setDefaultSectionSize(28)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setAlternatingRowColors(True)
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        return table

    class Window(QWidget):
        def __init__(self):
            super().__init__()
            self.baseline = None   # Path of the current encrypted baseline file
            self.secret = None     # passphrase bytes, kept in memory for this monitor only
            self.data = None       # decrypted, validated baseline dict
            self.last_report = None
            self.setWindowTitle("ENVY Integrity Monitor")
            self.resize(1200, 900)
            self.setMinimumSize(980, 760)
            self.setStyleSheet(STYLE)
            root = QVBoxLayout(self); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)
            self.header = Header(); root.addWidget(self.header)

            body = QWidget(); body.setObjectName("body")
            bl = QVBoxLayout(body); bl.setContentsMargins(22, 14, 22, 16); bl.setSpacing(10)

            intro = QLabel("Baseline a folder's files by SHA-256 into an encrypted record, then check what "
                           "has changed since. Accepting the current state writes a new revision. Nothing is sent.")
            intro.setObjectName("status"); intro.setWordWrap(True); bl.addWidget(intro)

            controls = QHBoxLayout()
            for caption, handler, name in (("New baseline", self.new_baseline, "go"),
                                           ("Open baseline", self.open_baseline, "pick"),
                                           ("Lock", self.lock, "pick"),
                                           ("Check now", self.check_now, "go"),
                                           ("Accept current state", self.accept_state, "pick"),
                                           ("Export report", self.export_report, "pick")):
                b = QPushButton(caption); b.setObjectName(name)
                b.setCursor(Qt.CursorShape.PointingHandCursor); b.clicked.connect(handler)
                controls.addWidget(b)
            controls.addStretch(1)
            bl.addLayout(controls)

            self.mon_header = QPlainTextEdit(); self.mon_header.setObjectName("mono")
            self.mon_header.setReadOnly(True); self.mon_header.setFixedHeight(84)
            self.mon_header.setPlainText("No baseline open. Create a new baseline or open an existing one.")
            bl.addWidget(self.mon_header)

            self.views = QTabWidget(); self.views.setObjectName("tabs")
            self.t_changes = make_table(["Status", "Path", "Size", "SHA-256"])
            self.t_baseline = make_table(["Path", "Size", "SHA-256"])
            self.t_history = make_table(["Checked UTC", "Added", "Removed", "Modified", "Unchanged"])
            self.views.addTab(self.t_changes, "Changes")
            self.views.addTab(self.t_baseline, "Baseline")
            self.views.addTab(self.t_history, "History")
            bl.addWidget(self.views, 1)

            self.path_label = QLabel(""); self.path_label.setObjectName("foot")
            self.path_label.setWordWrap(True); bl.addWidget(self.path_label)
            foot = QLabel("A difference proves a file's bytes changed since the baseline — not who changed "
                          "them, when (the clock is an assertion), or whether the change is benign. It sees only "
                          "files readable at scan time; a file that changes and changes back looks unchanged.")
            foot.setObjectName("foot"); foot.setWordWrap(True); bl.addWidget(foot)
            root.addWidget(body, 1)

            self.phase = 0.0
            self.timer = QTimer(self); self.timer.timeout.connect(self._animate); self.timer.start(33)
            self._set_enabled(False)

        # ----- lifecycle ----------------------------------------------------
        def _ask_passphrase(self, confirm):
            text, ok = QInputDialog.getText(self, "Passphrase",
                                            "Baseline passphrase (at least 12 characters):", QLE.EchoMode.Password)
            if not ok:
                return None
            secret = text.encode("utf-8")
            if confirm:
                again, ok2 = QInputDialog.getText(self, "Confirm passphrase",
                                                  "Repeat the passphrase:", QLE.EchoMode.Password)
                if not ok2:
                    return None
                if again.encode("utf-8") != secret:
                    self._warn("Passphrases do not match."); return None
            try:
                return core.check_passphrase(secret)
            except IntegrityError as exc:
                self._warn(str(exc)); return None

        def new_baseline(self):
            folder = QFileDialog.getExistingDirectory(self, "Choose a folder to monitor")
            if not folder:
                return
            title, ok = QInputDialog.getText(self, "New baseline", "Monitor title:")
            if not ok or not title.strip():
                return
            dest, _ = QFileDialog.getSaveFileName(self, "Save the encrypted baseline", "monitor.envymon",
                                                  "Baseline (*.envymon);;All files (*)")
            if not dest:
                return
            secret = self._ask_passphrase(confirm=True)
            if secret is None:
                return
            try:
                if Path(dest).exists():
                    Path(dest).unlink()
                core.create(dest, title.strip(), folder, secret)
                self._open_path(Path(dest), secret)
                self._warn(f"Baselined {len(self.data['files'])} files under\n{folder}",
                           icon=QMessageBox.Icon.Information, title="Baseline created")
            except (IntegrityError, OSError) as exc:
                self._warn(str(exc))

        def open_baseline(self):
            path, _ = QFileDialog.getOpenFileName(self, "Open an encrypted baseline", "",
                                                  "Baseline (*.envymon);;All files (*)")
            if not path:
                return
            secret = self._ask_passphrase(confirm=False)
            if secret is None:
                return
            self._open_path(Path(path), secret)

        def _open_path(self, path, secret):
            try:
                data, _ = core._load(path, secret)
            except IntegrityError as exc:
                self._warn(str(exc)); return
            self.baseline, self.secret, self.data, self.last_report = path, secret, data, None
            self._set_enabled(True)
            self.t_changes.setRowCount(0)
            self._refresh_header()
            self._fill_baseline(data["files"])
            self._fill_history(data["journal"])

        def lock(self):
            self.baseline = self.secret = self.data = self.last_report = None
            for t in (self.t_changes, self.t_baseline, self.t_history):
                t.setRowCount(0)
            self.mon_header.setPlainText("Locked. The passphrase was cleared from memory.")
            self.path_label.setText("")
            self._set_enabled(False)

        # ----- check / accept ----------------------------------------------
        def check_now(self):
            if not self.data:
                return
            try:
                report = core.check(self.baseline, self.secret)
            except (IntegrityError, OSError) as exc:
                self._warn(str(exc)); return
            self.last_report = report
            self._fill_changes(report)
            self.views.setCurrentIndex(0)
            self._refresh_header()
            if report["clean"]:
                self._warn("No changes since the baseline — the folder is clean.",
                           icon=QMessageBox.Icon.Information, title="Check complete")

        def accept_state(self):
            if not self.data:
                return
            confirm = QMessageBox.question(self, "Accept current state",
                                           "Record the folder's current state as a new baseline revision?\n\n"
                                           "This trusts whatever is on disk right now.")
            if confirm != QMessageBox.StandardButton.Yes:
                return
            dest = self._next_revision_path()
            try:
                result = core.accept(self.baseline, dest, self.secret)
            except (IntegrityError, OSError) as exc:
                self._warn(str(exc)); return
            self._open_path(Path(result["output"]), self.secret)
            self.t_changes.setRowCount(0); self.last_report = None
            self._warn(f"Accepted the current state as revision {result['revision']} → "
                       f"{Path(result['output']).name}", icon=QMessageBox.Icon.Information, title="State accepted")

        def export_report(self):
            if not self.data:
                return
            choice, ok = QInputDialog.getItem(self, "Export report", "Format:",
                                              ["HTML report", "JSON report"], 0, False)
            if not ok:
                return
            fmt = "html" if choice.startswith("HTML") else "json"
            dest, _ = QFileDialog.getSaveFileName(self, "Export change report",
                                                  f"integrity-report.{fmt}", f"{fmt.upper()} (*.{fmt});;All files (*)")
            if not dest:
                return
            try:
                if Path(dest).exists():
                    Path(dest).unlink()
                result = core.export(self.baseline, dest, self.secret, fmt)
            except (IntegrityError, OSError) as exc:
                self._warn(str(exc)); return
            self._warn(f"Exported a plaintext {fmt.upper()} report to {result['output']}.\n\n"
                       f"SHA-256: {result['sha256']}", icon=QMessageBox.Icon.Information, title="Report exported")

        # ----- display ------------------------------------------------------
        def _refresh_header(self):
            d = self.data
            if not d:
                return
            if self.last_report is not None:
                r = self.last_report
                verdict = "CLEAN" if r["clean"] else (f"+{len(r['added'])} ~{len(r['modified'])} "
                                                      f"-{len(r['removed'])} changed")
            else:
                verdict = "not checked yet"
            self.mon_header.setPlainText(
                f"{d['title']}  ·  revision {d['revision']}  ·  {len(d['files'])} files  ·  {verdict}\n"
                f"root: {d['root']}")
            if self.baseline:
                self.path_label.setText(str(self.baseline))

        def _cell(self, text, color=None):
            item = QTableWidgetItem("" if text is None else str(text))
            if color:
                item.setForeground(QColor(color))
            return item

        def _fill_changes(self, report):
            rows = ([("added", e) for e in report["added"]] +
                    [("removed", e) for e in report["removed"]] +
                    [("modified", e) for e in report["modified"]])
            t = self.t_changes; t.setRowCount(len(rows))
            for i, (status, e) in enumerate(rows):
                t.setItem(i, 0, self._cell(status, STATUS_COLOR[status]))
                t.setItem(i, 1, self._cell(e["path"], INK))
                if status == "modified":
                    t.setItem(i, 2, self._cell(f"{e['old_size']} → {e['new_size']}"))
                    t.setItem(i, 3, self._cell(f"{e['old_sha256'][:12]}… → {e['new_sha256'][:12]}…"))
                else:
                    t.setItem(i, 2, self._cell(e["size"]))
                    t.setItem(i, 3, self._cell(e["sha256"]))
            t.resizeColumnsToContents(); t.horizontalHeader().setStretchLastSection(True)
            if not rows:
                t.setRowCount(1)
                t.setItem(0, 0, self._cell("clean", GREEN))
                t.setItem(0, 1, self._cell("No changes since the baseline."))

        def _fill_baseline(self, files):
            t = self.t_baseline; t.setRowCount(len(files))
            for i, e in enumerate(files):
                t.setItem(i, 0, self._cell(e["path"], CYAN))
                t.setItem(i, 1, self._cell(e["size"]))
                t.setItem(i, 2, self._cell(e["sha256"]))
            t.resizeColumnsToContents(); t.horizontalHeader().setStretchLastSection(True)

        def _fill_history(self, journal):
            t = self.t_history; t.setRowCount(len(journal))
            for i, r in enumerate(reversed(journal)):
                c = r["check"]
                t.setItem(i, 0, self._cell(r["recorded_utc"]))
                t.setItem(i, 1, self._cell(c["added"], GREEN))
                t.setItem(i, 2, self._cell(c["removed"], PINK))
                t.setItem(i, 3, self._cell(c["modified"], AMBER))
                t.setItem(i, 4, self._cell(c["unchanged"]))
            t.resizeColumnsToContents(); t.horizontalHeader().setStretchLastSection(True)

        def _next_revision_path(self):
            base = self.baseline
            stem = base.stem
            if ".r" in stem and stem.rsplit(".r", 1)[-1].isdigit():
                stem = stem.rsplit(".r", 1)[0]
            rev = (self.data["revision"] + 1) if self.data else 1
            candidate = base.with_name(f"{stem}.r{rev}{base.suffix}")
            n = rev
            while candidate.exists():
                n += 1
                candidate = base.with_name(f"{stem}.r{n}{base.suffix}")
            return candidate

        def _set_enabled(self, on):
            self.views.setEnabled(on)

        def _warn(self, message, icon=None, title="Integrity Monitor"):
            box = QMessageBox(self); box.setWindowTitle(title)
            box.setIcon(icon or QMessageBox.Icon.Warning); box.setText(message); box.exec()

        def _animate(self):
            self.phase += 0.05
            self.header.tick(self.phase)

    return QApplication, Window


STYLE = f"""
#body {{ background: {BG}; }}
QWidget {{ color: {INK}; font-family: Helvetica, Arial, sans-serif; font-size: 13px; }}
#status {{ color: {MUTED}; font-size: 12px; }}
#foot {{ color: {DIM}; font-size: 11px; }}
#mono {{ background: {PANEL_HI}; border: 1px solid {LINE}; border-radius: 9px; color: {INK};
         font-family: "Courier New", monospace; font-size: 13px; padding: 8px; }}
QTableWidget {{ background: {PANEL_HI}; alternate-background-color: {PANEL}; border: 1px solid {LINE};
                border-radius: 10px; gridline-color: {LINE}; }}
QTableWidget::item {{ padding: 4px 6px; }}
QTableWidget::item:selected {{ background: {VIOLET}; color: {INK}; }}
QHeaderView::section {{ background: {PANEL}; color: {MUTED}; padding: 6px 8px; border: none;
                        border-bottom: 1px solid {LINE}; font-weight: bold; }}
QTableCornerButton::section {{ background: {PANEL}; border: none; }}
QTabWidget#tabs::pane {{ border: 1px solid {LINE}; border-radius: 12px; background: {PANEL}; }}
QTabBar::tab {{ background: {PANEL_HI}; color: {MUTED}; padding: 8px 18px; margin-right: 6px;
                border-top-left-radius: 9px; border-top-right-radius: 9px; font-weight: bold; }}
QTabBar::tab:selected {{ color: {INK}; border-bottom: 2px solid {PINK}; }}
QPushButton#go {{ background: {PINK}; color: {BG}; border: none; border-radius: 10px; font-weight: bold; padding: 9px 16px; }}
QPushButton#go:hover {{ background: {CYAN}; }}
QPushButton#pick {{ background: {PANEL_HI}; border: 1px solid {LAVENDER}; border-radius: 9px; color: {INK};
                    font-weight: bold; padding: 9px 14px; }}
QPushButton#pick:hover {{ background: #1b2150; }}
"""


def run_app() -> int:
    try:
        from PyQt6.QtWidgets import QApplication  # noqa: F401
    except Exception:
        print("PyQt6 is required for the Integrity Monitor window. Use 'envy-integrity-monitor' subcommands instead.")
        return 2
    if sys.platform.startswith("linux") and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        print("No display found. Use 'envy-integrity-monitor baseline/check/accept/export' in a terminal instead.")
        return 2
    try:
        QApplication, Window = _build()
        app = QApplication.instance() or QApplication(sys.argv)
        window = Window(); window.show()
        return app.exec()
    except Exception as exc:  # pragma: no cover
        print(f"Could not open the window: {exc}")
        return 2
