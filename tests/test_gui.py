"""Offscreen GUI tests: drive the real Integrity Monitor window without a display."""
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    import PyQt6.QtWidgets  # noqa: F401
    HAVE_QT = True
except Exception:  # pragma: no cover
    HAVE_QT = False

SECRET = b"correct horse battery staple"


@unittest.skipUnless(HAVE_QT, "PyQt6 is not installed")
class IntegrityWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from envy_integrity_monitor import gui
        app_cls, cls.Window = gui._build()
        cls.app = app_cls.instance() or app_cls([])
        cls.gui = gui

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.w = self.Window()
        self.messages = []
        self.w._warn = lambda message, **kw: self.messages.append(message)

    def tearDown(self):
        self.w.timer.stop(); self.w.close(); self.tmp.cleanup()

    def folders(self):
        a, b = self.root / "docs", self.root / "config"
        a.mkdir(); b.mkdir()
        (a / "report.txt").write_text("v1"); (a / "debug.log").write_text("noise")
        (b / "app.ini").write_text("x=1")
        return a, b

    def test_multi_root_baseline_with_ignore_and_root_column(self):
        a, b = self.folders()
        dest = self.root / "m.envymon"
        self.w.create_baseline(str(dest), "Servers", [str(a), str(b)], ["*.log"], SECRET)
        self.assertEqual(self.w.data["roots"], [str(a.resolve()), str(b.resolve())])
        self.assertIn("2 roots", self.w.mon_header.toPlainText())
        self.assertIn("ignoring: *.log", self.w.mon_header.toPlainText())
        self.assertFalse(self.w.t_baseline.isColumnHidden(0))
        paths = {self.w.t_baseline.item(r, 1).text() for r in range(self.w.t_baseline.rowCount())}
        self.assertEqual(paths, {"report.txt", "app.ini"})  # debug.log ignored

        (a / "report.txt").write_text("v2-changed"); (b / "new.ini").write_text("y")
        (a / "extra.log").write_text("still ignored")
        self.w.check_now()
        self.assertIn("+1 added", self.w.change_summary.text())
        self.assertIn("~1 modified", self.w.change_summary.text())
        self.assertEqual(self.w.t_changes.rowCount(), 2)
        roots_shown = {self.w.t_changes.item(r, 1).text() for r in range(2)}
        self.assertEqual(roots_shown, {"docs", "config"})

        self.w.change_filter.setCurrentIndex(3)  # Modified only
        self.assertEqual(self.w.t_changes.rowCount(), 1)
        self.assertEqual(self.w.t_changes.item(0, 2).text(), "report.txt")
        self.w.change_filter.setCurrentIndex(2)  # Removed: none
        self.assertEqual(self.w.t_changes.item(0, 2).text(), "No changes of this type.")

    def test_single_root_hides_root_column(self):
        a, _ = self.folders()
        self.w.create_baseline(str(self.root / "s.envymon"), "Docs", [str(a)], [], SECRET)
        self.assertTrue(self.w.t_baseline.isColumnHidden(0))
        self.assertIn(f"root: {a.resolve()}", self.w.mon_header.toPlainText())

    def test_new_baseline_dialog_validation(self):
        a, b = self.folders()
        d = self.w.make_new_baseline_dialog()
        self.assertEqual(d.validate(), "Give the monitor a title.")
        d.title.setText("Servers")
        self.assertEqual(d.validate(), "Add at least one folder.")
        d.add_root(str(a)); d.add_root(str(a)); d.add_root(str(b))
        self.assertEqual(d.root_list(), [str(a), str(b)])  # duplicates ignored
        d.ignore.setText("*.log,  .git/* ,")
        self.assertIsNone(d.validate())
        self.assertEqual(d.values(), ("Servers", [str(a), str(b)], ["*.log", ".git/*"]))
        d.roots.setCurrentRow(0); d.remove_selected()
        self.assertEqual(d.root_list(), [str(b)])

    def test_schedule_dialog_shows_cron_and_launchd(self):
        a, _ = self.folders()
        dest = self.root / "s.envymon"
        self.w.create_baseline(str(dest), "Docs", [str(a)], [], SECRET)
        d = self.w.make_schedule_dialog()
        text = d.text.toPlainText()
        self.assertIn("ENVY_INTEGRITY_PASSPHRASE=", text)
        self.assertIn(f"check {dest}", text.replace("'", ""))
        self.assertIn("--exit-detail", text)
        d.kind.setCurrentIndex(1)
        self.assertIn("<key>StartInterval</key>", d.text.toPlainText())
        d.copy()
        from PyQt6.QtWidgets import QApplication
        self.assertEqual(QApplication.clipboard().text(), d.text.toPlainText())

    def test_schedule_without_baseline_warns(self):
        self.w.show_schedule()
        self.assertEqual(self.messages, ["Open a baseline first."])


if __name__ == "__main__":
    unittest.main()
