"""CLI tests that need no display. The passphrase prompt is patched."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from envy_integrity_monitor import cli


class CLITest(unittest.TestCase):
    SECRET = b"a long private integrity passphrase"

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="envy-integrity-cli-"))
        self.addCleanup(__import__("shutil").rmtree, self.dir)
        self.tree = self.dir / "watched"; self.tree.mkdir()
        (self.tree / "a.txt").write_text("alpha")

    def invoke(self, *args, secret=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(cli, "_passphrase", return_value=secret or self.SECRET):
            code = cli.main([str(a) for a in args])
        return code, out.getvalue(), err.getvalue()

    def test_version(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as ctx:
            cli.main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("envy-integrity-monitor", out.getvalue())

    def test_baseline_check_accept_flow(self):
        base = self.dir / "m.envymon"
        code, out, _ = self.invoke("baseline", base, self.tree, "--title", "Proj")
        self.assertEqual(code, 0)
        self.assertTrue(base.exists())

        # No change yet -> check is clean (exit 0).
        code, out, _ = self.invoke("check", base)
        self.assertEqual(code, 0)
        self.assertIn("CLEAN", out)

        # Modify a file -> check reports a change (exit 1).
        (self.tree / "a.txt").write_text("changed")
        code, out, _ = self.invoke("check", base)
        self.assertEqual(code, 1)
        self.assertIn("1 modified", out)

        # Accept -> new revision; a fresh check is clean again.
        r1 = self.dir / "m.r1.envymon"
        code, out, _ = self.invoke("accept", base, r1)
        self.assertEqual(code, 0)
        self.assertTrue(r1.exists())
        code, out, _ = self.invoke("check", r1)
        self.assertEqual(code, 0)

    def test_inspect_and_export(self):
        base = self.dir / "m.envymon"
        self.invoke("baseline", base, self.tree, "--title", "Proj")
        code, out, _ = self.invoke("inspect", base)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["files"][0]["path"], "a.txt")
        out_html = self.dir / "r.html"
        code, out, _ = self.invoke("export", base, out_html, "--format", "html")
        self.assertEqual(code, 0)
        self.assertIn("sha256", out)

    def test_bad_passphrase_is_error(self):
        base = self.dir / "m.envymon"
        self.invoke("baseline", base, self.tree, "--title", "Proj")
        code, _, err = self.invoke("check", base, secret=b"the wrong passphrase!")
        self.assertEqual(code, 2)
        self.assertIn("passphrase", err.lower())

    def test_unknown_command(self):
        with self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["seance"])


if __name__ == "__main__":
    unittest.main()
