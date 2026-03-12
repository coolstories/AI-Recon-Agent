import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import _cli_runner as cli_runner


class CliRunnerAutoInstallTests(unittest.TestCase):
    def setUp(self):
        cli_runner.AUTO_INSTALL_LAST_ATTEMPT_TS = 0.0
        cli_runner.AUTO_INSTALL_LAST_SUMMARY = "not_attempted"

    def test_find_binary_checks_common_bin_dirs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_bin = Path(tmpdir) / "naabu"
            fake_bin.write_text("#!/bin/sh\necho naabu\n", encoding="utf-8")
            fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IXUSR)

            with patch.object(cli_runner, "COMMON_BIN_DIRS", [Path(tmpdir)]), patch.dict(
                os.environ, {"PATH": ""}, clear=False
            ):
                name, resolved = cli_runner.find_binary(["naabu"])
                self.assertIn(tmpdir, os.environ.get("PATH", ""))

            self.assertEqual(name, "naabu")
            self.assertEqual(resolved, str(fake_bin))

    def test_find_binary_or_auto_install_success_path(self):
        install_result = {
            "ran": True,
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "timed_out": False,
            "elapsed": 12.3,
        }
        with patch.object(
            cli_runner,
            "find_binary",
            side_effect=[(None, None), (None, None), ("naabu", "/tmp/naabu")],
        ), patch.object(cli_runner, "_run_tool_installer", return_value=install_result) as installer:
            name, path, err = cli_runner.find_binary_or_auto_install(["naabu"], tool_name="Naabu")

        self.assertEqual(name, "naabu")
        self.assertEqual(path, "/tmp/naabu")
        self.assertEqual(err, "")
        installer.assert_called_once()

    def test_find_binary_or_auto_install_failure_returns_diagnostics(self):
        install_result = {
            "ran": True,
            "stdout": "[WARN] failed to install naabu",
            "stderr": "permission denied",
            "exit_code": 1,
            "timed_out": False,
            "elapsed": 9.8,
        }
        with patch.object(
            cli_runner,
            "find_binary",
            side_effect=[(None, None), (None, None), (None, None)],
        ), patch.object(cli_runner, "_run_tool_installer", return_value=install_result):
            name, path, err = cli_runner.find_binary_or_auto_install(["naabu"], tool_name="Naabu")

        self.assertIsNone(name)
        self.assertIsNone(path)
        self.assertIn("ERROR: Naabu binary not found on PATH", err)
        self.assertIn("AUTO_INSTALL: attempted ./scripts/install_security_tools.sh", err)
        self.assertIn("permission denied", err)


if __name__ == "__main__":
    unittest.main()
