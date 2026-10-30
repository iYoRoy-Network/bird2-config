import argparse
import contextlib
import io
import json
import subprocess
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_intent import plugin


BIRD = plugin("bird_deploy", "files")
WG = plugin("wireguard_deploy", "files")


class DeploymentTests(unittest.TestCase):
    def test_wireguard_orphaned_interface_is_stopped_with_previous_config(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "intra_hkg03.conf"
            config.write_text("old config")
            calls = []

            def run(command, check=True):
                calls.append(command)
                if command[:3] == ["wg", "show", "intra_hkg03"]:
                    return subprocess.CompletedProcess(command, 0, "", "")
                return subprocess.CompletedProcess(command, 0, "", "")

            with patch.object(WG, "run", side_effect=run):
                self.assertTrue(WG.remove_orphaned_interface("intra_hkg03", config))

            self.assertEqual(calls, [
                ["wg", "show", "intra_hkg03"],
                ["wg-quick", "down", str(config)],
            ])

    def test_wireguard_orphaned_interface_without_previous_config_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            missing_config = Path(directory) / "missing.conf"
            with patch.object(WG, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
                with self.assertRaisesRegex(RuntimeError, "no previous config is available"):
                    WG.remove_orphaned_interface("intra_hkg03", missing_config)
            run.assert_called_once_with(["wg", "show", "intra_hkg03"], check=False)

    def test_bird_failed_reload_restores_and_reloads_previous_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live, stage = root / "live", root / "stage"
            live.mkdir()
            stage.mkdir()
            (live / "peer.conf").write_text("old")
            (stage / "peer.conf").write_text("new")
            args = argparse.Namespace(live_dir=str(live), staging_dir=str(stage), backup_dir=str(root / "backup"),
                                      file="peer.conf", remove=False, dry_run=False, preserve=[],
                                      check_command="parse", reload_command="reload")
            calls = []
            def run(command, directory):
                calls.append((command, (Path(directory) / "peer.conf").read_text()))
                if command == "reload" and calls[-1][1] == "new":
                    (live / "other.conf").write_text("unrelated concurrent change")
                    raise RuntimeError("rejected")
            with patch.object(BIRD, "run", side_effect=run), self.assertRaises(RuntimeError):
                BIRD.apply(args)
            self.assertEqual((live / "peer.conf").read_text(), "old")
            self.assertEqual((live / "other.conf").read_text(), "unrelated concurrent change")
            self.assertEqual(calls[-2:], [("parse", "old"), ("reload", "old")])

    def test_wireguard_service_failure_recovers_scoped_files_and_services(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live, stage, backup = root / "live", root / "stage", root / "backup"
            live.mkdir()
            stage.mkdir()
            (live / "target.conf").write_text("old")
            (live / "other.conf").write_text("unrelated")
            (stage / "target.conf").write_text("new address and MTU")
            calls = []
            def action(manager, action, interface, dry_run, ignore_failure=False):
                calls.append((action, interface))
                return {"failed": action == "stop" and not ignore_failure}
            def save(*_):
                shutil.copytree(live, backup)
                return True
            def restore(*_):
                shutil.rmtree(live)
                shutil.copytree(backup, live)
                return True
            argv = ["wg", "--live-dir", str(live), "--staging-dir", str(stage),
                    "--backup-dir", str(backup), "--interface", "target"]
            with patch.object(sys, "argv", argv), patch.object(WG, "enabled_systemd", return_value={"target", "other"}), \
                    patch.object(WG, "active_interfaces", return_value={"target"}), \
                    patch.object(WG, "backup_live", side_effect=save), patch.object(WG, "restore", side_effect=restore), \
                    patch.object(WG, "apply_service_action", side_effect=action), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(WG.main(), 1)
            self.assertEqual((live / "target.conf").read_text(), "old")
            self.assertEqual((live / "other.conf").read_text(), "unrelated")
            self.assertEqual(calls, [("stop", "target"), ("enable", "target"), ("start", "target")])

    def test_wireguard_recovers_running_but_disabled_interface(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live, stage, backup = root / "live", root / "stage", root / "backup"
            live.mkdir()
            stage.mkdir()
            (live / "target.conf").write_text("old")
            (stage / "target.conf").write_text("new")
            calls = []
            def action(manager, name, interface, dry_run, ignore_failure=False):
                calls.append((name, ignore_failure))
                if name == "enable" and not ignore_failure:
                    (live / "other.conf").write_text("concurrent unrelated change")
                    return {"failed": True}
                return {"rc": 0}
            def save(*_):
                shutil.copytree(live, backup)
                return True
            argv = ["wg", "--live-dir", str(live), "--staging-dir", str(stage),
                    "--backup-dir", str(backup), "--interface", "target"]
            with patch.object(sys, "argv", argv), patch.object(WG, "enabled_systemd", return_value=set()), \
                    patch.object(WG, "active_interfaces", return_value={"target"}), \
                    patch.object(WG, "backup_live", side_effect=save), \
                    patch.object(WG, "apply_service_action", side_effect=action), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(WG.main(), 1)
            self.assertEqual((live / "target.conf").read_text(), "old")
            self.assertEqual((live / "other.conf").read_text(), "concurrent unrelated change")
            self.assertEqual(calls[-2:], [("disable", True), ("start", True)])

    def test_wireguard_start_failure_does_not_block_other_interfaces(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live, stage, backup = root / "live", root / "stage", root / "backup"
            live.mkdir()
            stage.mkdir()
            (stage / "a-unavailable.conf").write_text("unavailable peer")
            (stage / "z-healthy.conf").write_text("healthy peer")
            calls = []

            def action(manager, name, interface, dry_run, ignore_failure=False):
                calls.append((name, interface))
                if name == "start" and interface == "a-unavailable":
                    return {"failed": True, "interface": interface, "action": name, "rc": 1}
                return {"rc": 0}

            def save(*_):
                backup.mkdir()
                return True

            def promote(staging, live_dir):
                shutil.copytree(staging, live_dir, dirs_exist_ok=True)

            argv = ["wg", "--live-dir", str(live), "--staging-dir", str(stage),
                    "--backup-dir", str(backup)]
            output = io.StringIO()
            with patch.object(sys, "argv", argv), patch.object(WG, "enabled_systemd", return_value=set()), \
                    patch.object(WG, "active_interfaces", return_value=set()), \
                    patch.object(WG, "backup_live", side_effect=save), \
                    patch.object(WG, "promote", side_effect=promote), \
                    patch.object(WG, "apply_service_action", side_effect=action), contextlib.redirect_stdout(output):
                self.assertEqual(WG.main(), 0)

            self.assertEqual((live / "a-unavailable.conf").read_text(), "unavailable peer")
            self.assertEqual((live / "z-healthy.conf").read_text(), "healthy peer")
            self.assertIn(("start", "z-healthy"), calls)
            summary = json.loads(output.getvalue())
            self.assertEqual([failure["interface"] for failure in summary["start_failures"]],
                             ["a-unavailable"])
            self.assertEqual(summary["service_failures"], [])

    def test_bird_control_error_response_is_failure_even_with_zero_exit_status(self):
        result = argparse.Namespace(returncode=0, stdout="0001 BIRD ready.\n9002 Cannot open configuration file\n", stderr="")
        with patch.object(BIRD.subprocess, "run", return_value=result), self.assertRaises(RuntimeError):
            BIRD.run("birdc -v configure", ".")
