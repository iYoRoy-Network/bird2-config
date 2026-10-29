import argparse
import contextlib
import io
import json
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
                return {"failed": action == "start" and not ignore_failure}
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
            self.assertEqual(calls, [("stop", "target"), ("start", "target"), ("stop", "target"),
                                     ("enable", "target"), ("start", "target")])

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
                if name == "start" and not ignore_failure:
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

    def test_wireguard_ignored_start_failure_does_not_block_other_interfaces(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live, stage, backup = root / "live", root / "stage", root / "backup"
            live.mkdir()
            stage.mkdir()
            (live / "changed.conf").write_text("old")
            (live / "unavailable.conf").write_text("same")
            (stage / "changed.conf").write_text("new")
            (stage / "unavailable.conf").write_text("same")
            calls = []

            def action(manager, name, interface, dry_run, ignore_failure=False):
                calls.append((name, interface))
                if name == "start" and interface == "unavailable":
                    return {"failed": True, "interface": interface, "action": name, "rc": 1}
                return {"rc": 0}

            def save(*_):
                shutil.copytree(live, backup)
                return True

            def promote(staging, live_dir):
                shutil.copytree(staging, live_dir, dirs_exist_ok=True)

            argv = ["wg", "--live-dir", str(live), "--staging-dir", str(stage),
                    "--backup-dir", str(backup), "--ignore-start-failure=unavailable"]
            output = io.StringIO()
            with patch.object(sys, "argv", argv), patch.object(WG, "enabled_systemd", return_value={"changed", "unavailable"}), \
                    patch.object(WG, "active_interfaces", return_value={"changed"}), \
                    patch.object(WG, "backup_live", side_effect=save), \
                    patch.object(WG, "promote", side_effect=promote), \
                    patch.object(WG, "apply_service_action", side_effect=action), contextlib.redirect_stdout(output):
                self.assertEqual(WG.main(), 0)

            self.assertEqual((live / "changed.conf").read_text(), "new")
            self.assertEqual((live / "unavailable.conf").read_text(), "same")
            self.assertIn(("start", "changed"), calls)
            summary = json.loads(output.getvalue())
            self.assertEqual([failure["interface"] for failure in summary["ignored_service_failures"]],
                             ["unavailable"])
            self.assertTrue(summary["ignored_service_failures"][0]["ignored_failure"])

    def test_bird_control_error_response_is_failure_even_with_zero_exit_status(self):
        result = argparse.Namespace(returncode=0, stdout="0001 BIRD ready.\n9002 Cannot open configuration file\n", stderr="")
        with patch.object(BIRD.subprocess, "run", return_value=result), self.assertRaises(RuntimeError):
            BIRD.run("birdc -v configure", ".")
