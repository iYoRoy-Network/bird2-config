import argparse
import contextlib
import io
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
                    raise RuntimeError("rejected")
            with patch.object(BIRD, "run", side_effect=run), self.assertRaises(RuntimeError):
                BIRD.apply(args)
            self.assertEqual((live / "peer.conf").read_text(), "old")
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
                    patch.object(WG, "backup_live", side_effect=save), patch.object(WG, "restore", side_effect=restore), \
                    patch.object(WG, "apply_service_action", side_effect=action), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(WG.main(), 1)
            self.assertEqual((live / "target.conf").read_text(), "old")
            self.assertEqual((live / "other.conf").read_text(), "unrelated")
            self.assertEqual(calls, [("stop", "target"), ("start", "target"), ("stop", "target"),
                                     ("enable", "target"), ("restart", "target")])
