import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from ansible.errors import AnsibleFilterError
from test_intent import INTENT, plugin
from test_geo import ROOT


ARTIFACT = plugin("artifact", "files")


class ArtifactTests(unittest.TestCase):
    def test_changed_or_extra_files_and_wrong_identity_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bird.conf").write_text("router id 192.0.2.1;")
            ARTIFACT.seal(root, "test", "bird", ROOT)
            ARTIFACT.verify(root, "test", "bird")
            with self.assertRaises(ValueError):
                ARTIFACT.verify(root, "another-node", "bird")
            (root / "extra.conf").write_text("unexpected")
            with self.assertRaises(ValueError):
                ARTIFACT.verify(root)
            (root / "extra.conf").unlink()
            (root / "bird.conf").write_text("changed")
            with self.assertRaises(ValueError):
                ARTIFACT.verify(root)

    def test_incomplete_stage_never_replaces_previous_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live, stage = root / "live", root / "stage"
            live.mkdir()
            stage.mkdir()
            (live / "bird.conf").write_text("previous")
            (stage / "bird.conf").write_text("incomplete")
            with self.assertRaises(FileNotFoundError):
                ARTIFACT.publish(stage, live)
            self.assertEqual((live / "bird.conf").read_text(), "previous")
            ARTIFACT.seal(stage, "test", "bird", ROOT)
            ARTIFACT.publish(stage, live)
            self.assertEqual((live / "bird.conf").read_text(), "incomplete")
            ARTIFACT.verify(live)

    def test_snapshot_must_match_current_queries(self):
        peer = {"neighbor": {"asn": 65000}, "as_set": "RADB::AS-TEST"}
        queries = INTENT.irr_queries({"peers": [peer, peer]})
        snapshot = {"queries": queries, "sets": {"peer_65000_as_set": [65002, 65000, 65002]}}
        self.assertEqual(INTENT.irr_defines(snapshot, queries), "define peer_65000_as_set = [65000, 65002];\n")
        with self.assertRaises(AnsibleFilterError):
            INTENT.irr_defines(snapshot, {"peer_65000_as_set": "AS-CHANGED"})
        with self.assertRaises(AnsibleFilterError):
            INTENT.irr_queries({"peers": [peer, {**peer, "as_set": "AS-OTHER"}]})

    def test_failed_publish_restores_previous_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live, stage = root / "live", root / "stage"
            for path, content in ((live, "old"), (stage, "new")):
                path.mkdir()
                (path / "bird.conf").write_text(content)
                ARTIFACT.seal(path, "test", "bird", ROOT)
            rename = Path.rename
            def fail_publish(path, target):
                if path == stage:
                    raise OSError("injected publish failure")
                return rename(path, target)
            with patch.object(Path, "rename", fail_publish), self.assertRaises(OSError):
                ARTIFACT.publish(stage, live)
            self.assertEqual((live / "bird.conf").read_text(), "old")
            ARTIFACT.verify(live, "test", "bird")
