#!/usr/bin/env python3
"""Seal, verify, and publish complete local render artifacts."""

import argparse
import fcntl
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


MANIFEST = "manifest.json"


def hashes(directory):
    result = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError("Artifact symlinks are not supported")
        if path.is_file() and path != directory / MANIFEST:
            result[str(path.relative_to(directory))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def verify(directory, node=None, kind=None):
    directory = Path(directory)
    data = json.loads((directory / MANIFEST).read_text())
    if data.get("version") != 1 or data["files"] != hashes(directory):
        raise ValueError("Artifact content does not match its manifest")
    if (node and data["node"] != node) or (kind and data["kind"] != kind):
        raise ValueError("Artifact belongs to another node or component")
    return data


def seal(directory, node, kind, source_root):
    directory = Path(directory)
    source_root = Path(source_root)
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=source_root,
                              check=True, text=True, capture_output=True).stdout.strip()
    diff = subprocess.run(["git", "diff", "--binary", "HEAD", "--", "ansible"], cwd=source_root,
                          check=True, capture_output=True).stdout
    paths = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "ansible"],
                           cwd=source_root, check=True, capture_output=True).stdout.split(b"\0")
    source_hashes = {path.decode(): hashlib.sha256((source_root / path.decode()).read_bytes()).hexdigest()
                     for path in paths if path and (source_root / path.decode()).is_file()}
    untracked = subprocess.run(["git", "ls-files", "--others", "--exclude-standard", "--", "ansible"],
                               cwd=source_root, check=True, capture_output=True).stdout
    data = {"version": 1, "node": node, "kind": kind, "source_revision": revision,
            "source_sha256": hashlib.sha256(json.dumps(source_hashes, sort_keys=True).encode()).hexdigest(),
            "tracked_diff_sha256": hashlib.sha256(diff).hexdigest(), "dirty": bool(diff or untracked),
            "files": hashes(directory)}
    (directory / MANIFEST).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def publish(stage, target):
    stage, target = Path(stage), Path(target)
    verify(stage)
    target.parent.mkdir(parents=True, exist_ok=True)
    previous = target.with_name(target.name + ".previous")
    with target.with_name(target.name + ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if previous.exists():
            if not target.exists():
                previous.rename(target)
            else:
                shutil.rmtree(previous)
        existed = target.exists()
        if existed:
            target.rename(previous)
        try:
            stage.rename(target)
        except Exception:
            if existed:
                previous.rename(target)
            raise
        if previous.exists():
            shutil.rmtree(previous)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--seal", action="store_true")
    parser.add_argument("--node")
    parser.add_argument("--kind", choices=["bird", "wireguard"])
    parser.add_argument("--source-root")
    parser.add_argument("--publish")
    args = parser.parse_args()
    if args.seal:
        if not all((args.node, args.kind, args.source_root)):
            parser.error("sealing requires node, kind, and source-root")
        seal(args.directory, args.node, args.kind, args.source_root)
    verify(args.directory, args.node, args.kind)
    if args.publish:
        publish(args.directory, args.publish)


if __name__ == "__main__":
    main()
