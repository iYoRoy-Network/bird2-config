#!/usr/bin/env python3
"""Apply a BIRD tree or peer file with validation and recovery."""

import argparse
import fcntl
from fnmatch import fnmatch
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys


def run(command, directory):
    result = subprocess.run(shlex.split(command), cwd=directory, capture_output=True, text=True)
    if result.returncode or re.search(r"^9\d{3}[ -]", result.stdout, re.MULTILINE) or any(
        word in result.stdout.lower() for word in ("syntax error", "reconfiguration failed", "configuration error")
    ):
        raise RuntimeError(result.stderr or result.stdout)


def apply(args):
    live, stage, backup = map(Path, (args.live_dir, args.staging_dir, args.backup_dir))
    if args.file and (Path(args.file).is_absolute() or ".." in Path(args.file).parts):
        raise ValueError("Expected a relative peer file")
    if args.dry_run:
        return {"dry_run": True, "file": args.file}
    existed = live.exists()
    if existed:
        shutil.copytree(live, backup)
    else:
        live.mkdir(parents=True)
    try:
        if args.file:
            target = live / args.file
            target.parent.mkdir(parents=True, exist_ok=True)
            if args.remove:
                target.unlink(missing_ok=True)
            else:
                temporary = target.with_suffix(target.suffix + ".tmp")
                shutil.copyfile(stage / args.file, temporary)
                temporary.chmod(0o644)
                temporary.replace(target)
            (live / "manifest.json").unlink(missing_ok=True)
        else:
            run(args.check_command, stage)
            for path in live.iterdir():
                if not any(fnmatch(path.name, pattern) for pattern in args.preserve):
                    shutil.rmtree(path) if path.is_dir() else path.unlink()
            shutil.copytree(stage, live, dirs_exist_ok=True)
        run(args.check_command, live)
        run(args.reload_command, live)
    except Exception:
        if args.file:
            for relative in (args.file, "manifest.json"):
                source, target = backup / relative, live / relative
                if source.exists():
                    shutil.copy2(source, target)
                else:
                    target.unlink(missing_ok=True)
        else:
            shutil.rmtree(live)
            if existed:
                shutil.copytree(backup, live)
        if existed:
            run(args.check_command, live)
            run(args.reload_command, live)
        raise
    return {"changed": True, "file": args.file, "backup": str(backup)}


def main():
    parser = argparse.ArgumentParser()
    for name in ("staging-dir", "live-dir", "backup-dir"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--file")
    parser.add_argument("--remove", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--preserve", action="append", default=[])
    parser.add_argument("--check-command", default="bird -p -c bird.conf")
    parser.add_argument("--reload-command", default="birdc -v configure")
    args = parser.parse_args()
    lock = Path(args.live_dir).parent / ".bird-deploy.lock"
    with lock.open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            print(json.dumps(apply(args)))
        except Exception as error:
            print(json.dumps({"error": str(error)}), file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
