#!/usr/bin/env python3
"""Inline selected BIRD ``define``s into rendered config files.

A BIRD ``define`` is a textual macro, so substituting its value at every use
site and dropping the definition is semantics-preserving. This flattens the
"data plane" constants (prefixes, netsets, loopbacks, LLAs) in the rendered
output while leaving the "control plane" vocabulary (ASN identities, geo codes,
confederation AS range, router ids) as named ``define``s.

Usage::

    BIRD_DEFINE_INLINE="NAME1 NAME2 ..." flatten_bird_defines.py <node_dir>

The define values are read from ``<node_dir>/bird.conf``; the substitution is
applied to every ``*.conf`` under ``<node_dir>`` (whole-word, longest name
first). Defines not listed in ``BIRD_DEFINE_INLINE`` are left untouched.
"""
import os
import re
import sys

DEFINE_RE = re.compile(
    r"^[ \t]*define[ \t]+(\w+)[ \t]*=[ \t]*(.*?);[ \t]*\n?", re.MULTILINE
)


def main(argv):
    if len(argv) != 2:
        sys.stderr.write(__doc__)
        return 2

    node_dir = argv[1]
    wanted = set((os.environ.get("BIRD_DEFINE_INLINE") or "").split())
    if not wanted:
        return 0

    bird_conf = os.path.join(node_dir, "bird.conf")
    with open(bird_conf) as fh:
        text = fh.read()

    values = {m.group(1): m.group(2) for m in DEFINE_RE.finditer(text)}
    targets = {name: values[name] for name in wanted if name in values}
    if not targets:
        return 0

    # Drop the define lines we are inlining (leave untouched ones intact).
    def _drop(match):
        return "" if match.group(1) in targets else match.group(0)

    with open(bird_conf, "w") as fh:
        fh.write(DEFINE_RE.sub(_drop, text))

    # Substitute whole-word occurrences across every rendered conf file.
    names = sorted(targets, key=len, reverse=True)
    patterns = {n: re.compile(r"\b%s\b" % re.escape(n)) for n in names}

    for root, _dirs, files in os.walk(node_dir):
        for filename in files:
            if not filename.endswith(".conf"):
                continue
            path = os.path.join(root, filename)
            with open(path) as fh:
                before = fh.read()
            after = before
            for name in names:
                after = patterns[name].sub(lambda _m, v=targets[name]: v, after)
            if after != before:
                with open(path, "w") as fh:
                    fh.write(after)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
