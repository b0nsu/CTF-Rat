#!/usr/bin/env python3
"""Compatibility entrypoint for the bounded instruction-trace runtime.

The historical ``--calls`` option was misleading because Qiling ``hook_code``
observes every instruction.  This scaffold names that data honestly and
delegates timeout/process cleanup to ``bin/rat-qiling``.
"""
import os
import sys


def main() -> int:
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    runner = os.path.join(root, "bin", "rat-qiling")
    if not os.path.isfile(runner):
        print("[qiling_trace:err] bin/rat-qiling not found", file=sys.stderr)
        return 3
    os.execv(runner, [runner, *sys.argv[1:]])
    return 70


if __name__ == "__main__":
    raise SystemExit(main())
