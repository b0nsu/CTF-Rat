"""Select the separately provisioned native-angr interpreter for rev tools."""
from __future__ import annotations

import os
import shutil
import sys


def configured_python():
    override = os.environ.get("RAT_ANGR_PYTHON")
    if override:
        candidate = os.path.expanduser(override)
        if not os.path.isabs(candidate):
            candidate = shutil.which(candidate) or candidate
        if not os.path.isfile(candidate) or not os.access(candidate, os.X_OK):
            raise ValueError("RAT_ANGR_PYTHON is not an executable: %s" % override)
        return os.path.abspath(candidate)
    root = os.environ.get("CTF_HOME") or os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    candidate = os.path.join(root, ".venv-angr", "bin", "python")
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return os.path.abspath(candidate)
    return None


def reexec_for_angr(script, argv):
    """Re-exec a rev entry point once; preserve its normal CLI and exit status."""
    try:
        python = configured_python()
    except ValueError as exc:
        print("%s: %s" % (os.path.basename(script), exc), file=sys.stderr)
        raise SystemExit(2) from exc
    # Virtualenv Python is commonly a symlink to the same base executable.
    # Comparing realpaths would mistake two different environments for one.
    if python and python != os.path.abspath(sys.executable):
        # A plain symlink to Python can set sys.executable to its target.  An
        # identity check alone would re-exec forever in that case.
        marker = "RAT_ANGR_REEXEC_TARGET"
        if os.environ.get(marker) == os.path.realpath(python):
            return
        env = os.environ.copy()
        env[marker] = os.path.realpath(python)
        os.execve(python, [python, os.path.realpath(script), *argv], env)
