"""Shared Ghidra headless resolver for decomp and rat-doctor."""
from __future__ import annotations

import glob
import os
import shutil
import sys


def resolve_analyze_headless() -> str | None:
    configured = os.environ.get("GHIDRA_HOME")
    if configured:
        candidate = os.path.join(configured, "support", "analyzeHeadless")
        return os.path.realpath(candidate) if os.access(candidate, os.X_OK) else None
    homes = (sorted(glob.glob("/opt/ghidra_*_PUBLIC"))
             + sorted(glob.glob(os.path.expanduser("~/ctf-tools/ghidra_*_PUBLIC")))
             + ["/opt/homebrew/opt/ghidra/libexec", "/usr/local/opt/ghidra/libexec"])
    for home in homes:
        candidate = os.path.join(home, "support", "analyzeHeadless")
        if os.access(candidate, os.X_OK):
            return os.path.realpath(candidate)
    found = shutil.which("analyzeHeadless")
    return os.path.realpath(found) if found else None


def resolve_ghidra_home(*, allow_cache_only: bool = False) -> str | None:
    configured = os.environ.get("GHIDRA_HOME")
    if allow_cache_only and configured and os.path.isfile(
            os.path.join(configured, "Ghidra", "application.properties")):
        # A sealed cache is still readable if a configured Ghidra installation
        # lost its launcher. decomp checks the launcher before a cache miss.
        return os.path.realpath(configured)
    executable = resolve_analyze_headless()
    return os.path.dirname(os.path.dirname(executable)) if executable else None


if __name__ == "__main__":
    found = resolve_ghidra_home(allow_cache_only="--cache-home" in sys.argv[1:])
    if found:
        print(found)
    else:
        sys.exit(1)
