"""Locations for mutable broker/guard control-plane state.

The installed code tree can be root-owned and read-only. ``RAT_RUNTIME_DIR``
is deliberately separate from artifacts and challenge files so the agent and
the broker share an active-target lock without making ``CTF_HOME`` writable.
"""
from __future__ import annotations

import os


def runtime_dir(ctf_home: str | None = None) -> str:
    home = os.path.abspath(ctf_home or os.environ.get("CTF_HOME") or ".")
    return os.path.abspath(os.environ.get("RAT_RUNTIME_DIR") or home)


def active_path(ctf_home: str | None = None) -> str:
    return os.path.join(runtime_dir(ctf_home), "ACTIVE.json")
