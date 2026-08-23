"""Progress Novelty Governor.

Time-based "stuck" detection is replaced by a novelty check: if the last
`window` tool/query actions produced no new artifact digest, finding
revision, ruled-out route, or primitive status change, force a re-route or
DEEP escalation instead of continuing to retry.

This module is the pure decision hook only. Maintaining the rolling
novelty-flag history and actually triggering re-route/DEEP is the caller's
job (M4's `rat` dispatcher loop) -- CLI wiring is out of scope for M1.
"""
from __future__ import annotations

DEFAULT_WINDOW = 5

def check_progress(recent_novelty_flags, *, window=DEFAULT_WINDOW):
    """`recent_novelty_flags` is a chronological list of bool: whether each of
    the caller's last tool/query actions introduced something new (new
    artifact digest, finding revision, ruled-out route, or primitive status
    change) relative to everything already seen. Fewer than `window` actions
    recorded so far is not yet "stuck" -- there isn't enough history."""
    tail = list(recent_novelty_flags)[-window:]
    if len(tail) < window:
        return {"stuck": False, "action": None, "reason": None}
    if any(tail):
        return {"stuck": False, "action": None, "reason": None}
    return {
        "stuck": True,
        "action": "re-route-or-deep-escalate",
        "reason": "no new artifact digest / finding revision / ruled-out route / "
                  "primitive status change in the last %d actions" % window,
    }
