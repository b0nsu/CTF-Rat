"""Isolated revq CFGFast extraction worker. Invoked only by revq's parent."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import sys


def main(argv):
    if len(argv) != 4:
        return 2
    binary, output, load_spec_json, scope_json = argv
    script = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "revq"))
    sys.path.insert(0, os.path.dirname(script))
    loader = importlib.machinery.SourceFileLoader("_worker_revq", script)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    revq = importlib.util.module_from_spec(spec)
    loader.exec_module(revq)
    try:
        load_spec = json.loads(load_spec_json)
        scope = json.loads(scope_json)
        options = None
        if scope:
            options = {"regions": [(scope["addr"], scope["end"])],
                       "function_starts": [scope["addr"]], "start_at_entry": False,
                       "force_complete_scan": False, "symbols": False}
        result = revq.extract_angr(binary, load_spec, cfg_options=options)
        with open(output, "w", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=False)
        return 0
    except MemoryError:
        print("RAT_ANGR_WORKER_OOM: address-space limit reached", file=sys.stderr)
        return 71
    except Exception as exc:
        print("RAT_ANGR_WORKER_ERROR: %s: %s" % (type(exc).__name__, str(exc)[:500]),
              file=sys.stderr)
        return 70


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
