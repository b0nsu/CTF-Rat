"""Real Linux GDB/MI smoke test; run explicitly in a GDB-capable environment."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
from ratlib import gdb_session
from ratlib.run_manifest import new_direct


def main():
    with tempfile.TemporaryDirectory(prefix="rat-gdb-e2e-") as directory:
        root = pathlib.Path(directory)
        source = root / "chall.c"
        source.write_text("int stage(void){volatile int value=7; return value-7;} int main(void){return stage();}\n")
        binary = root / "chall"
        subprocess.run(["gcc", "-g", "-O0", str(source), "-o", str(binary)], check=True)
        scenario = root / "scenario.json"
        scenario.write_text(json.dumps({"schema": "rat.scenario/v1", "argv": []}))
        run = new_direct("fixture", str(binary), None, None)
        run["status"] = "active"
        (root / "run.json").write_text(json.dumps(run))
        (root / "ACTIVE.json").write_text(json.dumps({"chal": "fixture"}))
        old_home = os.environ.get("CTF_HOME")
        os.environ["CTF_HOME"] = directory
        try:
            started = gdb_session.start(str(binary), str(scenario), idle_timeout=15)
            session_id = started["session_id"]
            try:
                breakpoint = gdb_session.request(str(binary), session_id, "break", target="stage")
                continued = gdb_session.request(str(binary), session_id, "continue")
                registers = gdb_session.request(str(binary), session_id, "registers")
                assert breakpoint["status"] == "ok", breakpoint
                assert continued["status"] == "ok", continued
                assert registers["status"] == "ok", registers
                assert registers["observation"]["result"]["registers"], registers
            finally:
                gdb_session.request(str(binary), session_id, "close")
        finally:
            if old_home is None:
                os.environ.pop("CTF_HOME", None)
            else:
                os.environ["CTF_HOME"] = old_home
    print("real GDB/MI session: OK")


if __name__ == "__main__":
    main()
