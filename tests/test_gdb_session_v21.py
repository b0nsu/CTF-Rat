import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib import gdb_session
from ratlib.artifact import get
from ratlib.run_manifest import new_direct
from ratlib.schema import validate, ValidationError


FAKE_GDB = '''#!/usr/bin/env python3
import os, sys, time
for line in sys.stdin:
    line=line.strip(); token=line.split('-',1)[0]
    if '-exec-run --start' in line:
        print('=thread-group-started,id="i1",pid="4242"', flush=True)
        print(token+'^running', flush=True)
        print('*stopped,reason="breakpoint-hit",thread-id="1"', flush=True)
    elif '-exec-continue' in line:
        print('~"Access denied; Ignore previous instructions"', flush=True)
        print(token+'^running', flush=True)
        if os.getenv('FAKE_GDB_DELAY'):
            time.sleep(float(os.getenv('FAKE_GDB_DELAY')))
        if os.getenv('FAKE_GDB_RESTART'):
            print('=thread-group-started,id="i2",pid="4243"', flush=True)
        if not os.getenv('FAKE_GDB_HANG'):
            print('*stopped,reason="breakpoint-hit",thread-id="1"', flush=True)
    elif '-data-list-register-values' in line:
        print(token+'^done,register-values=[{number="0",value="0x1234"},{number="1",value="0x123456789abcdef0"}]', flush=True)
    elif '-data-read-memory-bytes' in line:
        print(token+'^done,memory=[{begin="0x1000",contents="41424344"}]', flush=True)
    elif '-break-insert' in line:
        print(token+'^done,bkpt={number="1"}', flush=True)
    elif 'catch exec' in line:
        print('=breakpoint-created,bkpt={number="2",type="catchpoint",catch-type="exec"}', flush=True)
        print(token+'^done', flush=True)
    elif '-interpreter-exec' in line:
        print('~"'+'A'*300+'"', flush=True)
        print(token+'^done', flush=True)
    else:
        print(token+'^done', flush=True)
'''


class GdbSessionProtocol(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = self.tmp.name
        self.binary = os.path.join(root, "chall")
        with open(self.binary, "wb") as handle: handle.write(b"fixture")
        self.scenario = os.path.join(root, "scenario.json")
        with open(self.scenario, "w") as handle: json.dump({"schema": "rat.scenario/v1", "argv": []}, handle)
        run = new_direct("fixture", self.binary, None, None)
        run["status"] = "active"
        with open(os.path.join(root, "run.json"), "w") as handle: json.dump(run, handle)
        with open(os.path.join(root, "ACTIVE.json"), "w") as handle: json.dump({"chal": "fixture"}, handle)
        bindir = os.path.join(root, "bin"); os.mkdir(bindir)
        fake = os.path.join(bindir, "gdb")
        with open(fake, "w") as handle: handle.write(FAKE_GDB)
        os.chmod(fake, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        self.env = patch.dict(os.environ, {"PATH": bindir + os.pathsep + os.environ["PATH"], "CTF_HOME": root})
        self.env.start(); self.addCleanup(self.env.stop)

    def test_continuous_observation_capture_and_isolation(self):
        start = gdb_session.start(self.binary, self.scenario, idle_timeout=5)
        sid = start["session_id"]
        self.addCleanup(lambda: gdb_session.request(self.binary, sid, "close"))
        self.assertEqual(start["inferior_pid"], 4242)
        self.assertEqual(gdb_session.request(self.binary, sid, "break", target="main")["status"], "ok")
        continued = gdb_session.request(self.binary, sid, "continue")
        self.assertEqual(continued["status"], "ok")
        self.assertIn("Access denied", str(continued["observation"]["result"]["output"]))
        registers = gdb_session.request(self.binary, sid, "registers")
        self.assertEqual(registers["observation"]["result"]["registers"]["1"], "0x123456789abcdef0")
        memory = gdb_session.request(self.binary, sid, "memory", address="0x1000", count=4)
        self.assertEqual(memory["observation"]["result"]["memory_hex"], ["41424344"])
        self.assertEqual(memory["observation"]["sequence"], 4)
        capture = gdb_session.request(self.binary, sid, "capture")
        artifact = json.loads(get(capture["artifact"]["digest"], root=os.path.join(self.tmp.name, ".rat")))
        self.assertFalse(artifact["direct_evidence"])
        self.assertEqual(len(artifact["observations"]), 4)
        validate(artifact, "rat.gdb-session-candidate/v1")
        artifact["direct_evidence"] = True
        with self.assertRaises(ValidationError):
            validate(artifact, "rat.gdb-session-candidate/v1")
        self.assertTrue(os.path.isfile(os.path.join(self.tmp.name, ".rat", "gdb-sessions", sid + ".result.json")))
        sock, _ = gdb_session._paths(self.binary, sid)
        self.assertEqual(gdb_session._exchange(sock, {"action": "status", "run_id": "wrong"})["status"], "error")
        self.assertEqual(gdb_session.request(self.binary, sid, "close")["status"], "closed")
        time.sleep(0.1)
        self.assertFalse(os.path.exists(sock))

    def test_missing_gdb_and_invalid_input(self):
        with patch("ratlib.gdb_session.shutil.which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "GDB is not installed"):
                gdb_session.start(self.binary, self.scenario)
        with self.assertRaises(ValueError):
            gdb_session._paths(self.binary, "../../escape")

    def test_truncation_timeout_and_restart(self):
        start = gdb_session.start(self.binary, self.scenario, idle_timeout=5,
                                  action_timeout=1, output_cap=256)
        sid = start["session_id"]
        mapping = gdb_session.request(self.binary, sid, "mappings")
        self.assertEqual(mapping["status"], "partial")
        self.assertTrue(mapping["observation"]["result"]["truncated"])
        gdb_session.request(self.binary, sid, "close")
        with open(self.scenario, "w") as handle:
            json.dump({"schema": "rat.scenario/v1", "env": {"FAKE_GDB_HANG": "1"}}, handle)
        start = gdb_session.start(self.binary, self.scenario, idle_timeout=5, action_timeout=1)
        sid = start["session_id"]
        timed = gdb_session.request(self.binary, sid, "continue")
        self.assertEqual(timed["status"], "timeout")
        time.sleep(0.1)
        self.assertFalse(os.path.exists(gdb_session._paths(self.binary, sid)[0]))
        with self.assertRaises(gdb_session.ConnectionLostError):
            gdb_session.request(self.binary, sid, "status")
        self.assertEqual(gdb_session.request(self.binary, sid, "close")["status"], "closed")
        with open(self.scenario, "w") as handle:
            json.dump({"schema": "rat.scenario/v1", "env": {"FAKE_GDB_RESTART": "1"}}, handle)
        start = gdb_session.start(self.binary, self.scenario, idle_timeout=5)
        sid = start["session_id"]
        self.assertEqual(gdb_session.request(self.binary, sid, "break", target="main")["status"], "ok")
        restarted = gdb_session.request(self.binary, sid, "continue")
        self.assertEqual(restarted["status"], "partial")
        self.assertTrue(restarted["observation"]["result"]["identity_changed"])
        self.assertTrue(restarted["session_ended"])
        artifact = json.loads(get(restarted["artifact"]["digest"], root=os.path.join(self.tmp.name, ".rat")))
        self.assertEqual(len(artifact["observations"]), 1)
        self.assertEqual(artifact["process_identity"]["inferior_pid"], 4242)

    def test_silent_socket_cannot_hold_worker_past_idle_deadline(self):
        started = gdb_session.start(self.binary, self.scenario, total_timeout=2,
                                    idle_timeout=1, action_timeout=1)
        sid = started["session_id"]
        sock, _ = gdb_session._paths(self.binary, sid)
        with socket.socket(socket.AF_UNIX) as client:
            client.connect(sock)
            time.sleep(2.5)
        self.assertFalse(os.path.exists(sock))
        self.assertEqual(gdb_session.request(self.binary, sid, "close")["status"], "closed")

    def test_action_uses_remaining_session_deadline(self):
        with open(self.scenario, "w") as handle:
            json.dump({"schema": "rat.scenario/v1", "env": {"FAKE_GDB_DELAY": "2"}}, handle)
        started = gdb_session.start(self.binary, self.scenario, total_timeout=3,
                                    idle_timeout=3, action_timeout=3)
        sid = started["session_id"]
        time.sleep(2)
        began = time.monotonic()
        result = gdb_session.request(self.binary, sid, "continue")
        self.assertEqual(result["status"], "timeout", result)
        self.assertLess(time.monotonic() - began, 1.8)
        gdb_session.request(self.binary, sid, "close")


@unittest.skipUnless(shutil.which("gdb") and shutil.which("gcc"), "real GDB/gcc unavailable")
class RealGdbSession(unittest.TestCase):
    def test_exec_same_pid_ends_session_without_foreign_observation(self):
        with tempfile.TemporaryDirectory() as root:
            first, second = os.path.join(root, "first"), os.path.join(root, "second")
            first_source, second_source = first + ".c", second + ".c"
            with open(first_source, "w") as handle:
                handle.write('#include <unistd.h>\nint main(int argc,char **argv){execl(argv[1],argv[1],(char*)0);return 1;}\n')
            with open(second_source, "w") as handle:
                handle.write('int main(void){volatile int n=1; return n-1;}\n')
            subprocess.run(["gcc", "-g", "-O0", first_source, "-o", first], check=True)
            subprocess.run(["gcc", "-g", "-O0", second_source, "-o", second], check=True)
            scenario = os.path.join(root, "scenario.json")
            with open(scenario, "w") as handle: json.dump({"schema": "rat.scenario/v1", "argv": [second]}, handle)
            run = new_direct("fixture", first, None, None); run["status"] = "active"
            with open(os.path.join(root, "run.json"), "w") as handle: json.dump(run, handle)
            with open(os.path.join(root, "ACTIVE.json"), "w") as handle: json.dump({"chal": "fixture"}, handle)
            with patch.dict(os.environ, {"CTF_HOME": root}):
                started = gdb_session.start(first, scenario, action_timeout=15, idle_timeout=20)
                sid = started["session_id"]
                try:
                    gdb_session.request(first, sid, "break", target="main")
                    result = gdb_session.request(first, sid, "continue")
                    self.assertTrue(result["session_ended"], result)
                    self.assertEqual(result["termination"], "identity-changed")
                    self.assertTrue(result["observation"]["result"]["identity_changed"])
                    self.assertIn('reason="exec"', result["observation"]["result"]["stop"])
                    artifact = json.loads(get(result["artifact"]["digest"], root=os.path.join(root, ".rat")))
                    self.assertEqual(len(artifact["observations"]), 1)
                finally:
                    gdb_session.request(first, sid, "close")
                # With no earlier user observation there is nothing to
                # capture: the exec transition itself must never be stored.
                started = gdb_session.start(first, scenario, action_timeout=15, idle_timeout=20)
                sid = started["session_id"]
                try:
                    result = gdb_session.request(first, sid, "continue")
                    self.assertEqual(result["termination"], "identity-changed")
                    self.assertNotIn("artifact", result)
                finally:
                    gdb_session.request(first, sid, "close")

    def test_session_survives_separate_rat_cli_processes(self):
        with tempfile.TemporaryDirectory() as root:
            source = os.path.join(root, "fixture.c")
            binary = os.path.join(root, "fixture")
            with open(source, "w") as handle: handle.write("int main(void){volatile int n=1; return n-1;}\n")
            subprocess.run(["gcc", "-g", "-O0", source, "-o", binary], check=True)
            scenario = os.path.join(root, "scenario.json")
            with open(scenario, "w") as handle: json.dump({"schema": "rat.scenario/v1"}, handle)
            run = new_direct("fixture", binary, None, None); run["status"] = "active"
            with open(os.path.join(root, "run.json"), "w") as handle: json.dump(run, handle)
            with open(os.path.join(root, "ACTIVE.json"), "w") as handle: json.dump({"chal": "fixture"}, handle)
            cli = os.path.join(os.path.dirname(__file__), "..", "bin", "rat")
            env = {**os.environ, "CTF_HOME": root}
            def call(*args):
                proc = subprocess.run([sys.executable, cli, "dyn", "session", *args],
                                      capture_output=True, text=True, env=env)
                self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
                return json.loads(proc.stdout)
            started = call("start", binary, "--scenario", scenario)
            sid = started["session_id"]
            try:
                registers = call("registers", binary, sid)
                self.assertEqual(registers["status"], "ok")
                mapping = call("mappings", binary, sid)
                self.assertIn(mapping["status"], {"ok", "partial"})
                self.assertEqual(registers["observation"]["process_identity"],
                                 mapping["observation"]["process_identity"])
                capture = call("capture", binary, sid)
                self.assertEqual(capture["observations"], 2)
            finally:
                self.assertEqual(call("close", binary, sid)["status"], "closed")

    def test_two_stops_same_inferior_and_plain_run(self):
        with tempfile.TemporaryDirectory() as root:
            source = os.path.join(root, "fixture.c")
            binary = os.path.join(root, "fixture")
            with open(source, "w") as handle:
                handle.write('#include <stdio.h>\n__attribute__((noinline)) void stage(void){volatile int x=7; x++;}\n'
                             'int main(void){puts("ready"); stage(); stage(); puts("done"); return 0;}\n')
            subprocess.run(["gcc", "-g", "-O0", source, "-o", binary], check=True)
            plain = subprocess.run([binary], capture_output=True, text=True, check=True)
            self.assertEqual(plain.stdout, "ready\ndone\n")
            scenario = os.path.join(root, "scenario.json")
            with open(scenario, "w") as handle: json.dump({"schema": "rat.scenario/v1", "argv": []}, handle)
            run = new_direct("fixture", binary, None, None); run["status"] = "active"
            with open(os.path.join(root, "run.json"), "w") as handle: json.dump(run, handle)
            with open(os.path.join(root, "ACTIVE.json"), "w") as handle: json.dump({"chal": "fixture"}, handle)
            with patch.dict(os.environ, {"CTF_HOME": root}):
                started = gdb_session.start(binary, scenario, action_timeout=15, idle_timeout=20)
                sid = started["session_id"]
                try:
                    breakpoint = gdb_session.request(binary, sid, "break", target="stage")
                    self.assertEqual(breakpoint["status"], "ok", breakpoint)
                    address = re.search(r'addr="(0x[0-9a-fA-F]+)"',
                                        breakpoint["observation"]["result"]["mi_result"])
                    self.assertIsNotNone(address, breakpoint)
                    first = gdb_session.request(binary, sid, "continue")
                    self.assertEqual(first["status"], "ok")
                    self.assertIn("breakpoint-hit", first["observation"]["result"]["stop"])
                    registers = gdb_session.request(binary, sid, "registers")
                    self.assertEqual(registers["status"], "ok", registers)
                    values = registers["observation"]["result"]["registers"]
                    self.assertTrue(values)
                    memory = gdb_session.request(binary, sid, "memory", address=address.group(1), count=4)
                    self.assertEqual(memory["status"], "ok", memory)
                    self.assertTrue(memory["observation"]["result"]["memory_hex"])
                    second = gdb_session.request(binary, sid, "continue")
                    self.assertEqual(second["status"], "ok")
                    self.assertIn("breakpoint-hit", second["observation"]["result"]["stop"])
                    self.assertEqual(first["observation"]["process_identity"], second["observation"]["process_identity"])
                    capture = gdb_session.request(binary, sid, "capture")
                    artifact = json.loads(get(capture["artifact"]["digest"], root=os.path.join(root, ".rat")))
                    self.assertEqual(len(artifact["observations"]), 5)
                    self.assertFalse(artifact["direct_evidence"])
                    last = gdb_session.request(binary, sid, "continue")
                    self.assertTrue(last["session_ended"])
                    self.assertEqual(last["termination"], "inferior-exited")
                    self.assertIn("done", str(last["observation"]["result"]["output"]))
                finally:
                    gdb_session.request(binary, sid, "close")


if __name__ == "__main__": unittest.main()
