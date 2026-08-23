#!/usr/bin/env python3
"""P0 regression tests for untrusted ingest and bounded execution."""
import io
import importlib.machinery
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "bin")
if BIN not in sys.path:
    sys.path.insert(0, BIN)

from ratlib.runner import (EXIT_CANCELLED, EXIT_DEPENDENCY, EXIT_TIMEOUT,
                           ResourceLimits, RunnerPolicyError, run)
from ratlib.safe_archive import ArchiveError, ArchivePolicy, load_policy, safe_extract_archive
from ratlib.decomp_cache import validate as validate_decomp_cache, write_meta as write_decomp_meta
from ratlib.run_manifest import atomic_write as write_shared_manifest
from ratlib.run_manifest import new_direct as new_direct_manifest


def load_ctfpull_module():
    path = os.path.join(BIN, "ctfpull")
    loader = importlib.machinery.SourceFileLoader("ctfpull_test_module", path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class SafeArchiveTests(unittest.TestCase):
    def make_zip(self, path, entries):
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, data in entries:
                zf.writestr(name, data)

    def test_extracts_regular_files_without_shell_interpretation(self):
        with tempfile.TemporaryDirectory() as temp:
            archive, dest = os.path.join(temp, "input.zip"), os.path.join(temp, "dest")
            self.make_zip(archive, [("dir/- strange name\n", b"ok")])
            self.assertEqual(safe_extract_archive(archive, dest), 1)
            with open(os.path.join(dest, "dir", "- strange name\n"), "rb") as f:
                self.assertEqual(f.read(), b"ok")

    def test_rejects_traversal_without_destination_write(self):
        with tempfile.TemporaryDirectory() as temp:
            archive, dest = os.path.join(temp, "bad.zip"), os.path.join(temp, "dest")
            os.makedirs(dest)
            sentinel = os.path.join(dest, "sentinel")
            with open(sentinel, "wb") as f:
                f.write(b"keep")
            self.make_zip(archive, [("../outside", b"no")])
            with self.assertRaises(ArchiveError):
                safe_extract_archive(archive, dest)
            with open(sentinel, "rb") as f:
                self.assertEqual(f.read(), b"keep")
            self.assertFalse(os.path.exists(os.path.join(temp, "outside")))

    def test_rejects_absolute_drive_and_backslash_traversal(self):
        for bad in ("/absolute", "C:/drive", "..\\outside"):
            with self.subTest(name=bad), tempfile.TemporaryDirectory() as temp:
                archive = os.path.join(temp, "bad.zip")
                self.make_zip(archive, [(bad, b"no")])
                with self.assertRaises(ArchiveError):
                    safe_extract_archive(archive, os.path.join(temp, "dest"))

    def test_rejects_zip_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = os.path.join(temp, "link.zip")
            info = zipfile.ZipInfo("link")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr(info, "target")
            with self.assertRaises(ArchiveError):
                safe_extract_archive(archive, os.path.join(temp, "dest"))

    def test_rejects_tar_link(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = os.path.join(temp, "link.tar")
            with tarfile.open(archive, "w") as tf:
                member = tarfile.TarInfo("link")
                member.type = tarfile.SYMTYPE
                member.linkname = "/etc/passwd"
                tf.addfile(member)
            with self.assertRaises(ArchiveError):
                safe_extract_archive(archive, os.path.join(temp, "dest"))

    def test_rejects_tar_hardlink_and_device(self):
        for member_type in (tarfile.LNKTYPE, tarfile.CHRTYPE):
            with self.subTest(member_type=member_type), tempfile.TemporaryDirectory() as temp:
                archive = os.path.join(temp, "special.tar")
                with tarfile.open(archive, "w") as tf:
                    member = tarfile.TarInfo("special")
                    member.type = member_type
                    member.linkname = "target"
                    tf.addfile(member)
                with self.assertRaises(ArchiveError):
                    safe_extract_archive(archive, os.path.join(temp, "dest"))

    def test_rejects_compression_bomb_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = os.path.join(temp, "bomb.zip")
            self.make_zip(archive, [("zeros", b"\0" * 8192)])
            policy = ArchivePolicy(max_compression_ratio=2)
            with self.assertRaises(ArchiveError):
                safe_extract_archive(archive, os.path.join(temp, "dest"), policy)

    def test_never_overwrites_existing_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            archive, dest = os.path.join(temp, "input.zip"), os.path.join(temp, "dest")
            os.makedirs(dest)
            with open(os.path.join(dest, "same"), "wb") as f:
                f.write(b"old")
            self.make_zip(archive, [("same", b"new")])
            with self.assertRaises(ArchiveError):
                safe_extract_archive(archive, dest)
            with open(os.path.join(dest, "same"), "rb") as f:
                self.assertEqual(f.read(), b"old")

    def test_rejects_duplicate_and_overlong_names(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = os.path.join(temp, "duplicate.zip")
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("same", b"a"); zf.writestr("same", b"b")
            with self.assertRaises(ArchiveError):
                safe_extract_archive(archive, os.path.join(temp, "dest"))
        with tempfile.TemporaryDirectory() as temp:
            archive = os.path.join(temp, "long.zip")
            self.make_zip(archive, [("x" * 241, b"a")])
            with self.assertRaises(ArchiveError):
                safe_extract_archive(archive, os.path.join(temp, "dest"))

    def test_unicode_and_glob_names_remain_distinct(self):
        with tempfile.TemporaryDirectory() as temp:
            archive, dest = os.path.join(temp, "names.zip"), os.path.join(temp, "dest")
            self.make_zip(archive, [("é", b"nfc"), ("e\u0301", b"nfd"), ("[abc]*?", b"glob")])
            safe_extract_archive(archive, dest)
            self.assertEqual(sorted(os.listdir(dest)), sorted(["é", "e\u0301", "[abc]*?"]))

    def test_policy_file_can_only_tighten_limits(self):
        with tempfile.TemporaryDirectory() as temp:
            path = os.path.join(temp, "policy.json")
            with open(path, "w") as f: f.write('{"max_members": 2, "max_depth": 1}')
            policy = load_policy(path)
            self.assertEqual((policy.max_members, policy.max_depth), (2, 1))
            with open(path, "w") as f: f.write('{"max_members": 999999}')
            with self.assertRaises(ArchiveError): load_policy(path)

    def test_ctfpull_uses_fail_closed_extractor(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = os.path.join(temp, "bad.zip")
            self.make_zip(archive, [("../outside", b"no")])
            with self.assertRaises(ArchiveError):
                load_ctfpull_module().extract_archives(temp)

    def test_ctfpull_rejects_nested_archive_beyond_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            inner2 = io.BytesIO()
            with zipfile.ZipFile(inner2, "w") as zf: zf.writestr("payload", b"x")
            inner1 = io.BytesIO()
            with zipfile.ZipFile(inner1, "w") as zf: zf.writestr("inner2.zip", inner2.getvalue())
            self.make_zip(os.path.join(temp, "outer.zip"), [("inner1.zip", inner1.getvalue())])
            with self.assertRaises(ArchiveError):
                load_ctfpull_module().extract_archives(temp, ArchivePolicy(max_depth=2))


class RunnerTests(unittest.TestCase):
    def test_success_and_stderr_capture(self):
        result = run([sys.executable, "-c", "import sys; print('ok'); print('warn', file=sys.stderr)"],
                     tool_version="python-fixture-v1")
        self.assertEqual(result.exit_code, 0)
        self.assertIn(b"ok", result.stdout.preview)
        self.assertIn(b"warn", result.stderr.preview)
        self.assertEqual(result.tool_version, "python-fixture-v1")

    def test_signal_is_recorded_and_shell_exit_is_preserved(self):
        result = run([sys.executable, "-c", "import os,signal;os.kill(os.getpid(),signal.SIGTERM)"])
        self.assertEqual((result.signal, result.exit_code), (15, 143))

    def test_cpu_resource_limit_uses_timeout_exit(self):
        result = run([sys.executable, "-c", "while True: pass"], timeout_seconds=5,
                     limits=ResourceLimits(cpu_seconds=1))
        self.assertTrue(result.resource_limited)
        self.assertEqual(result.exit_code, EXIT_TIMEOUT)

    def test_timeout_has_common_exit_code(self):
        start = time.monotonic()
        result = run([sys.executable, "-c", "import time; time.sleep(10)"], timeout_seconds=0.1)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.exit_code, EXIT_TIMEOUT)
        self.assertLess(time.monotonic() - start, 3)

    def test_cancel_has_common_exit_code(self):
        cancel = threading.Event()
        timer = threading.Timer(0.1, cancel.set); timer.start()
        try:
            result = run([sys.executable, "-c", "import time; time.sleep(10)"], cancel_event=cancel)
        finally:
            timer.cancel()
        self.assertTrue(result.cancelled)
        self.assertEqual(result.exit_code, EXIT_CANCELLED)

    def test_default_process_budget_allows_descendant_then_kills_group(self):
        code = "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);print(p.pid,flush=True);time.sleep(30)"
        result = run([sys.executable, "-c", code], timeout_seconds=0.4, grace_seconds=0.05)
        self.assertEqual(result.exit_code, EXIT_TIMEOUT, result.stderr.preview)
        pid = int(result.stdout.preview.strip())
        for _ in range(20):
            if not os.path.exists("/proc/%d" % pid): break
            time.sleep(0.05)
        self.assertFalse(os.path.exists("/proc/%d" % pid))

    def test_default_environment_does_not_leak_secret(self):
        old = os.environ.get("RAT_TEST_SECRET")
        os.environ["RAT_TEST_SECRET"] = "do-not-inherit"
        try:
            result = run([sys.executable, "-c", "import os;print(os.environ.get('RAT_TEST_SECRET','missing'))"])
        finally:
            if old is None: os.environ.pop("RAT_TEST_SECRET", None)
            else: os.environ["RAT_TEST_SECRET"] = old
        self.assertEqual(result.stdout.preview.strip(), b"missing")

    def test_output_cap_keeps_draining_and_marks_truncation(self):
        with tempfile.TemporaryDirectory() as temp:
            result = run([sys.executable, "-c", "import sys; sys.stdout.write('x' * 20000)"],
                         preview_bytes=64, max_output_bytes=1024, spool_dir=temp,
                         spool_threshold_bytes=64)
            self.assertEqual(result.exit_code, 0)
            self.assertTrue(result.stdout.truncated)
            self.assertEqual(len(result.stdout.preview), 64)
            self.assertEqual(os.path.getsize(result.stdout.spool_path), 1024)

    def test_missing_command_is_dependency_error(self):
        result = run(["definitely-not-a-ctf-rat-command"])
        self.assertEqual(result.exit_code, EXIT_DEPENDENCY)

    def test_unenforceable_network_policy_fails_closed(self):
        with self.assertRaises(RunnerPolicyError):
            run([sys.executable, "-c", "pass"], network="none")

    def test_guarded_network_preflight_runs_before_child(self):
        with tempfile.TemporaryDirectory() as temp:
            os.makedirs(os.path.join(temp, "bin"))
            guard = os.path.join(temp, "bin", "ctfguard")
            with open(guard, "w") as f:
                f.write("#!/bin/sh\n[ \"$1:$2:$3\" = 'check-target:allowed:1' ]\n")
            os.chmod(guard, 0o755)
            accepted = run([sys.executable, "-c", "print('started')"],
                           network="ctfguard-target", guard_target=["allowed", "1"], ctf_home=temp)
            self.assertEqual(accepted.exit_code, 0)
            self.assertIn(b"started", accepted.stdout.preview)
            with self.assertRaises(RunnerPolicyError):
                run([sys.executable, "-c", "raise RuntimeError('must not start')"],
                    network="ctfguard-target", guard_target=["other", "1"], ctf_home=temp)


class DecompCacheTests(unittest.TestCase):
    def fixture(self, temp):
        binary = os.path.join(temp, "binary")
        with open(binary, "wb") as f: f.write(b"first")
        scripts = os.path.join(temp, "scripts"); os.makedirs(scripts)
        for name in ("DecompExport.java", "DecompOne.java"):
            with open(os.path.join(scripts, name), "w") as f: f.write(name)
        ghidra = os.path.join(temp, "ghidra")
        os.makedirs(os.path.join(ghidra, "Ghidra"))
        with open(os.path.join(ghidra, "Ghidra", "application.properties"), "w") as f:
            f.write("application.version=11.test\n")
        cache = binary + ".decomp"; os.makedirs(cache)
        with open(os.path.join(cache, "_index.txt"), "w") as f: f.write("00001000\tmain\t10\n")
        return binary, scripts, ghidra, cache

    def test_content_and_tool_provenance_cache_key(self):
        with tempfile.TemporaryDirectory() as temp:
            binary, scripts, ghidra, cache = self.fixture(temp)
            write_decomp_meta(cache, binary, ghidra, scripts, "complete")
            self.assertEqual(validate_decomp_cache(cache, binary, ghidra, scripts), (True, "hit"))
            old_mtime = os.stat(binary).st_mtime_ns
            with open(binary, "wb") as f: f.write(b"other")
            os.utime(binary, ns=(old_mtime, old_mtime))
            self.assertEqual(validate_decomp_cache(cache, binary, ghidra, scripts), (False, "stale"))

    def test_tool_and_script_changes_invalidate_cache(self):
        with tempfile.TemporaryDirectory() as temp:
            binary, scripts, ghidra, cache = self.fixture(temp)
            write_decomp_meta(cache, binary, ghidra, scripts, "complete")
            with open(os.path.join(scripts, "DecompOne.java"), "a") as f: f.write("changed")
            self.assertEqual(validate_decomp_cache(cache, binary, ghidra, scripts), (False, "stale"))
            write_decomp_meta(cache, binary, ghidra, scripts, "complete")
            with open(os.path.join(ghidra, "Ghidra", "application.properties"), "w") as f:
                f.write("application.version=12.test\n")
            self.assertEqual(validate_decomp_cache(cache, binary, ghidra, scripts), (False, "stale"))

    def test_partial_cache_is_never_a_hit(self):
        with tempfile.TemporaryDirectory() as temp:
            binary, scripts, ghidra, cache = self.fixture(temp)
            write_decomp_meta(cache, binary, ghidra, scripts, "partial", "timeout")
            self.assertEqual(validate_decomp_cache(cache, binary, ghidra, scripts), (False, "partial"))

    def test_failed_function_export_cannot_be_marked_complete(self):
        with tempfile.TemporaryDirectory() as temp:
            binary, scripts, ghidra, cache = self.fixture(temp)
            with open(os.path.join(cache, ".rat-decomp-status.json"), "w") as f:
                json.dump({"discovered": 2, "exported": 1, "failed": ["00401000"]}, f)
            write_decomp_meta(cache, binary, ghidra, scripts, "complete")
            with open(os.path.join(cache, ".rat-cache.json")) as f: meta=json.load(f)
            self.assertEqual(meta["status"], "partial"); self.assertEqual(meta["failed_functions"], ["00401000"])

    def test_decomp_missing_dependency_has_common_exit(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = os.path.join(temp, "binary")
            with open(binary, "wb") as f: f.write(b"not-elf")
            result = subprocess.run([os.path.join(BIN, "decomp"), "--timeout", "1", binary],
                                    env=dict(os.environ, CTF_HOME=os.path.abspath(os.path.join(BIN, "..")),
                                             GHIDRA_HOME=os.path.join(temp, "missing")),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(result.returncode, EXIT_DEPENDENCY, result.stderr)
            self.assertIn("dependency_missing", result.stderr)

    def test_decomp_timeout_is_partial_and_uses_common_exit(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = os.path.join(temp, "binary")
            with open(binary, "wb") as f: f.write(b"fixture")
            ghidra = os.path.join(temp, "ghidra")
            os.makedirs(os.path.join(ghidra, "support"))
            os.makedirs(os.path.join(ghidra, "Ghidra"))
            with open(os.path.join(ghidra, "Ghidra", "application.properties"), "w") as f:
                f.write("application.version=fake\n")
            analyzer = os.path.join(ghidra, "support", "analyzeHeadless")
            with open(analyzer, "w") as f: f.write("#!/bin/sh\nsleep 10\n")
            os.chmod(analyzer, 0o755)
            completed = subprocess.run([os.path.join(BIN, "decomp"), "--timeout", "1", binary],
                                       env=dict(os.environ, CTF_HOME=os.path.abspath(os.path.join(BIN, "..")),
                                                GHIDRA_HOME=ghidra),
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            self.assertEqual(completed.returncode, EXIT_TIMEOUT, completed.stderr)
            self.assertIn("RAT_STATUS=timeout", completed.stderr)
            with open(binary + ".decomp/.rat-cache.json") as f: meta = json.load(f)
            self.assertEqual(meta["status"], "partial")


class ManifestAndQilingTests(unittest.TestCase):
    def test_invalid_manifest_does_not_replace_existing_file(self):
        module = load_ctfpull_module()
        with tempfile.TemporaryDirectory() as temp:
            path = os.path.join(temp, "run.json")
            with open(path, "w") as f: f.write("original\n")
            with self.assertRaises(ValueError): module.write_run_manifest(path, {"schema": "rat.run/v1"})
            with open(path) as f: self.assertEqual(f.read(), "original\n")

    def test_qiling_missing_dependency_is_explicit(self):
        if importlib.util.find_spec("qiling") is not None:
            self.skipTest("Qiling installed; dependency-missing branch not applicable")
        with tempfile.TemporaryDirectory() as temp:
            binary = os.path.join(temp, "binary"); rootfs = os.path.join(temp, "rootfs")
            with open(binary, "wb") as f: f.write(b"x")
            os.makedirs(rootfs)
            result = subprocess.run([os.path.join(BIN, "rat-qiling"), binary, "--rootfs", rootfs],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(result.returncode, EXIT_DEPENDENCY, result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "dependency_missing")

    def test_qiling_instruction_hook_stops_at_budget(self):
        with tempfile.TemporaryDirectory() as temp:
            package = os.path.join(temp, "qiling"); os.makedirs(package)
            with open(os.path.join(package, "const.py"), "w") as f:
                f.write("class QL_VERBOSE:\n    OFF = 0\n")
            with open(os.path.join(package, "__init__.py"), "w") as f:
                f.write("""import os
class Qiling:
    def __init__(self, argv, rootfs, verbose=0):
        self.rootfs=rootfs; self.running=True; self.hook=None
    def hook_code(self, callback): self.hook=callback
    def emu_stop(self): self.running=False
    def run(self):
        open(os.path.join(self.rootfs,'pid'),'w').write(str(os.getpid()))
        address=0
        while self.running:
            address += 1; self.hook(self, address, 1)
            if address % 1000 == 0:
                open(os.path.join(self.rootfs,'heartbeat'),'w').write(str(address))
        open(os.path.join(self.rootfs,'stopped'),'w').write(str(address))
""")
            binary = os.path.join(temp, "sample.exe"); rootfs = os.path.join(temp, "rootfs")
            with open(binary, "wb") as f: f.write(b"MZ")
            os.makedirs(rootfs)
            env = dict(os.environ, PYTHONPATH=temp)
            completed = subprocess.run([os.path.join(BIN, "rat-qiling"), binary, "--rootfs", rootfs,
                                        "--instruction-budget", "7", "--timeout", "2"],
                                       env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                       timeout=5)
            payload = json.loads(completed.stdout)
            self.assertEqual(completed.returncode, EXIT_TIMEOUT, completed.stderr)
            self.assertEqual((payload["reason"], payload["hook_type"], payload["instructions"]),
                             ("instruction_budget", "instruction", 7))
            with open(os.path.join(rootfs, "stopped")) as f:
                self.assertEqual(f.read(), "7")
            with open(os.path.join(rootfs, "pid")) as f:
                pid = int(f.read())
            self.assertFalse(os.path.exists("/proc/%d" % pid))

            wall_rootfs = os.path.join(temp, "wall-rootfs"); os.makedirs(wall_rootfs)
            # 0.1s previously: too tight under amd64-under-emulation (docker/dev on
            # Apple Silicon) where a single Python interpreter cold-start already
            # costs ~0.1s, and rat-qiling spawns a *second* nested interpreter for
            # the bounded run -- the wall-clock deadline could fire before the
            # child even reached Qiling.run(). 1.5s keeps ample headroom below the
            # instruction-budget of 1e9 (which the pure-Python mock hook loop
            # would take far longer than 1.5s to reach), so this still reliably
            # exercises the wall_timeout branch rather than instruction_budget.
            wall = subprocess.run([os.path.join(BIN, "rat-qiling"), binary, "--rootfs", wall_rootfs,
                                   "--instruction-budget", "1000000000", "--timeout", "1.5"],
                                  env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                  timeout=10)
            wall_payload = json.loads(wall.stdout)
            self.assertEqual((wall.returncode, wall_payload["reason"]),
                             (EXIT_TIMEOUT, "wall_timeout"), wall.stderr)
            with open(os.path.join(wall_rootfs, "pid")) as f:
                wall_pid = int(f.read())
            for _ in range(20):
                if not os.path.exists("/proc/%d" % wall_pid): break
                time.sleep(0.05)
            self.assertFalse(os.path.exists("/proc/%d" % wall_pid))


class NewchalTests(unittest.TestCase):
    def make_home(self, temp):
        for path in ("bin", "solve", "solve/_template"):
            os.makedirs(os.path.join(temp, path), exist_ok=True)
        with open(os.path.join(temp, "solve/_template/state.md"), "w") as f:
            f.write("# {{NAME}} {{BIN}} {{REMOTE}}\n")
        for name, body in (("ctfguard", "exit 0"), ("libcgate", "exit 0"),
                           ("recon", "echo recon-ok")):
            path = os.path.join(temp, "bin", name)
            with open(path, "w") as f: f.write("#!/bin/sh\n%s\n" % body)
            os.chmod(path, 0o755)

    def test_staging_manifest_identity_is_materialized_in_solve(self):
        with tempfile.TemporaryDirectory() as temp:
            self.make_home(temp)
            binary = os.path.join(temp, "incoming.bin")
            with open(binary, "wb") as f: f.write(b"fixture")
            with open(os.path.join(temp, "Dockerfile"), "w") as f: f.write("FROM scratch\n")
            incoming = os.path.join(temp, "incoming-run.json")
            source = new_direct_manifest("safe_slug", binary, None, "host.test:31337")
            source["custom_ingest_field"] = {"keep": True}
            write_shared_manifest(incoming, source)
            completed = subprocess.run([os.path.join(BIN, "newchal"), "safe_slug", binary,
                                        "", "host.test:31337", "--run", incoming],
                                       env=dict(os.environ, CTF_HOME=temp), stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True, timeout=10)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            output = os.path.join(temp, "solve", "safe_slug", "run.json")
            with open(output) as f: materialized = json.load(f)
            self.assertEqual(materialized["run_id"], source["run_id"])
            with open(os.path.join(temp, "solve", "safe_slug", "exploit.py"), encoding="utf-8") as f:
                exploit = f.read()
            self.assertIn("remote('host.test', 31337)", exploit)
            self.assertNotIn("remote(HOST, PORT)", exploit)
            self.assertEqual(materialized["manifest_owner"],
                             {"kind": "solve", "path": "solve/safe_slug/run.json"})
            self.assertTrue(materialized["custom_ingest_field"]["keep"])
            self.assertEqual([item["role"] for item in materialized["inputs"]], ["binary"])
            self.assertTrue(os.path.isfile(os.path.join(temp, "solve", "safe_slug", "Dockerfile")))

    def test_slug_and_symlink_escape_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            self.make_home(temp)
            binary = os.path.join(temp, "binary")
            with open(binary, "wb") as f: f.write(b"fixture")
            invalid = subprocess.run([os.path.join(BIN, "newchal"), "../escape", binary],
                                     env=dict(os.environ, CTF_HOME=temp), stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
            self.assertEqual(invalid.returncode, 2)
            outside = os.path.join(temp, "outside"); os.makedirs(outside)
            os.symlink(outside, os.path.join(temp, "solve", "safe"))
            escaped = subprocess.run([os.path.join(BIN, "newchal"), "safe", binary],
                                     env=dict(os.environ, CTF_HOME=temp), stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
            self.assertEqual(escaped.returncode, 5)
            self.assertEqual(os.listdir(outside), [])

    def test_invalid_incoming_manifest_fails_before_scaffold_write(self):
        with tempfile.TemporaryDirectory() as temp:
            self.make_home(temp)
            binary = os.path.join(temp, "binary")
            with open(binary, "wb") as f: f.write(b"fixture")
            invalid = os.path.join(temp, "run.json")
            with open(invalid, "w") as f: f.write('{"schema":"rat.run/v1"}\n')
            completed = subprocess.run([os.path.join(BIN, "newchal"), "safe", binary,
                                        "--run", invalid], env=dict(os.environ, CTF_HOME=temp),
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(completed.returncode, 2)
            self.assertFalse(os.path.exists(os.path.join(temp, "solve", "safe")))

    def test_invalid_remote_fails_before_scaffold_write(self):
        with tempfile.TemporaryDirectory() as temp:
            self.make_home(temp)
            binary = os.path.join(temp, "binary")
            with open(binary, "wb") as f: f.write(b"fixture")
            for remote in ("host-without-port", "host:0", "host:65536", "host:not-a-port"):
                completed = subprocess.run(
                    [os.path.join(BIN, "newchal"), "safe", binary, "", remote],
                    env=dict(os.environ, CTF_HOME=temp), stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True,
                )
                self.assertEqual(completed.returncode, 2, remote)
                self.assertFalse(os.path.exists(os.path.join(temp, "solve", "safe")), remote)

    def test_different_run_identity_does_not_overwrite_existing_solve(self):
        with tempfile.TemporaryDirectory() as temp:
            self.make_home(temp)
            old_binary = os.path.join(temp, "old.bin")
            new_binary = os.path.join(temp, "new.bin")
            with open(old_binary, "wb") as f: f.write(b"old")
            with open(new_binary, "wb") as f: f.write(b"new")
            destination = os.path.join(temp, "solve", "safe"); os.makedirs(destination)
            existing = new_direct_manifest("safe", old_binary, None, None)
            write_shared_manifest(os.path.join(destination, "run.json"), existing)
            incoming = new_direct_manifest("safe", new_binary, None, None)
            source = os.path.join(temp, "incoming.json"); write_shared_manifest(source, incoming)
            completed = subprocess.run([os.path.join(BIN, "newchal"), "safe", new_binary,
                                        "--run", source], env=dict(os.environ, CTF_HOME=temp),
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(completed.returncode, 5)
            self.assertFalse(os.path.exists(os.path.join(destination, "new.bin")))
            with open(os.path.join(destination, "run.json")) as f: preserved = json.load(f)
            self.assertEqual(preserved["run_id"], existing["run_id"])


class SelftestExitTests(unittest.TestCase):
    def test_forced_failure_is_nonzero_and_reported(self):
        root = os.path.abspath(os.path.join(BIN, ".."))
        env = dict(os.environ, CTF_HOME=root, PKSELFTEST_FORCE_FAIL="1",
                   PATH=BIN + os.pathsep + os.environ.get("PATH", ""))
        completed = subprocess.run([os.path.join(BIN, "pkselftest"), "--format", "json"],
                                   env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, timeout=30)
        payload = json.loads(completed.stdout.splitlines()[0])
        self.assertNotEqual(completed.returncode, 0)
        self.assertGreaterEqual(payload["fail"], 1)


class PrimitiveGateTests(unittest.TestCase):
    def run_state(self, state_path, *args):
        return subprocess.run([os.path.join(BIN, "state"), *args],
                              env=dict(os.environ, STATE_PATH=state_path),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_pass_requires_valid_status_and_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            state_path = os.path.join(temp, "STATE.jsonl")
            self.assertNotEqual(self.run_state(state_path, "primitive", "rip", "maybe", "x").returncode, 0)
            self.assertNotEqual(self.run_state(state_path, "primitive", "rip", "pass").returncode, 0)
            self.assertEqual(self.run_state(state_path, "hypothesis", "saved RIP control").returncode, 0)
            passed = self.run_state(state_path, "primitive", "rip", "pass",
                                    "core:rip=0x41414141 marker=SELF")
            self.assertEqual(passed.returncode, 0, passed.stderr)
            with open(state_path) as f: events = [json.loads(line) for line in f]
            self.assertEqual(events[-1]["status"], "pass")
            self.assertTrue(events[-1]["evidence"])


class GuardExitTests(unittest.TestCase):
    def test_policy_refusal_uses_common_exit_five(self):
        with tempfile.TemporaryDirectory() as temp:
            env = dict(os.environ, CTF_HOME=temp)
            missing = subprocess.run([os.path.join(BIN, "ctfguard"), "check-target", "host", "1"],
                                     env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(missing.returncode, 5)
            started = subprocess.run([os.path.join(BIN, "ctfguard"), "begin", "one", "good:1"],
                                     env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(started.returncode, 0)
            rejected = subprocess.run([os.path.join(BIN, "ctfguard"), "check-target", "bad", "1"],
                                      env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(rejected.returncode, 5)


if __name__ == "__main__":
    unittest.main()
