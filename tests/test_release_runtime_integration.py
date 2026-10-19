"""Opt-in, offline integration of libcgate with the real Docker daemon.

Run with RAT_RUN_RUNTIME_INTEGRATION=1 python3 -m unittest
tests.test_release_runtime_integration. Requires locally cached Debian and
Ubuntu images; no pull or network access is used.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
from ratlib.run_manifest import atomic_write, new_direct, read, sha256_file


@unittest.skipUnless(os.environ.get("RAT_RUN_RUNTIME_INTEGRATION") == "1",
                     "real Docker integration is opt-in")
class ReleaseRuntimeIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="ctf-rat-runtime-check-")
        self.root = Path(self.scratch.name)
        unique = uuid.uuid4().hex[:12]
        self.tags = ["ctf-rat-runtime-check:%s-final" % unique,
                     "ctf-rat-runtime-check:%s-missing-loader" % unique]
        self.unique = unique

    def tearDown(self):
        for tag in self.tags:
            subprocess.run(["docker", "image", "rm", tag], capture_output=True,
                           text=True, timeout=120)
        self.scratch.cleanup()

    def run_command(self, argv, **kwargs):
        result = subprocess.run(argv, capture_output=True, text=True,
                                timeout=120, **kwargs)
        self.assertEqual(result.returncode, 0,
                         "%r failed: %s" % (argv[:4], result.stderr[-600:]))
        return result.stdout.strip()

    def test_final_image_extraction_and_missing_loader_rollback(self):
        builder = os.environ.get("RAT_INTEGRATION_BUILDER_IMAGE", "debian:stable-slim")
        final = os.environ.get("RAT_INTEGRATION_FINAL_IMAGE", "ubuntu:22.04")
        for image in (builder, final):
            self.run_command(["docker", "image", "inspect", "--format", "{{.Id}}", image])
        binary = self.root / "chall"
        shutil.copy2("/bin/true", binary)
        atomic_write(str(self.root / "run.json"),
                     new_direct("runtime-check", str(binary), None, None))
        dockerfile = ("FROM %s AS builder\nFROM %s\nLABEL ctf.rat.integration=%s\n" %
                      (builder, final, self.unique))
        self.run_command(["docker", "build", "--pull=false", "--network=none",
                          "-t", self.tags[0], "-f", "-", str(self.root)],
                         input=dockerfile)
        image_id = self.run_command(["docker", "image", "inspect", "--format",
                                     "{{.Id}}", self.tags[0]])
        env = {**os.environ, "CTF_HOME": str(ROOT)}
        self.run_command([str(ROOT / "bin" / "libcgate"), "--extract", "--image",
                          self.tags[0], str(self.root)], env=env)
        manifest = read(str(self.root / "run.json"))
        inputs = {item["role"]: item for item in manifest["inputs"]
                  if item["role"] in {"libc", "loader"}}
        self.assertEqual(set(inputs), {"libc", "loader"})
        for role, name in (("libc", "libc_docker.so.6"), ("loader", "ld_docker.so")):
            path = self.root / name
            self.assertTrue(path.is_file() and not path.is_symlink())
            self.assertEqual(inputs[role]["sha256"], sha256_file(str(path)))
            self.assertEqual(inputs[role]["provenance"]["image_id"], image_id)
        final_libc_sha = sha256_file(str(self.root / "libc_docker.so.6"))
        builder_container = self.run_command(["docker", "create", "--", builder])
        try:
            builder_libc = self.root / "builder-libc.so.6"
            self.run_command(["docker", "cp", "-L",
                              "%s:/usr/lib/x86_64-linux-gnu/libc.so.6" % builder_container,
                              str(builder_libc)])
            builder_sha = sha256_file(str(builder_libc))
        finally:
            self.run_command(["docker", "rm", "-f", "--", builder_container])
        self.assertNotEqual(final_libc_sha, builder_sha,
                            "test bases must have distinct libc contents")
        before_manifest = (self.root / "run.json").read_bytes()
        before_libc = (self.root / "libc_docker.so.6").read_bytes()
        before_loader = (self.root / "ld_docker.so").read_bytes()
        shutil.copy2(self.root / "libc_docker.so.6", self.root / "libc-seed.so")
        missing_loader = ("FROM scratch\n"
                          "COPY libc-seed.so /usr/lib/x86_64-linux-gnu/libc.so.6\n"
                          "LABEL ctf.rat.integration=%s-missing\n"
                          "CMD [\"/nonexistent\"]\n" % self.unique)
        self.run_command(["docker", "build", "--pull=false", "--network=none",
                          "-t", self.tags[1], "-f", "-", str(self.root)],
                         input=missing_loader)
        failed = subprocess.run([str(ROOT / "bin" / "libcgate"), "--extract", "--image",
                                 self.tags[1], str(self.root)], env=env,
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(failed.returncode, 2, failed.stdout + failed.stderr)
        self.assertIn("could not extract the loader", failed.stdout)
        self.assertEqual((self.root / "run.json").read_bytes(), before_manifest)
        self.assertEqual((self.root / "libc_docker.so.6").read_bytes(), before_libc)
        self.assertEqual((self.root / "ld_docker.so").read_bytes(), before_loader)
        for tag in self.tags:
            self.assertEqual(self.run_command(["docker", "ps", "-a", "--filter",
                                               "ancestor=" + tag, "--format", "{{.ID}}"]), "")
        print("real Docker final-image provenance and rollback: PASS",
              "image_id=" + image_id, "final_libc=" + final_libc_sha,
              "builder_libc=" + builder_sha)

    @unittest.skipUnless(sys.platform.startswith("linux"), "bwrap integration requires Linux")
    def test_mode_b_inside_networkless_container(self):
        # This host forbids unprivileged uid maps. Grant only the namespace and
        # mount permissions needed inside a disposable, networkless container;
        # no home or credential paths are mounted. The repository is read-only.
        script = textwrap.dedent('''
            import importlib.machinery
            import importlib.util
            import os
            from pathlib import Path
            import subprocess
            import tempfile
            import time

            loader = importlib.machinery.SourceFileLoader("ratbench_runtime_check", "/work/bin/ratbench")
            spec = importlib.util.spec_from_loader(loader.name, loader)
            ratbench = importlib.util.module_from_spec(spec)
            loader.exec_module(ratbench)
            ratbench._have_angr = lambda: False
            with tempfile.TemporaryDirectory(prefix="ratbench-runtime-check-") as scratch:
                root = Path(scratch)
                kit = root / "kit"
                kit.mkdir()
                outside = root / "outside-sentinel"
                outside.write_text("not visible to agent")
                os.environ["DUMMY_API_TOKEN"] = "fixture-secret"
                env = ratbench._agent_environment(str(kit))
                assert "DUMMY_API_TOKEN" not in env
                command = (f"test ! -e /work/AGENTS.md && test ! -e {outside} && "
                           f"test -d {kit} && test -z \\"$DUMMY_API_TOKEN\\" && "
                           f"test \\"$HOME\\" = {kit} && printf isolated")
                probe = ratbench._run_agent(command, cwd=str(kit), env=env, timeout=5)
                assert probe.returncode == 0, (probe.returncode, probe.stdout)
                assert probe.stdout == b"isolated", probe.stdout
                marker = kit / "late"
                detached = f"setsid /bin/sh -c 'sleep 1; touch {marker}' </dev/null >/dev/null 2>&1 & wait"
                for traced in (False, True):
                    trace = root / "exec.trace" if traced else None
                    try:
                        ratbench._run_agent(detached, cwd=str(kit), env=env,
                                            timeout=0.4 if traced else 0.1,
                                            trace_path=str(trace) if trace else None)
                    except subprocess.TimeoutExpired:
                        pass
                    else:
                        raise AssertionError("Mode B command did not time out")
                    time.sleep(1.25)
                    assert not marker.exists(), "detached child survived timeout"
                    if trace:
                        observed = trace.read_text()
                        assert "execve" in observed and "bwrap" in observed
            print("real bwrap Mode B isolation and traced/untraced timeout: PASS")
        ''')
        command = ["docker", "run", "--rm", "-i", "--network", "none", "--pull", "never",
                   "--cap-add", "SYS_ADMIN", "--security-opt", "seccomp=unconfined",
                   "--security-opt", "apparmor=unconfined"]
        for path in ("/usr", "/lib", "/lib64"):
            if os.path.exists(path):
                command += ["-v", path + ":" + path + ":ro"]
        command += ["-v", str(ROOT) + ":/work:ro", "-w", "/work",
                    "-e", "CTF_HOME=/work", "-e", "PYTHONPATH=/work/bin",
                    "debian:stable-slim", "/usr/bin/python3", "-"]
        output = self.run_command(command, input=script)
        self.assertIn("real bwrap Mode B isolation and traced/untraced timeout: PASS", output)


if __name__ == "__main__":
    unittest.main()
