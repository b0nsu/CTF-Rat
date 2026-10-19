"""WASI proc_exit and real trap behavior under the bundled Wasmtime runtime."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv-angr" / "bin" / "python"


def _wasmtime_available():
    """True only when .venv-angr's python can actually import wasmtime.

    The interpreter file existing is not enough: a .venv-angr without the optional
    SETUP §9 `wasmtime` package would otherwise FAIL (not skip) at wat2wasm, which
    misreports a missing optional dependency as a real test failure."""
    if not PYTHON.is_file():
        return False
    try:
        probe = subprocess.run(
            [str(PYTHON), "-c", "import wasmtime"],
            capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.returncode == 0


@unittest.skipUnless(_wasmtime_available(),
                     "optional Wasmtime package not installed in .venv-angr (SETUP §9)")
class WasmExitTests(unittest.TestCase):
    def test_exit_zero_nonzero_and_trap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stdin = root / "stdin"
            stdin.write_bytes(b"")
            for name, ending, expected_status in (
                    ("zero", "(call $exit (i32.const 0))", "executed"),
                    ("nonzero", "(call $exit (i32.const 7))", "error"),
                    ("trap", "unreachable", "error")):
                wat = f'''(module
                  (import "wasi_snapshot_preview1" "fd_write"
                    (func $write (param i32 i32 i32 i32) (result i32)))
                  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
                  (memory 1) (export "memory" (memory 0))
                  (data (i32.const 0) "\\08\\00\\00\\00\\05\\00\\00\\00")
                  (data (i32.const 8) "HELLO")
                  (func (export "_start")
                    (drop (call $write (i32.const 1) (i32.const 0)
                                       (i32.const 1) (i32.const 32)))
                    {ending}))'''
                module = root / (name + ".wasm")
                (root / (name + ".wat")).write_text(wat)
                built = subprocess.run(
                    [str(PYTHON), "-c",
                     "import wasmtime,sys; open(sys.argv[2],'wb').write(wasmtime.wat2wasm(open(sys.argv[1]).read()))",
                     str(root / (name + ".wat")), str(module)],
                    capture_output=True, text=True)
                self.assertEqual(built.returncode, 0, built.stderr)
                result = subprocess.run(
                    [str(PYTHON), str(ROOT / "bin" / "rat-wasm"), "_execute",
                     str(module), str(stdin), "-"], capture_output=True, text=True)
                payload = json.loads(result.stdout)
                self.assertEqual(payload["runtime_status"], expected_status)
                if name == "zero":
                    self.assertEqual(result.returncode, 0)
                    self.assertEqual(payload["stdout"], "HELLO")
                else:
                    self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
