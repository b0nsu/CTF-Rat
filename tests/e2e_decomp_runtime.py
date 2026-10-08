"""Run a tiny real binary through the Ghidra headless decomp path.

The temporary timeout shim supplies GNU timeout's small command contract on
macOS hosts without coreutils; the analysis itself still runs in Ghidra.
"""
import os
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix="rat-decomp-e2e-") as directory:
        root = pathlib.Path(directory)
        source = root / "tiny.c"
        binary = root / "tiny"
        source.write_text("int square(int x){return x*x;} int main(void){return square(3)-9;}\n")
        subprocess.run(["gcc", "-g", "-O0", str(source), "-o", str(binary)], check=True)
        shim_dir = root / "bin"
        shim_dir.mkdir()
        timeout = shim_dir / "timeout"
        timeout.write_text(
            "#!/usr/bin/env python3\n"
            "import subprocess,sys\n"
            "seconds=int(sys.argv[3].removesuffix('s'))\n"
            "try: sys.exit(subprocess.run(sys.argv[4:],timeout=seconds).returncode)\n"
            "except subprocess.TimeoutExpired: sys.exit(124)\n"
        )
        timeout.chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = str(shim_dir) + os.pathsep + env.get("PATH", "")
        result = subprocess.run(
            [str(ROOT / "bin" / "decomp"), "--timeout", "60", str(binary), "square"],
            env=env, capture_output=True, text=True, timeout=75,
        )
        if result.returncode or "square" not in result.stdout:
            raise RuntimeError("Ghidra decomp failed: rc=%d stdout=%s stderr=%s" % (
                result.returncode, result.stdout[-500:], result.stderr[-1000:]))
    print("real Ghidra decomp: OK")


if __name__ == "__main__":
    main()
