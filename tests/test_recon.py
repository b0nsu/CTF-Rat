import pathlib
import os
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL = ROOT / "bin" / "recon"


class ReconTests(unittest.TestCase):
    def test_pe_with_shell_metacharacters_in_path_is_routed_to_rev(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fixture = root / "sample 'quoted name'.exe"
            # Minimal PE32 image: DOS header, PE offset, signature, and an
            # i386 COFF header.  The pwn stub must never parse this fixture.
            image = bytearray(256)
            image[:2] = b"MZ"
            image[0x3C:0x40] = (0x80).to_bytes(4, "little")
            image[0x80:0x84] = b"PE\0\0"
            image[0x84:0x86] = (0x14C).to_bytes(2, "little")
            fixture.write_bytes(image)
            (root / "pwn.py").write_text(
                "class _Context: log_level = None\n"
                "context = _Context()\n"
                "class ELF:\n    def __init__(self, *args, **kwargs): raise AssertionError('ELF parser called')\n",
                encoding="utf-8",
            )
            file_tool = root / "file"
            file_tool.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "assert sys.argv[1:] == ['--', %r]\n"
                "print(sys.argv[2] + ': PE32 executable (console) Intel 80386')\n" % str(fixture),
                encoding="utf-8",
            )
            file_tool.chmod(0o755)
            env = dict(
                os.environ,
                PATH=str(root) + os.pathsep + os.environ.get("PATH", ""),
                PYTHONPATH=str(root) + os.pathsep + str(ROOT / "bin"),
            )
            result = subprocess.run(
                [str(TOOL), str(fixture)], cwd=ROOT, env=env, text=True, capture_output=True
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PE/Windows", result.stdout)


if __name__ == "__main__":
    unittest.main()
