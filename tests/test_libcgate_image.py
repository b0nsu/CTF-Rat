"""Final-image identity and symlink extraction regressions."""
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
LIBCGATE = runpy.run_path(str(ROOT / "bin" / "libcgate"))
from ratlib.run_manifest import atomic_write, new_direct, read


class LibcgateImageTests(unittest.TestCase):
    def test_explicit_final_image_and_follow_links(self):
        extract = LIBCGATE["extract_from_image"]
        image_id = "sha256:" + "b" * 64
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            if argv[1:3] == ["image", "inspect"]:
                return subprocess.CompletedProcess(argv, 0, image_id + "\n", "")
            if argv[1] == "create":
                return subprocess.CompletedProcess(argv, 0, "container-id\n", "")
            if argv[1] == "cp":
                self.assertEqual(argv[2], "-L")
                target = Path(argv[-1])
                if "libc.so.6" in argv[-2] and not target.name.startswith("ld_"):
                    target.write_bytes(b"GNU C Library stable release version 2.35\0")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if "ld-linux" in argv[-2]:
                    target.write_bytes(b"loader")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                return subprocess.CompletedProcess(argv, 1, "", "not found")
            return subprocess.CompletedProcess(argv, 0, "", "")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "chall"
            binary.write_bytes(b"fixture")
            atomic_write(str(root / "run.json"),
                         new_direct("fixture", str(binary), None, None))
            (root / "Dockerfile").write_text(
                "FROM first:stage AS builder\nFROM final:stage\nRUN apt-get upgrade -y\n")
            with patch.dict(os.environ, {}, clear=False), patch.object(
                    LIBCGATE["shutil"], "which", return_value="/fake/docker"), patch.object(
                    LIBCGATE["subprocess"], "run", side_effect=fake_run):
                text, rc = extract(str(root), image="challenge:built")
            self.assertEqual(rc, 0, text)
            self.assertIn(image_id, text)
            creates = [c for c in calls if c[1] == "create"]
            self.assertEqual(creates[0][-1], image_id)
            self.assertNotIn("first:stage", repr(calls))
            self.assertTrue((root / "libc_docker.so.6").is_file())
            self.assertTrue((root / "ld_docker.so").is_file())
            recorded = {item["role"]: item for item in read(str(root / "run.json"))["inputs"]
                        if item["role"] in {"libc", "loader"}}
            self.assertEqual(set(recorded), {"libc", "loader"})
            self.assertEqual(recorded["libc"]["provenance"]["image_id"], image_id)
            self.assertEqual(recorded["loader"]["provenance"]["image_id"], image_id)
            self.assertEqual(recorded["libc"]["sha256"],
                             "sha256:" + LIBCGATE["sha256"](root / "libc_docker.so.6"))

    def test_missing_or_ambiguous_identity_fails_closed(self):
        extract = LIBCGATE["extract_from_image"]
        with tempfile.TemporaryDirectory() as temporary:
            text, rc = extract(temporary)
            self.assertEqual(rc, 2)
            self.assertIn("--image", text)
            calls = []

            def ambiguous(argv, **kwargs):
                calls.append(argv)
                return subprocess.CompletedProcess(argv, 0, "sha256:short\n", "")

            with patch.object(LIBCGATE["shutil"], "which", return_value="/fake/docker"), patch.object(
                    LIBCGATE["subprocess"], "run", side_effect=ambiguous):
                text, rc = extract(temporary, image="tag:mutable")
            self.assertEqual(rc, 2)
            self.assertIn("ambiguous", text)
            self.assertFalse(any(c[1] == "create" for c in calls))

    def test_failed_second_extraction_preserves_previous_files_and_manifest(self):
        extract = LIBCGATE["extract_from_image"]
        image_id = "sha256:" + "c" * 64

        def fake_run(argv, **kwargs):
            if argv[1:3] == ["image", "inspect"]:
                return subprocess.CompletedProcess(argv, 0, image_id + "\n", "")
            if argv[1] == "create":
                return subprocess.CompletedProcess(argv, 0, "container-id\n", "")
            if argv[1] == "cp" and "libc.so.6" in argv[-2]:
                Path(argv[-1]).write_bytes(b"new libc")
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 1, "", "missing loader")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "chall"
            binary.write_bytes(b"fixture")
            (root / "libc_docker.so.6").write_bytes(b"old libc")
            (root / "ld_docker.so").write_bytes(b"old loader")
            atomic_write(str(root / "run.json"),
                         new_direct("fixture", str(binary), None, None))
            previous_manifest = (root / "run.json").read_bytes()
            with patch.object(LIBCGATE["shutil"], "which", return_value="/fake/docker"), \
                 patch.object(LIBCGATE["subprocess"], "run", side_effect=fake_run):
                message, rc = extract(str(root), image="challenge:new")
            self.assertEqual(rc, 2, message)
            self.assertEqual((root / "libc_docker.so.6").read_bytes(), b"old libc")
            self.assertEqual((root / "ld_docker.so").read_bytes(), b"old loader")
            self.assertEqual((root / "run.json").read_bytes(), previous_manifest)

    def test_manifest_write_failure_rolls_back_both_files(self):
        extract = LIBCGATE["extract_from_image"]
        image_id = "sha256:" + "d" * 64

        def fake_run(argv, **kwargs):
            if argv[1:3] == ["image", "inspect"]:
                return subprocess.CompletedProcess(argv, 0, image_id + "\n", "")
            if argv[1] == "create":
                return subprocess.CompletedProcess(argv, 0, "container-id\n", "")
            if argv[1] == "cp":
                Path(argv[-1]).write_bytes(b"new runtime")
            return subprocess.CompletedProcess(argv, 0, "", "")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "chall"
            binary.write_bytes(b"fixture")
            (root / "libc_docker.so.6").write_bytes(b"old libc")
            (root / "ld_docker.so").write_bytes(b"old loader")
            atomic_write(str(root / "run.json"),
                         new_direct("fixture", str(binary), None, None))
            previous_manifest = (root / "run.json").read_bytes()
            with patch.object(LIBCGATE["shutil"], "which", return_value="/fake/docker"), \
                 patch.object(LIBCGATE["subprocess"], "run", side_effect=fake_run), \
                 patch("ratlib.run_manifest.atomic_write", side_effect=OSError("write failed")):
                message, rc = extract(str(root), image="challenge:new")
            self.assertEqual(rc, 2, message)
            self.assertIn("rollback complete", message)
            self.assertEqual((root / "libc_docker.so.6").read_bytes(), b"old libc")
            self.assertEqual((root / "ld_docker.so").read_bytes(), b"old loader")
            self.assertEqual((root / "run.json").read_bytes(), previous_manifest)

    def test_copy_retries_after_broken_or_host_link(self):
        copy_first = LIBCGATE["_docker_cp_first"]
        with tempfile.TemporaryDirectory() as temporary:
            dest = Path(temporary) / "libc"
            external = Path(temporary) / "host"
            external.write_bytes(b"host secret fixture")
            calls = []

            def copy(argv, **kwargs):
                calls.append(argv)
                if len(calls) == 1:
                    dest.symlink_to("/missing/container/target")
                elif len(calls) == 2:
                    dest.symlink_to(external)
                else:
                    dest.write_bytes(b"container libc fixture")
                return subprocess.CompletedProcess(argv, 0, "", "")

            with patch.object(LIBCGATE["shutil"], "which", return_value="/fake/docker"), \
                 patch.object(LIBCGATE["subprocess"], "run", side_effect=copy):
                found = copy_first("cid", ["/broken", "/host-link", "/real"], str(dest))
            self.assertEqual(found, "/real")
            self.assertEqual(dest.read_bytes(), b"container libc fixture")
            self.assertEqual(external.read_bytes(), b"host secret fixture")


if __name__ == "__main__":
    unittest.main()
