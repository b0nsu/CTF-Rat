import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"bin"))
from ratlib.artifact import get
from ratlib.state_v2 import Stream


class AdapterStoreRootTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("gdb"),"requires Linux GDB")
    def test_reported_gdb_info_files_capture_is_direct_in_active_state_store(self):
        from tests.test_kernel_workflow import kernel_elf
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/".rat").mkdir()
            binary=root/"vmlinux"; kernel_elf(binary)
            command=[str(ROOT/"bin/rat-adapt"),"--root",".rat","--input",str(binary),
                     "--direct-subject",str(binary),"--fresh","gdbq",str(binary),"info files"]
            run=subprocess.run(command,cwd=d,text=True,capture_output=True,timeout=20)
            self.assertEqual(run.returncode,0,run.stderr)
            doc=json.loads(run.stdout)
            self.assertEqual(doc["exit"]["code"],0,doc)
            digest=doc["extensions"]["envelope_digest"]
            stream=Stream(d)
            stream.append("observation.recorded",{"observation_id":"kernel-info-files","kind":"pwn.kernel.identity",
                          "quality":{"level":"heuristic"},"validity":{"state":"active"},"evidence":[digest]})
            self.assertEqual(stream.view()["observations"]["kernel-info-files"]["quality"]["level"],"direct")

    def test_challenge_root_rejected_before_execution_correct_store_resolves_state(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/".rat").mkdir()
            command=[str(ROOT/"bin/rat-adapt"),"--root",".","revq","selftest"]
            bad=subprocess.run(command,cwd=d,text=True,capture_output=True,timeout=20)
            self.assertEqual(bad.returncode,2,bad.stderr)
            self.assertIn("--root "+str(root.resolve()/".rat"),bad.stderr)
            self.assertFalse((root/"objects").exists())
            command[2]=".rat"
            good=subprocess.run(command,cwd=d,text=True,capture_output=True,timeout=20)
            self.assertEqual(good.returncode,0,good.stderr)
            digest=json.loads(good.stdout)["extensions"]["envelope_digest"]
            self.assertTrue(get(digest,root=Stream(d).root))
            stream=Stream(d)
            stream.append("observation.recorded",{"observation_id":"adapter-result","kind":"test.adapter",
                          "quality":{"level":"heuristic"},"validity":{"state":"active"},"evidence":[digest]})
            self.assertEqual(stream.view()["observations"]["adapter-result"]["quality"]["level"],"derived")


if __name__=="__main__":
    unittest.main()
