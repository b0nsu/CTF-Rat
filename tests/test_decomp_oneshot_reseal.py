import os
import shutil
import subprocess
import tempfile
import unittest

from ratlib.decomp_cache import validate, write_meta


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DECOMP = os.path.join(ROOT, "bin", "decomp")
SCRIPTS = os.path.join(ROOT, "bin", "ghidra_scripts")


@unittest.skipUnless(shutil.which("timeout") or shutil.which("gtimeout"),
                     "decomp requires timeout/gtimeout")
class DecompOneShotResealTests(unittest.TestCase):
    def test_successful_one_shot_mutation_is_resealed_before_return(self):
        with tempfile.TemporaryDirectory() as root:
            binary = os.path.join(root, "chall")
            with open(binary, "wb") as fh:
                fh.write(b"fixture-binary")

            ghidra = os.path.join(root, "ghidra")
            os.makedirs(os.path.join(ghidra, "support"))
            os.makedirs(os.path.join(ghidra, "Ghidra"))
            with open(os.path.join(ghidra, "Ghidra", "application.properties"), "w", encoding="utf-8") as fh:
                fh.write("application.version=fake-oneshot\n")

            analyzer = os.path.join(ghidra, "support", "analyzeHeadless")
            with open(analyzer, "w", encoding="utf-8") as fh:
                fh.write("""#!/usr/bin/env bash
set -euo pipefail
args=(\"$@\")
cache=\"\"
addr=\"\"
for ((i=0; i<${#args[@]}; i++)); do
  if [ \"${args[$i]}\" = \"DecompOne.java\" ]; then
    cache=\"${args[$((i+1))]}\"
    addr=\"${args[$((i+2))]}\"
    break
  fi
done
[ -n \"$cache\" ] && [ -n \"$addr\" ]
printf 'int FUN_00001234(void) { return 0; }\\n' > \"$cache/FUN_00001234.c\"
printf '00001234\\tFUN_00001234\\t8\\n' >> \"$cache/_index.txt\"
""")
            os.chmod(analyzer, 0o755)

            cache = binary + ".decomp"
            os.makedirs(cache)
            with open(os.path.join(cache, "_index.txt"), "w", encoding="utf-8") as fh:
                fh.write("00001000\tmain\t10\t00001000_main\n")
            with open(os.path.join(cache, "00001000_main.c"), "w", encoding="utf-8") as fh:
                fh.write("int main(void) { return 0; }\n")
            write_meta(cache, binary, ghidra, SCRIPTS, "complete")
            self.assertEqual(validate(cache, binary, ghidra, SCRIPTS), (True, "hit"))

            completed = subprocess.run(
                [DECOMP, binary, "1234"],
                env=dict(os.environ, CTF_HOME=ROOT, GHIDRA_HOME=ghidra),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=15,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("FUN_00001234", completed.stdout)
            self.assertEqual(validate(cache, binary, ghidra, SCRIPTS), (True, "hit"))


if __name__ == "__main__":
    unittest.main()
