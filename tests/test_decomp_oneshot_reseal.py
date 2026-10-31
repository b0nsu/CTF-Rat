import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "bin"))
from ratlib.decomp_cache import validate, write_meta


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

    def test_failed_one_shot_never_mutates_previous_sealed_generation(self):
        for mode in ("nonzero", "timeout", "bad-instruction", "seal-failure"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root:
                binary = os.path.join(root, "chall")
                shutil.copy2("/bin/true", binary)
                ghidra = os.path.join(root, "ghidra")
                os.makedirs(os.path.join(ghidra, "support"))
                os.makedirs(os.path.join(ghidra, "Ghidra"))
                with open(os.path.join(ghidra, "Ghidra", "application.properties"), "w") as fh:
                    fh.write("application.version=fake-oneshot\n")
                analyzer = os.path.join(ghidra, "support", "analyzeHeadless")
                with open(analyzer, "w") as fh:
                    fh.write("""#!/usr/bin/env bash
set -euo pipefail
args=("$@")
for ((i=0;i<${#args[@]};i++)); do
  if [ "${args[$i]}" = "DecompOne.java" ]; then
    cache="${args[$((i+1))]}"
    printf '%s\\n' "$DECOMP_TEST_MODE" > "$DECOMP_TEST_MARKER"
    printf '00001234\\tFUN_00001234\\t8\\n' >> "$cache/_index.txt"
    printf 'int FUN_00001234(void) { return 7; }\\n' > "$cache/FUN_00001234.c"
    printf 'damaged\\n' > "$cache/00001000_main.c"
    case "$DECOMP_TEST_MODE" in
      nonzero) exit 9 ;;
      timeout) sleep 4 ;;
      bad-instruction) echo 'Bad instruction' >> "$cache/FUN_00001234.c" ;;
      seal-failure) echo '{"discovered":2,"exported":1,"failed":["FUN_00001234"]}' > "$cache/.rat-decomp-status.json" ;;
    esac
    exit 0
  fi
done
exit 88
""")
                os.chmod(analyzer, 0o755)
                cache = binary + ".decomp"
                os.makedirs(cache)
                with open(os.path.join(cache, "_index.txt"), "w") as fh:
                    fh.write("00001000\tmain\t10\t00001000_main\n")
                original = b"int main(void) { return 0; }\n"
                with open(os.path.join(cache, "00001000_main.c"), "wb") as fh:
                    fh.write(original)
                # /bin/true is PIE on common CI hosts; its image base is needed
                # to resolve a numeric request into the one-shot miss branch.
                Path(cache, ".rat-decomp-status.json").write_text(
                    '{"image_base":"0","discovered":1,"exported":1,"failed":[]}')
                write_meta(cache, binary, ghidra, SCRIPTS, "complete")
                prior_meta = Path(cache, ".rat-cache.json").read_bytes()
                marker = Path(root, "analyzer-ran.txt")
                env = dict(os.environ, CTF_HOME=ROOT, GHIDRA_HOME=ghidra,
                           DECOMP_TEST_MODE=mode, DECOMP_TEST_MARKER=str(marker))
                attempted = subprocess.run([DECOMP, "--timeout", "1", binary, "1234"],
                                           env=env, capture_output=True, text=True, timeout=15)
                self.assertTrue(marker.exists(), attempted.stderr)
                self.assertEqual(marker.read_text().strip(), mode)
                self.assertEqual(attempted.returncode, 0, attempted.stderr)
                self.assertIn("RAT_STATUS=fallback", attempted.stderr)
                self.assertNotIn("return 7", attempted.stdout)
                self.assertEqual(validate(cache, binary, ghidra, SCRIPTS), (True, "hit"))
                self.assertEqual(Path(cache, ".rat-cache.json").read_bytes(), prior_meta)
                self.assertEqual(Path(cache, "00001000_main.c").read_bytes(), original)
                self.assertNotIn("FUN_00001234", Path(cache, "_index.txt").read_text())
                hit = subprocess.run([DECOMP, binary, "main"], env=env,
                                     capture_output=True, text=True, timeout=15)
                self.assertEqual(hit.returncode, 0, hit.stderr)
                self.assertIn("return 0", hit.stdout)
                self.assertNotIn("전체 분석", hit.stderr)

if __name__ == "__main__":
    unittest.main()
