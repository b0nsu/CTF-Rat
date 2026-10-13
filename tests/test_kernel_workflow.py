"""Synthetic format fixtures exercise the reported CLI paths without booting."""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin"
sys.path.insert(0, str(BIN))
from ratlib.kernel_identity import inspect
from ratlib.route import route
from ratlib.schema import validate


def boot_image(path):
    data = bytearray(4096)
    data[0x1fe:0x200] = b"\x55\xaa"
    data[0x202:0x206] = b"HdrS"
    data[0x206:0x208] = (0x20f).to_bytes(2, "little")
    data[0x211] = 1
    Path(path).write_bytes(data)


def kernel_elf(path, *, elf64=True, endian="<", kernel=True, recovered=False, low_address=False):
    """Minimal real ELF section/symbol tables, including recovered NOTYPEs."""
    init_name = ".extra" if recovered else ".init.text"
    names = ["", ".text", init_name, ".symtab", ".strtab", ".shstrtab"]
    shstrings = b"\0" + b"".join(n.encode() + b"\0" for n in names[1:])
    symbols = ["start_kernel", "copy_process", "linux_banner"] if kernel else ["main"]
    strings = b"\0" + b"".join(n.encode() + b"\0" for n in symbols)
    symfmt = endian + ("IBBHQQ" if elf64 else "IIIBBH")
    symsize = struct.calcsize(symfmt)
    symdata = bytearray(symsize)
    base = 0xffffffff81000000 if elf64 else 0xc1000000
    if low_address:
        base = 0x400000
    for i, name in enumerate(symbols):
        offset = strings.index(name.encode())
        fields = (offset, 0x10, 0, 1, base + i, 0) if elf64 else (offset, base+i, 0, 0x10, 0, 1)
        symdata.extend(struct.pack(symfmt, *fields))
    data = bytearray(64 if elf64 else 52)
    sections = [(0,0,0,0,0,0,0,0,0,0)]
    for name, stype, flags, addr, payload, link, entsize in [
        (".text",1,6,base,b"\xc3"*16,0,0),
        (init_name,1,6,base+16,b"\xc3",0,0),
        (".symtab",2,0,0,bytes(symdata),4,symsize),
        (".strtab",3,0,0,strings,0,0),
        (".shstrtab",3,0,0,shstrings,0,0),
    ]:
        sections.append((shstrings.index(name.encode()),stype,flags,addr,len(data),len(payload),link,0,1,entsize))
        data.extend(payload)
    shoff = len(data)
    shfmt = endian + ("IIQQQQIIQQ" if elf64 else "IIIIIIIIII")
    for section in sections:
        data.extend(struct.pack(shfmt,*section))
    ident = b"\x7fELF" + bytes([2 if elf64 else 1,1 if endian=="<" else 2,1]) + b"\0"*9
    fmt = endian + ("HHIQQQIHHHHHH" if elf64 else "HHIIIIIHHHHHH")
    header = struct.pack(fmt,2,62 if elf64 else 3,1,base,0,shoff,0,len(ident)+struct.calcsize(fmt),0,0,struct.calcsize(shfmt),len(sections),5)
    data[:len(ident)+len(header)] = ident + header
    Path(path).write_bytes(data)


def load_tool(name):
    loader = importlib.machinery.SourceFileLoader("_kernel_test_"+name,str(BIN/name))
    spec = importlib.util.spec_from_loader(loader.name,loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class KernelWorkflowTests(unittest.TestCase):
    def run_tool(self, name, *args, env=None, cwd=None):
        return subprocess.run([str(BIN/name),*map(str,args)],capture_output=True,text=True,
                              env=env,cwd=cwd,timeout=30)

    def test_boot_identity_requires_header_not_filename(self):
        with tempfile.TemporaryDirectory() as d:
            image=Path(d)/"unnamed"
            boot_image(image)
            self.assertEqual(inspect(image)["kind"],"bzimage")
            for offset in (0x1fe,0x202,0x207):
                original=image.read_bytes()
                damaged=bytearray(original); damaged[offset]=0
                image.write_bytes(damaged)
                self.assertEqual(inspect(image)["kind"],"unknown")
                image.write_bytes(original)
            named=Path(d)/"bzImage"; named.write_bytes(b"ordinary data")
            self.assertEqual(inspect(named)["kind"],"unknown")

    def test_elf_identity_and_recovered_symbols_across_classes_and_endianness(self):
        with tempfile.TemporaryDirectory() as d:
            for elf64 in (False,True):
                for endian in ("<",">"):
                    with self.subTest(elf64=elf64,endian=endian):
                        image=Path(d)/"image"; kernel_elf(image,elf64=elf64,endian=endian)
                        identity=inspect(image,include_symbols=True)
                        self.assertEqual(identity["kind"],"vmlinux",identity)
                        self.assertFalse(identity["diagnostics"])
                        self.assertEqual(len(identity["functions"]),3)
                        self.assertEqual(identity["functions"][1]["symbol_type"],"notype")
                        self.assertGreater(identity["functions"][1]["addr"],0xc0000000)
            kernel_elf(image,kernel=False)
            self.assertEqual(inspect(image)["kind"],"elf")

    def test_metadata_budget_is_reported_without_kernel_identity(self):
        with tempfile.TemporaryDirectory() as d:
            image=Path(d)/"image"; kernel_elf(image)
            data=bytearray(image.read_bytes()); data[60:62]=(5000).to_bytes(2,"little")
            image.write_bytes(data)
            identity=inspect(image)
            self.assertEqual(identity["kind"],"elf")
            self.assertIn("budget",identity["diagnostics"][0])

    def test_single_text_recovered_kernel_needs_multiple_symbols_and_high_vma(self):
        with tempfile.TemporaryDirectory() as d:
            image=Path(d)/"image"
            kernel_elf(image,recovered=True)
            identity=inspect(image)
            self.assertEqual(identity["kind"],"vmlinux")
            self.assertEqual(identity["sections"],[])
            self.assertTrue(identity["high_kernel_text"])
            kernel_elf(image,recovered=True,low_address=True)
            self.assertEqual(inspect(image)["kind"],"elf")
            kernel_elf(image,recovered=True,kernel=False)
            self.assertEqual(inspect(image)["kind"],"elf")

    def test_kernel_identity_dominates_incidental_strings_preserves_other_facts(self):
        with tempfile.TemporaryDirectory() as d:
            image=Path(d)/"image"; kernel_elf(image)
            rev={"functions":[{"name":"copy_process"}],"strings":[{"val":"kvm opcode sha256"}]}
            result=route(profile={"artifact_identity":inspect(image),"imports":["gets","malloc","free"]},revq=rev)
            validate(result)
            self.assertIn("kernel",result["leads"])
            self.assertNotIn("vm",result["leads"])
            self.assertNotIn("oracle-discovery",result["leads"])
            self.assertIn("stack-overwrite",result["leads"])
            self.assertIn("heap-lifetime",result["leads"])
            self.assertIsNone(result["skill"])

    def test_revq_kernel_uses_symbols_replaces_legacy_empty_cache(self):
        mod=load_tool("revq")
        with tempfile.TemporaryDirectory() as d:
            image=Path(d)/"image"; kernel_elf(image)
            legacy={"schema":mod.SCHEMA,"sha256":mod.sha256(image),"engine":"angr",
                    "functions":[],"evasion_signal_schema":mod.EVASION_SIGNAL_SCHEMA,"evasion_signals":[]}
            Path(str(image)+".revq.json").write_text(json.dumps(legacy))
            with mock.patch.object(mod,"extract_angr",side_effect=AssertionError("whole kernel CFG")), \
                 mock.patch.object(mod,"extract_binutils",side_effect=AssertionError("unbounded external symbol dump")):
                rev=mod.load_or_extract(str(image),"angr",False)
                self.assertEqual(rev["cache_state"],"miss")
                self.assertEqual(rev["engine"],"binutils")
                self.assertEqual(len(rev["functions"]),3)
                self.assertFalse(rev["analysis_complete"])
                hit=mod.load_or_extract(str(image),"angr",False)
                self.assertEqual(hit["cache_state"],"hit")

    def test_route_cli_boot_and_kernel_have_actionable_results(self):
        with tempfile.TemporaryDirectory() as d:
            image=Path(d)/"image"
            for make, action in ((boot_image,"extract-vmlinux"),(kernel_elf,"rat query func")):
                make(image)
                result=self.run_tool("rat","route",image,"--fast","--format","json")
                self.assertEqual(result.returncode,0,result.stderr)
                card=json.loads(result.stdout); validate(card)
                self.assertIn("kernel",card["leads"])
                self.assertTrue(any(a["query"]==action for a in card["next"]))
                self.assertIsNone(card["skill"])
                self.assertNotIn("No loader",result.stderr)

    def test_func_cli_retains_high_kernel_address_and_partial_coverage(self):
        with tempfile.TemporaryDirectory() as d:
            image=Path(d)/"image"; kernel_elf(image,recovered=True)
            result=self.run_tool("rat","query","func",image,"copy_process","--fast","--format","json")
            self.assertEqual(result.returncode,0,result.stderr)
            card=json.loads(result.stdout); validate(card)
            self.assertEqual(card["status"],"partial")
            self.assertEqual(card["facts"]["function"]["addr"],0xffffffff81000001)
            self.assertEqual(card["facts"]["callees"],[])

    def test_newchal_boot_skips_recon_and_elf_execution_template(self):
        with tempfile.TemporaryDirectory() as d:
            home=Path(d)/"kit"
            (home/"bin").mkdir(parents=True); (home/"solve/_template").mkdir(parents=True)
            (home/"solve/_template/state.md").write_text("# {{NAME}} {{BIN}}\n")
            for name,body in (("ctfguard","exit 0"),("libcgate","exit 0"),("recon","echo UNEXPECTED_RECON; exit 23")):
                tool=home/"bin"/name; tool.write_text("#!/bin/sh\n"+body+"\n"); tool.chmod(0o755)
            image=Path(d)/"blob"; boot_image(image)
            result=self.run_tool("newchal","boot",image,env=dict(os.environ,CTF_HOME=str(home)))
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertNotIn("UNEXPECTED_RECON",result.stdout)
            self.assertIn("recon 생략",result.stdout)
            solve=home/"solve/boot"
            self.assertTrue((solve/"run.json").exists())
            self.assertNotIn("ELF(",(solve/"exploit.py").read_text())

    def test_decomp_kernel_cold_import_requires_explicit_full_analysis(self):
        with tempfile.TemporaryDirectory() as d:
            image=Path(d)/"kernel"; kernel_elf(image)
            ghidra=Path(d)/"ghidra"; (ghidra/"support").mkdir(parents=True)
            marker=Path(d)/"launched"
            analyzer=ghidra/"support/analyzeHeadless"
            analyzer.write_text("#!/bin/sh\ntouch '"+str(marker)+"'\nexit 1\n"); analyzer.chmod(0o755)
            fake=Path(d)/"bin"; fake.mkdir()
            timeout=fake/"timeout"; timeout.write_text('#!/bin/sh\nshift 3\nexec "$@"\n'); timeout.chmod(0o755)
            env=dict(os.environ,CTF_HOME=str(ROOT),GHIDRA_HOME=str(ghidra),
                     XDG_CONFIG_HOME=str(Path(d)/"xdg"),PATH=str(fake)+os.pathsep+os.environ["PATH"])
            result=self.run_tool("decomp",image,"copy_process",env=env)
            self.assertEqual(result.returncode,2,result.stderr)
            self.assertIn("--allow-full-analysis",result.stderr)
            self.assertFalse(marker.exists())
            self.assertFalse(Path(str(image)+".decomp").exists())
            large=Path(d)/"stripped-or-unknown"
            with large.open("wb") as out:
                out.truncate(16*1024*1024)
            result=self.run_tool("decomp",large,"copy_process",env=env)
            self.assertEqual(result.returncode,2,result.stderr)
            self.assertFalse(marker.exists())
            boot=Path(d)/"bzImage"; boot_image(boot)
            result=self.run_tool("decomp","--allow-full-analysis",boot,"copy_process",env=env)
            self.assertEqual(result.returncode,2,result.stderr)
            self.assertIn("extract-vmlinux",result.stderr)
            self.assertFalse(marker.exists())
            result=self.run_tool("decomp","--allow-full-analysis","--timeout","5",image,"copy_process",env=env)
            self.assertEqual(result.returncode,70,result.stderr)
            self.assertTrue(marker.exists())

    def test_decomp_serves_kernel_cache_but_guards_refresh_and_address_import(self):
        from ratlib.decomp_cache import write_meta
        with tempfile.TemporaryDirectory() as d:
            image=Path(d)/"kernel"; kernel_elf(image)
            ghidra=Path(d)/"ghidra"; (ghidra/"support").mkdir(parents=True)
            analyzer=ghidra/"support/analyzeHeadless"
            analyzer.write_text("#!/bin/sh\necho UNEXPECTED_ANALYSIS\nexit 1\n"); analyzer.chmod(0o755)
            cache=Path(str(image)+".decomp"); cache.mkdir()
            (cache/"_index.txt").write_text("ffffffff81000001\tcopy_process\t1\n")
            (cache/"copy_process.c").write_text("void copy_process(void) {}\n")
            write_meta(str(cache),str(image),str(ghidra),str(BIN/"ghidra_scripts"),"complete")
            fake=Path(d)/"bin"; fake.mkdir()
            timeout=fake/"timeout"; timeout.write_text('#!/bin/sh\nshift 3\nexec "$@"\n'); timeout.chmod(0o755)
            env=dict(os.environ,CTF_HOME=str(ROOT),GHIDRA_HOME=str(ghidra),
                     XDG_CONFIG_HOME=str(Path(d)/"xdg"),PATH=str(fake)+os.pathsep+os.environ["PATH"])
            hit=self.run_tool("decomp",image,"copy_process",env=env)
            self.assertEqual(hit.returncode,0,hit.stderr)
            self.assertIn("copy_process",hit.stdout)
            for args in (("--refresh",image,"copy_process"),(image,"1234")):
                denied=self.run_tool("decomp",*args,env=env)
                self.assertEqual(denied.returncode,2,denied.stderr)
                self.assertIn("--allow-full-analysis",denied.stderr)
                self.assertNotIn("UNEXPECTED_ANALYSIS",denied.stderr)
                self.assertTrue((cache/"copy_process.c").exists())


if __name__=="__main__":
    unittest.main()
