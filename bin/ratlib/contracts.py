"""Adapters that turn existing deterministic tools into P1 result envelopes."""
from __future__ import annotations
import hashlib, json, os, platform, re, shlex, sys, uuid
from datetime import datetime, timezone
from .artifact import get, put_bytes
from .cache import Cache, key as cache_key
from .runner import run
from .schema import validate
from .state_v2 import Stream, _evidence_quality, direct_measurement_policy, now, trusted_producer_for_build

def _iso(): return datetime.now(timezone.utc).isoformat()

PROOF_MODES={
 "pwn-control-state":{"tool":"gdbq","kind":"pwn.reg"},
 "pwn-memory-control":{"tool":"gdbq","kind":"pwn.memory-control"},
 "pwn-control-target":{"tool":"gdbq","kind":"pwn.control-target"},
 "rev-solution-input":{"tool":"symsolve","kind":"rev.solution.input"},
 "rev-success-oracle":{"tool":"gdbq","kind":"rev.solution.oracle"},
 "rev-concrete-replay":{"tool":"gdbq","kind":"rev.solution.replay"},
}
_GDB_BREAK=re.compile(r"(?:0x[0-9a-fA-F]+|[A-Za-z_.$][A-Za-z0-9_.$]*)\Z")
_GDB_EXPR=re.compile(r"(?:\$[A-Za-z][A-Za-z0-9]*|0x[0-9a-fA-F]+)(?:[+-](?:0x[0-9a-fA-F]+|[0-9]+))?\Z")
_HEX_BYTES=re.compile(r"(?:[0-9a-fA-F]{2})+\Z")

def _proof_error(message):
 raise ValueError("proof observation: "+message)

def _proof_input_command(path):
 path=os.path.realpath(os.path.abspath(path))
 if not os.path.isfile(path): _proof_error("proof input is not an existing file")
 if "\n" in path or "\r" in path: _proof_error("proof input path contains a newline")
 return "run < "+shlex.quote(path)

def prepare_proof_invocation(tool_name, tool_path, base_args, *, direct_subject,
                             proof=None, proof_input=None, proof_break=None,
                             proof_address=None, proof_marker=None,
                             proof_target=None, proof_expect=None):
 """Build a bounded verifier invocation for a semantic proof observation.

 Arbitrary user GDB commands are never accepted in proof mode.  PWN/REV runtime
 proof modes construct the exact gdbq commands themselves, then the parser below
 validates the resulting capture before STATE receives a canonical observation.
 """
 if proof is None: return [tool_path,*base_args]
 spec=PROOF_MODES.get(proof)
 if not spec: _proof_error("unknown proof mode %r" % proof)
 if tool_name!=spec["tool"]:
  _proof_error("%s requires tool %s" % (proof,spec["tool"]))
 if not direct_subject or not os.path.isfile(direct_subject):
  _proof_error("proof mode requires an existing --direct-subject")
 if proof=="rev-solution-input":
  if not base_args or os.path.realpath(base_args[0])!=os.path.realpath(direct_subject):
   _proof_error("rev-solution-input requires symsolve args to start with --direct-subject")
  if not any(arg in {"--find","--find-str"} for arg in base_args[1:]):
   _proof_error("rev-solution-input requires symsolve --find or --find-str")
  return [tool_path,*base_args]
 if base_args:
  _proof_error("gdbq proof modes do not accept arbitrary trailing gdbq commands")
 if not proof_input: _proof_error("%s requires --proof-input" % proof)
 commands=[]
 if proof.startswith("pwn-"):
  if not proof_break or not _GDB_BREAK.fullmatch(proof_break):
   _proof_error("%s requires a safe --proof-break symbol/address" % proof)
  commands=["break "+proof_break,_proof_input_command(proof_input)]
  if proof=="pwn-control-state":
   commands.append("info registers rip rsp rbp")
  elif proof=="pwn-memory-control":
   if not proof_address or not _GDB_EXPR.fullmatch(proof_address):
    _proof_error("pwn-memory-control requires a safe --proof-address")
   if not proof_marker or not _HEX_BYTES.fullmatch(proof_marker) or len(proof_marker)%2:
    _proof_error("pwn-memory-control requires even-length --proof-marker hex")
   size=len(proof_marker)//2
   if not 1<=size<=64: _proof_error("pwn-memory-control marker must be 1..64 bytes")
   commands.append("x/%dbx %s" % (size,proof_address))
  else:
   if not proof_address or not _GDB_EXPR.fullmatch(proof_address):
    _proof_error("pwn-control-target requires a safe --proof-address")
   try: target=int(str(proof_target),0)
   except (TypeError,ValueError): _proof_error("pwn-control-target requires numeric --proof-target")
   if not 0<=target<2**64: _proof_error("pwn-control-target is outside uint64")
   commands.append("x/gx "+proof_address)
 elif proof in {"rev-success-oracle","rev-concrete-replay"}:
  if not isinstance(proof_expect,str) or not proof_expect:
   _proof_error("%s requires non-empty --proof-expect" % proof)
  commands=[_proof_input_command(proof_input)]
  if proof=="rev-concrete-replay":
   commands.append("echo RAT_REPLAY_COMPLETE\\n")
 return [tool_path,direct_subject,*commands]

def _proof_stdout(doc, root):
 artifact=next((a for a in doc.get("artifacts",[]) if a.get("kind")=="stdout"),None)
 if not artifact or not isinstance(artifact.get("digest"),str):
  _proof_error("verifier result has no stdout artifact")
 return get(artifact["digest"],root=root).decode("utf-8",errors="replace")

def _parse_registers(text):
 out={}
 for name,value in re.findall(r"(?m)^\s*([A-Za-z][A-Za-z0-9]*)\s+(0x[0-9a-fA-F]+)\b",text):
  out[name.lower()]=int(value,16)
 return out

def _parse_memory_bytes(text):
 out=[]
 for line in text.splitlines():
  if ":" not in line: continue
  _addr,tail=line.split(":",1)
  out.extend(int(x,16) for x in re.findall(r"0x([0-9a-fA-F]{2})\b",tail))
 return bytes(out)

def _parse_memory_word(text):
 for line in text.splitlines():
  if ":" not in line: continue
  match=re.search(r":\s*(0x[0-9a-fA-F]+)\b",line)
  if match: return int(match.group(1),16)
 return None

def parse_proof_value(proof, doc, root, *, proof_address=None, proof_marker=None,
                      proof_target=None, proof_expect=None):
 """Validate verifier stdout and return the canonical observation value."""
 text=_proof_stdout(doc,root)
 if proof.startswith("pwn-") and not re.search(r"(?m)^Breakpoint \d+,",text):
  _proof_error("GDB did not stop at the requested proof breakpoint")
 if proof=="pwn-control-state":
  regs=_parse_registers(text)
  if "rip" not in regs or "rsp" not in regs:
   _proof_error("control-state output is missing RIP/RSP")
  return {"rip":regs["rip"],"rsp":regs["rsp"],"rbp":regs.get("rbp")}
 if proof=="pwn-memory-control":
  marker=bytes.fromhex(proof_marker)
  measured=_parse_memory_bytes(text)
  if measured[:len(marker)]!=marker:
   _proof_error("measured memory does not match the attacker marker")
  return {"address":proof_address,"marker_hex":proof_marker.lower(),"bytes":len(marker)}
 if proof=="pwn-control-target":
  measured=_parse_memory_word(text)
  target=int(str(proof_target),0)
  if measured is None or measured!=target:
   _proof_error("measured control target does not match --proof-target")
  return {"address":proof_address,"target":target}
 if proof=="rev-solution-input":
  solutions={}
  # symsolve prints one stable two-line pair per symbolic source:
  #   stdin  = b'...'
  #          hex: 4142...
  pattern=re.compile(r"(?m)^\s*(stdin|argv1|file:[^ =]+)\s*=.*\n\s*hex:\s*([0-9a-fA-F]*)\s*$")
  for label,hex_value in pattern.findall(text): solutions[label]=hex_value.lower()
  if not solutions: _proof_error("symsolve output contains no reconstructed concrete input")
  return {"solutions":solutions}
 if proof in {"rev-success-oracle","rev-concrete-replay"}:
  if "exited normally" not in text:
   _proof_error("concrete replay did not exit normally")
  if proof_expect not in text:
   _proof_error("concrete replay output does not contain --proof-expect")
  if proof=="rev-concrete-replay" and "RAT_REPLAY_COMPLETE" not in text:
   _proof_error("replay completion sentinel is absent")
  return {"expected":proof_expect,"exit":"normal"}
 _proof_error("unsupported proof mode %r" % proof)

def record_proof_observation(doc, *, root, direct_subject, proof,
                             proof_address=None, proof_marker=None,
                             proof_target=None, proof_expect=None):
 """Record one validated canonical proof observation backed by a direct envelope."""
 spec=PROOF_MODES.get(proof)
 if not spec: _proof_error("unknown proof mode %r" % proof)
 root=os.path.realpath(os.path.abspath(root))
 if os.path.basename(root)!=".rat":
  _proof_error("--root must name the challenge .rat directory when recording proof observations")
 digest=(doc.get("extensions") or {}).get("envelope_digest")
 if not isinstance(digest,str): _proof_error("verifier result has no envelope_digest")
 if _evidence_quality([digest],root)!="direct":
  _proof_error("verifier envelope is not direct evidence")
 value=parse_proof_value(proof,doc,root,proof_address=proof_address,
                         proof_marker=proof_marker,proof_target=proof_target,
                         proof_expect=proof_expect)
 stream=Stream(os.path.dirname(root))
 for oid,existing in stream.view().get("observations",{}).items():
  if existing.get("kind")==spec["kind"] and digest in existing.get("evidence",[]):
   return {"observation_id":oid,"kind":spec["kind"],"deduplicated":True}
 policy=(doc.get("extensions") or {}).get("evidence_policy") or {}
 observation_id="obs_proof_"+uuid.uuid4().hex
 payload={
  "schema":"rat.observation/v1","observation_id":observation_id,
  "run_id":doc.get("run_id") or "local","created_at":now(),
  "producer":{"tool":doc.get("tool",{}).get("name","unknown"),
              "version":doc.get("tool",{}).get("version","unknown"),
              "adapter":"rat-adapt/proof-v1"},
  "subject":{"binary":os.path.realpath(direct_subject),
             "binary_digest":policy.get("subject_digest")},
  "kind":spec["kind"],"value":value,"evidence":[digest],
  "quality":{"level":"direct"},"validity":{"state":"active"},
  "extensions":{"proof_mode":proof,"invocation_id":doc.get("invocation_id")},
 }
 stream.append("observation.recorded",payload)
 stored=stream.view()["observations"][observation_id]
 if stored.get("quality",{}).get("level")!="direct":
  raise RuntimeError("proof observation unexpectedly failed direct evidence reclassification")
 return {"observation_id":observation_id,"kind":spec["kind"],"deduplicated":False}
def direct_evidence_envelope(*, root, producer, measurement, summary=None):
 """Deprecated compatibility stub.

 Production code must not mint synthetic direct evidence. Run an allow-listed
 SELF verifier through ``execute()`` and cite ``extensions.envelope_digest``.
 """
 raise RuntimeError("synthetic direct evidence is disabled; use execute() and cite extensions.envelope_digest")
def _digest_file(path):
 h=hashlib.sha256()
 with open(path,"rb") as f:
  for b in iter(lambda:f.read(65536),b""): h.update(b)
 return "sha256:"+h.hexdigest()
def _captured_bytes(stream):
 """Return the full bounded capture, preferring the runner spool over preview."""
 if stream.spool_path:
  with open(stream.spool_path,"rb") as f: return f.read()
 return stream.preview
def _capture_artifact(stream, kind, root):
 """Persist one bounded stream, then best-effort remove its staging spool.

 The content-addressed artifact is the durable copy. A spool file is only a
 transient runner staging object and must not become a second long-term store.
 Cleanup happens only after ``put_bytes`` succeeds, so a failed artifact write
 leaves the spool available for diagnosis/retry.
 """
 data=_captured_bytes(stream)
 rec=put_bytes(data,kind=kind,media_type="text/plain; charset=utf-8",
               logical_name=kind+".txt",root=root)
 if stream.spool_path:
  try: os.unlink(stream.spool_path)
  except OSError: pass
 return {k:rec[k] for k in ("kind","digest","media_type","size","logical_name")}
def _validate_direct_target(build, tool_argv, direct_subject):
 """Fail closed when a trusted SELF verifier targets a different subject.

 ``direct_subject`` is caller metadata; the verifier argv is the execution truth.
 For the registered gdbq/symsolve contracts the measured binary is argv[1].
 Compare by content so equivalent relative/symlink paths remain portable.
 """
 producer=trusted_producer_for_build(build)
 if producer not in {"gdbq","symsolve","symsolve.py"}:
  return
 if len(tool_argv)<2:
  raise ValueError("direct verifier invocation is missing its measured subject")
 target=os.fspath(tool_argv[1])
 if not os.path.isfile(target):
  raise ValueError("direct verifier target is not an existing file")
 if _digest_file(target)!=_digest_file(direct_subject):
  raise ValueError("direct_subject does not match verifier target")
def _persist_cache_hit_invocation(doc, root):
 """Persist cache hits for session telemetry without minting cached direct evidence.

 The returned document may still cite the original executed envelope as
 ``extensions.envelope_digest``. The invocation record itself deliberately drops
 evidence_policy/envelope_digest so a cache hit cannot masquerade as a fresh SELF
 measurement while rat-metrics can still count the invocation.
 """
 recorded={**doc}
 ext={**(recorded.get("extensions") or {})}
 ext.pop("evidence_policy",None)
 ext.pop("envelope_digest",None)
 if ext:
  recorded["extensions"]=ext
 else:
  recorded.pop("extensions",None)
 validate(recorded)
 raw=json.dumps(recorded,sort_keys=True,separators=(",",":")).encode()
 put_bytes(raw,kind="tool-result",media_type="application/json",
           logical_name="cache-hit-invocation.json",root=root)
def execute(tool_argv, *, root=None, input_paths=(), parameters=None, timeout=60, direct_subject=None):
 """Run a tool and preserve its complete bounded stdout/stderr as artifacts.

 ``direct_subject`` (one of ``input_paths``) opts this invocation into direct-evidence
 issuance: only a real measurement mode of a registered verifier that consumed that
 subject mints a direct policy (see state_v2.direct_measurement_policy). Left unset,
 or for any non-measurement run, the envelope is derived evidence.
 """
 root=os.path.abspath(root or os.path.join(os.getcwd(),".rat")); parameters=parameters or {}
 tool_path=tool_argv[0]; build=_digest_file(tool_path) if os.path.isfile(tool_path) else "sha256:"+"0"*64
 inputs=[{"role":"input","digest":_digest_file(p),"size":os.path.getsize(p)} for p in input_paths if os.path.isfile(p)]
 policy="sha256:"+hashlib.sha256(b"p1-local").hexdigest()
 # Tool output depends on command-line mode too. Preserve the full argv so
 # measurement, diagnostic, and query modes cannot share one cache envelope.
 cache_parameters={**parameters,"_execution_policy":{"timeout_seconds":timeout,"max_output_bytes":64*1024*1024},
                   "_tool_argv":[str(arg) for arg in tool_argv]}
 # A direct request and a plain request over the same argv/inputs must not alias in
 # the cache: their envelopes differ (one carries an evidence_policy).
 if direct_subject is not None:
  # The envelope's policy is bound to this specific measured input. Keeping
  # only a boolean here lets two subjects in the same input set alias one
  # another's direct-evidence envelope on a cache hit.
  if direct_subject not in input_paths or not os.path.isfile(direct_subject):
   raise ValueError("direct_subject must name an existing input path")
  _validate_direct_target(build,tool_argv,direct_subject)
  cache_parameters={**cache_parameters,"_direct_measurement":True,
                    "_direct_subject_digest":_digest_file(direct_subject)}
 ck=cache_key(tool={"name":os.path.basename(tool_path),"version":"legacy-adapter/v1","build_digest":build},inputs=inputs,parameters=cache_parameters,dependencies={},policy_digest=policy)
 tool_name=os.path.basename(tool_path)
 cache=Cache(root); hit=cache.get(ck)
 if hit:
  try:
   from .artifact import get
   old_doc=json.loads(get(hit,root=root)); now=_iso()
   extensions={**(old_doc.get("extensions") or {}),"envelope_digest":hit}
   doc={**old_doc,"invocation_id":"invoke_"+uuid.uuid4().hex,"started_at":now,"finished_at":now,"duration_ms":0,
    "tool_name":tool_name,"params_digest":"unindexed","cache_state":"hit",
    "extensions":extensions,
    "provenance":{**old_doc["provenance"],"cache":{"key":ck,"hit":True,"source_invocation":old_doc.get("invocation_id")}}}
   validate(doc)
   _persist_cache_hit_invocation(doc,root)
   return doc
  except Exception:
   pass
 started=_iso(); result=run(tool_argv,timeout_seconds=timeout,spool_dir=os.path.join(root,"tmp"))
 artifacts=[_capture_artifact(result.stdout,"stdout",root),
            _capture_artifact(result.stderr,"stderr",root)]
 status="timeout" if result.timed_out else ("ok" if result.exit_code==0 else "error")
 # Direct evidence is minted ONLY when the caller names the measured subject and the
 # invocation is a real measurement mode of a registered verifier (see
 # state_v2.direct_measurement_policy). A generic successful run -- including a
 # verifier's own `selftest`, which measures no challenge -- yields derived evidence.
 direct_policy=(direct_measurement_policy(build, tool_argv, input_paths, direct_subject)
                if status=="ok" and direct_subject is not None else None)
 extensions={"evidence_policy":direct_policy} if direct_policy else None
 doc={"schema":"rat.tool-result/v1","tool":{"name":os.path.basename(tool_path),"version":"legacy-adapter/v1","build_digest":build},"run_id":"local","invocation_id":"invoke_"+uuid.uuid4().hex,"status":status,"started_at":started,"finished_at":_iso(),"duration_ms":result.duration_ms,"inputs":inputs,"parameters":parameters,"summary":{"stdout_bytes":result.stdout.total_bytes,"stderr_bytes":result.stderr.total_bytes,"truncated":result.stdout.truncated or result.stderr.truncated},"artifacts":artifacts,"findings":[],"diagnostics":([{"code":"timeout","severity":"warning","message":"retry with a larger budget"}] if status=="timeout" else []),"exit":{"code":result.exit_code,"signal":result.signal,"timed_out":result.timed_out,"cancelled":result.cancelled},"provenance":{"platform":{"os":sys.platform,"arch":platform.machine()},"dependency_versions":{},"policy_digest":policy,"cache":{"key":ck,"hit":False,"source_invocation":None}},"tool_name":tool_name,"params_digest":"unindexed","cache_state":"miss"}
 if extensions: doc["extensions"]=extensions
 validate(doc); raw=json.dumps(doc,sort_keys=True,separators=(",",":")).encode(); envelope=put_bytes(raw,kind="tool-result",media_type="application/json",logical_name="result.json",root=root)
 doc["extensions"]={**(doc.get("extensions") or {}),"envelope_digest":envelope["digest"]}
 validate(doc)
 # A partial, failed, or truncated run is evidence, not a reusable analysis
 # result. Re-running with a larger budget must execute the tool again.
 if status=="ok" and not result.stdout.truncated and not result.stderr.truncated:
  cache.put(ck,envelope["digest"])
 return doc
