"""Adapters that turn existing deterministic tools into P1 result envelopes."""
from __future__ import annotations
import hashlib, json, os, platform, sys, uuid
from datetime import datetime, timezone
from .artifact import put_bytes
from .cache import Cache, key as cache_key
from .runner import run
from .schema import validate
from .state_v2 import direct_measurement_policy

def _iso(): return datetime.now(timezone.utc).isoformat()
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
 # Tool output depends on command-line mode too.  Preserve the full argv so
 # measurement, diagnostic, and query modes cannot share one cache envelope.
 cache_parameters={**parameters,"_execution_policy":{"timeout_seconds":timeout,"max_output_bytes":64*1024*1024},
                   "_tool_argv":[str(arg) for arg in tool_argv]}
 # A direct request and a plain request over the same argv/inputs must not alias in
 # the cache: their envelopes differ (one carries an evidence_policy).
 if direct_subject is not None:
  # The envelope's policy is bound to this specific measured input.  Keeping
  # only a boolean here lets two subjects in the same input set alias one
  # another's direct-evidence envelope on a cache hit.
  if direct_subject not in input_paths or not os.path.isfile(direct_subject):
   raise ValueError("direct_subject must name an existing input path")
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
   validate(doc); return doc
  except Exception: pass
 started=_iso(); result=run(tool_argv,timeout_seconds=timeout,spool_dir=os.path.join(root,"tmp"))
 artifacts=[]
 for kind,data in (("stdout",_captured_bytes(result.stdout)),("stderr",_captured_bytes(result.stderr))):
  rec=put_bytes(data,kind=kind,media_type="text/plain; charset=utf-8",logical_name=kind+".txt",root=root)
  artifacts.append({k:rec[k] for k in ("kind","digest","media_type","size","logical_name")})
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
 # result.  Re-running with a larger budget must execute the tool again.
 if status=="ok" and not result.stdout.truncated and not result.stderr.truncated:
  cache.put(ck,envelope["digest"])
 return doc
