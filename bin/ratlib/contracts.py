"""Adapters that turn existing deterministic tools into P1 result envelopes."""
from __future__ import annotations
import hashlib, json, os, platform, sys, uuid
from datetime import datetime, timezone
from .artifact import put_bytes
from .cache import Cache, key as cache_key
from .runner import run
from .schema import validate

def _iso(): return datetime.now(timezone.utc).isoformat()
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
def _cache_hit_doc(cached, ck):
 """Return a fresh invocation envelope while reusing cached deterministic artifacts.

 A cache lookup is a new invocation for telemetry/provenance purposes.  Returning
 the producer envelope verbatim would incorrectly report ``hit=false`` and reuse
 its invocation id, making cache-hit ratios and duplicate-call analysis wrong.
 """
 now=_iso(); source=cached.get("invocation_id")
 doc=dict(cached)
 doc["invocation_id"]="invoke_"+uuid.uuid4().hex
 doc["started_at"]=now; doc["finished_at"]=now; doc["duration_ms"]=0
 provenance=dict(cached.get("provenance",{}))
 provenance["cache"]={"key":ck,"hit":True,"source_invocation":source}
 doc["provenance"]=provenance
 validate(doc)
 return doc
def execute(tool_argv, *, root=None, input_paths=(), parameters=None, timeout=60):
 """Run an existing tool and preserve its complete stdout/stderr as artifacts."""
 root=os.path.abspath(root or os.path.join(os.getcwd(),".rat")); parameters=parameters or {}
 tool_path=tool_argv[0]; build=_digest_file(tool_path) if os.path.isfile(tool_path) else "sha256:"+"0"*64
 inputs=[{"role":"input","digest":_digest_file(p),"size":os.path.getsize(p)} for p in input_paths if os.path.isfile(p)]
 policy="sha256:"+hashlib.sha256(b"p1-local").hexdigest()
 cache_parameters={**parameters,"_execution_policy":{"timeout_seconds":timeout,"max_output_bytes":64*1024*1024}}
 ck=cache_key(tool={"name":os.path.basename(tool_path),"version":"legacy-adapter/v1","build_digest":build},inputs=inputs,parameters=cache_parameters,dependencies={},policy_digest=policy)
 cache=Cache(root); hit=cache.get(ck)
 if hit:
  try:
   from .artifact import get
   return _cache_hit_doc(json.loads(get(hit,root=root)),ck)
  except Exception: pass
 started=_iso(); result=run(tool_argv,timeout_seconds=timeout,spool_dir=os.path.join(root,"tmp"))
 artifacts=[]
 for kind,data in (("stdout",_captured_bytes(result.stdout)),("stderr",_captured_bytes(result.stderr))):
  rec=put_bytes(data,kind=kind,media_type="text/plain; charset=utf-8",logical_name=kind+".txt",root=root)
  artifacts.append({k:rec[k] for k in ("kind","digest","media_type","size","logical_name")})
 status="timeout" if result.timed_out else ("ok" if result.exit_code==0 else "error")
 doc={"schema":"rat.tool-result/v1","tool":{"name":os.path.basename(tool_path),"version":"legacy-adapter/v1","build_digest":build},"run_id":"local","invocation_id":"invoke_"+uuid.uuid4().hex,"status":status,"started_at":started,"finished_at":_iso(),"duration_ms":result.duration_ms,"inputs":inputs,"parameters":parameters,"summary":{"stdout_bytes":result.stdout.total_bytes,"stderr_bytes":result.stderr.total_bytes,"truncated":result.stdout.truncated or result.stderr.truncated},"artifacts":artifacts,"findings":[],"diagnostics":([{"code":"timeout","severity":"warning","message":"retry with a larger budget"}] if status=="timeout" else []),"exit":{"code":result.exit_code,"signal":result.signal,"timed_out":result.timed_out,"cancelled":result.cancelled},"provenance":{"platform":{"os":sys.platform,"arch":platform.machine()},"dependency_versions":{},"policy_digest":policy,"cache":{"key":ck,"hit":False,"source_invocation":None}}}
 validate(doc); raw=json.dumps(doc,sort_keys=True,separators=(",",":")).encode(); envelope=put_bytes(raw,kind="tool-result",media_type="application/json",logical_name="result.json",root=root)
 # A partial, failed, or truncated run is evidence, not a reusable analysis
 # result.  Re-running with a larger budget must execute the tool again.
 if status=="ok" and not result.stdout.truncated and not result.stderr.truncated:
  cache.put(ck,envelope["digest"])
 return doc
