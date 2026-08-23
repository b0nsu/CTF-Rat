"""Adapters that turn existing deterministic tools into P1 result envelopes."""
from __future__ import annotations
import copy, hashlib, os, platform, sys, time, uuid
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
def _active_run(root):
 try:
  from .telemetry import active_run_id
  return active_run_id(root)
 except Exception:
  return None
def _cache_metric(root, tool, ck, *, hit=None, write=False, detail=None):
 """Best-effort telemetry must never change tool/cache behavior."""
 try:
  from .telemetry import record_cache, record_cache_write
  if write: record_cache_write(tool=tool,key=ck,root=root)
  else: record_cache(tool=tool,key=ck,hit=bool(hit),root=root,detail=detail)
 except Exception:
  pass
def execute(tool_argv, *, root=None, input_paths=(), parameters=None, timeout=60):
 """Run an existing tool and preserve its complete stdout/stderr as artifacts."""
 root=os.path.abspath(root or os.path.join(os.getcwd(),".rat")); parameters=parameters or {}
 tool_path=tool_argv[0]; tool_name=os.path.basename(tool_path)
 build=_digest_file(tool_path) if os.path.isfile(tool_path) else "sha256:"+"0"*64
 inputs=[{"role":"input","digest":_digest_file(p),"size":os.path.getsize(p)} for p in input_paths if os.path.isfile(p)]
 policy="sha256:"+hashlib.sha256(b"p1-local").hexdigest()
 cache_parameters={**parameters,"_execution_policy":{"timeout_seconds":timeout,"max_output_bytes":64*1024*1024}}
 ck=cache_key(tool={"name":tool_name,"version":"legacy-adapter/v1","build_digest":build},inputs=inputs,parameters=cache_parameters,dependencies={},policy_digest=policy)
 cache=Cache(root); hit=cache.get(ck); cache_started=time.monotonic()
 if hit:
  try:
   from .artifact import get
   import json
   doc=json.loads(get(hit,root=root))
   source_invocation=doc.get("invocation_id")
   doc=copy.deepcopy(doc); now=_iso()
   # A cache hit is a new invocation. Do not leak the run_id of the invocation
   # that originally populated the cache when no benchmark run is active now.
   doc["run_id"]=_active_run(root) or "local"
   doc["invocation_id"]="invoke_"+uuid.uuid4().hex
   doc["started_at"]=now; doc["finished_at"]=_iso()
   doc["duration_ms"]=max(0,int((time.monotonic()-cache_started)*1000))
   doc["provenance"]["cache"]={"key":ck,"hit":True,"source_invocation":source_invocation}
   validate(doc); _cache_metric(root,tool_name,ck,hit=True); return doc
  except Exception:
   _cache_metric(root,tool_name,ck,hit=False,detail="indexed artifact unavailable or invalid")
 else:
  _cache_metric(root,tool_name,ck,hit=False)
 started=_iso(); result=run(tool_argv,timeout_seconds=timeout,spool_dir=os.path.join(root,"tmp"))
 artifacts=[]
 for kind,data in (("stdout",_captured_bytes(result.stdout)),("stderr",_captured_bytes(result.stderr))):
  rec=put_bytes(data,kind=kind,media_type="text/plain; charset=utf-8",logical_name=kind+".txt",root=root)
  artifacts.append({k:rec[k] for k in ("kind","digest","media_type","size","logical_name")})
 status="timeout" if result.timed_out else ("ok" if result.exit_code==0 else "error")
 doc={"schema":"rat.tool-result/v1","tool":{"name":tool_name,"version":"legacy-adapter/v1","build_digest":build},"run_id":_active_run(root) or "local","invocation_id":"invoke_"+uuid.uuid4().hex,"status":status,"started_at":started,"finished_at":_iso(),"duration_ms":result.duration_ms,"inputs":inputs,"parameters":parameters,"summary":{"stdout_bytes":result.stdout.total_bytes,"stderr_bytes":result.stderr.total_bytes,"truncated":result.stdout.truncated or result.stderr.truncated},"artifacts":artifacts,"findings":[],"diagnostics":([{"code":"timeout","severity":"warning","message":"retry with a larger budget"}] if status=="timeout" else []),"exit":{"code":result.exit_code,"signal":result.signal,"timed_out":result.timed_out,"cancelled":result.cancelled},"provenance":{"platform":{"os":sys.platform,"arch":platform.machine()},"dependency_versions":{},"policy_digest":policy,"cache":{"key":ck,"hit":False,"source_invocation":None}}}
 validate(doc); raw=__import__("json").dumps(doc,sort_keys=True,separators=(",",":")).encode(); envelope=put_bytes(raw,kind="tool-result",media_type="application/json",logical_name="result.json",root=root)
 # A partial, failed, or truncated run is evidence, not a reusable analysis
 # result. Re-running with a larger budget must execute the tool again.
 if status=="ok" and not result.stdout.truncated and not result.stderr.truncated:
  cache.put(ck,envelope["digest"]); _cache_metric(root,tool_name,ck,write=True)
 return doc
