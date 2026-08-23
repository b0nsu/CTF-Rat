"""Canonical cache keys and a mutable index pointing only at artifacts.

M2 adds canonical_key() (DESIGN_v2 C3 v2 shape) and a (backend, path)
read-through index alongside the original P1 (key -> envelope_digest) index
consumed by contracts.py. Both live in the same sqlite table; the schema
migrates existing 2-column databases in place (dual-read/single-write: old
rows keep working via get()/put(), new rows use get_entry()/put_entry()).
"""
from __future__ import annotations
import hashlib, json, os, sqlite3
from datetime import datetime, timezone

def key(*, tool, inputs, parameters, dependencies, policy_digest, output_schema="rat.tool-result/v1"):
    doc={"schema":"rat.cache-key/v1","tool":tool,"inputs":sorted(inputs,key=lambda x:(x.get("role",""),x.get("digest",""))),"parameters":parameters,"dependencies":dependencies,"policy_digest":policy_digest,"output_schema":output_schema}
    raw=json.dumps(doc,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode(); return "sha256:"+hashlib.sha256(raw).hexdigest()

def canonical_key(*, binary_sha256, tool_name, tool_version, params, dep_versions,
                   artifact_inputs=(), output_schema="rat.tool-result/v1", analysis_schema_version="v1"):
    """DESIGN_v2 C3 (S9.1) canonical cache key v2, shared by revq/decomp/rat-profile."""
    doc={"schema":"rat.cache-key/v2","binary_sha256":binary_sha256,"tool_name":tool_name,"tool_version":tool_version,
         "params":params,"dep_versions":dep_versions,
         "artifact_inputs":sorted(artifact_inputs,key=lambda x:(x.get("role",""),x.get("digest",""))),
         "output_schema":output_schema,"analysis_schema_version":analysis_schema_version}
    raw=json.dumps(doc,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode(); return "sha256:"+hashlib.sha256(raw).hexdigest()

class Cache:
 def __init__(self, root):
  path=os.path.join(root,"indexes","cache.sqlite3"); os.makedirs(os.path.dirname(path),exist_ok=True); self.db=sqlite3.connect(path)
  self.db.execute("CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, envelope_digest TEXT, backend TEXT, path TEXT, produced_at TEXT)")
  cols={row[1] for row in self.db.execute("PRAGMA table_info(cache)")}
  if "backend" not in cols:
   self.db.execute("ALTER TABLE cache RENAME TO cache_v1")
   self.db.execute("CREATE TABLE cache (key TEXT PRIMARY KEY, envelope_digest TEXT, backend TEXT, path TEXT, produced_at TEXT)")
   self.db.execute("INSERT INTO cache (key, envelope_digest) SELECT key, envelope_digest FROM cache_v1")
   self.db.execute("DROP TABLE cache_v1")
  self.db.commit()
 def get(self,k):
  row=self.db.execute("SELECT envelope_digest FROM cache WHERE key=?",(k,)).fetchone(); return row[0] if row else None
 def put(self,k,envelope_digest): self.db.execute("INSERT OR REPLACE INTO cache (key, envelope_digest) VALUES (?,?)",(k,envelope_digest)); self.db.commit()
 def get_entry(self,k):
  row=self.db.execute("SELECT backend, path, produced_at, envelope_digest FROM cache WHERE key=?",(k,)).fetchone()
  if not row: return None
  backend,path,produced_at,envelope_digest=row
  if backend is None and path is None: return None
  return {"backend":backend,"path":path,"produced_at":produced_at,"envelope_digest":envelope_digest}
 def put_entry(self,k,*,backend,path,envelope_digest=None):
  self.db.execute("INSERT OR REPLACE INTO cache (key, envelope_digest, backend, path, produced_at) VALUES (?,?,?,?,?)",
                   (k,envelope_digest,backend,path,datetime.now(timezone.utc).isoformat())); self.db.commit()
