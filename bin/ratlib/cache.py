"""Canonical cache keys and a mutable index pointing only at artifacts.

Adds canonical_key() (cache key v2 shape) and a (backend, path)
read-through index alongside the original (key -> envelope_digest) index
consumed by contracts.py. Both live in the same sqlite table; the schema
migrates existing 2-column databases in place (dual-read/single-write: old
rows keep working via get()/put(), new rows use get_entry()/put_entry()).
"""
from __future__ import annotations
import hashlib, json, os, sqlite3
from datetime import datetime, timezone

def resolve_index_root(binary, *, override=None):
    """Single canonical index-root resolver shared by revq/decomp/rat-profile.

    The whole point of the M2 index is that one sqlite points at all three
    backends. That only holds if every tool anchors the index the same way,
    so all three MUST route through this function instead of computing a root
    from their own incidental coordinate (cwd / --store / binary dir).

    Precedence:
      1. explicit ``override`` arg, else ``RAT_INDEX_ROOT`` env -- power-user
         / test override; when all tools are given the same one they converge.
      2. ``dirname(realpath(binary))/.rat`` -- the default. Every tool sees the
         same binary, so with no override they land in one shared index
         regardless of where each was invoked from.
    """
    ov = override or os.environ.get("RAT_INDEX_ROOT")
    if ov:
        return os.path.abspath(ov)
    if binary:
        return os.path.join(os.path.dirname(os.path.realpath(binary)), ".rat")
    return os.path.abspath(os.path.join(os.getcwd(), ".rat"))

def key(*, tool, inputs, parameters, dependencies, policy_digest, output_schema="rat.tool-result/v1"):
    doc={"schema":"rat.cache-key/v1","tool":tool,"inputs":sorted(inputs,key=lambda x:(x.get("role",""),x.get("digest",""))),"parameters":parameters,"dependencies":dependencies,"policy_digest":policy_digest,"output_schema":output_schema}
    raw=json.dumps(doc,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode(); return "sha256:"+hashlib.sha256(raw).hexdigest()

def canonical_key(*, binary_sha256, tool_name, tool_version, params, dep_versions,
                   artifact_inputs=(), output_schema="rat.tool-result/v1", analysis_schema_version="v1"):
    """Canonical cache key v2, shared by revq/decomp/rat-profile."""
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
   cols={row[1] for row in self.db.execute("PRAGMA table_info(cache)")}
  if "source_invocation" not in cols:
   self.db.execute("ALTER TABLE cache ADD COLUMN source_invocation TEXT")
  self.db.commit()
 def get(self,k):
  row=self.db.execute("SELECT envelope_digest FROM cache WHERE key=?",(k,)).fetchone(); return row[0] if row else None
 def put(self,k,envelope_digest): self.db.execute("INSERT OR REPLACE INTO cache (key, envelope_digest) VALUES (?,?)",(k,envelope_digest)); self.db.commit()
 def get_entry(self,k):
  row=self.db.execute("SELECT backend, path, produced_at, envelope_digest, source_invocation FROM cache WHERE key=?",(k,)).fetchone()
  if not row: return None
  backend,path,produced_at,envelope_digest,source_invocation=row
  if backend is None and path is None: return None
  return {"backend":backend,"path":path,"produced_at":produced_at,"envelope_digest":envelope_digest,"source_invocation":source_invocation}
 def put_entry(self,k,*,backend,path,envelope_digest=None,source_invocation=None):
  self.db.execute("INSERT OR REPLACE INTO cache (key, envelope_digest, backend, path, produced_at, source_invocation) VALUES (?,?,?,?,?,?)",
                   (k,envelope_digest,backend,path,datetime.now(timezone.utc).isoformat(),source_invocation)); self.db.commit()
 def stats(self):
  total=self.db.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
  by_backend=dict(self.db.execute("SELECT COALESCE(backend,'unspecified'), COUNT(*) FROM cache GROUP BY backend"))
  oldest,newest=self.db.execute("SELECT MIN(produced_at), MAX(produced_at) FROM cache WHERE produced_at IS NOT NULL").fetchone()
  return {"total_entries":total,"by_backend":by_backend,"oldest_produced_at":oldest,"newest_produced_at":newest}
