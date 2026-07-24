"""Canonical P1 cache keys and a mutable index pointing only at artifacts."""
from __future__ import annotations
import hashlib, json, os, sqlite3
def key(*, tool, inputs, parameters, dependencies, policy_digest, output_schema="rat.tool-result/v1"):
    doc={"schema":"rat.cache-key/v1","tool":tool,"inputs":sorted(inputs,key=lambda x:(x.get("role",""),x.get("digest",""))),"parameters":parameters,"dependencies":dependencies,"policy_digest":policy_digest,"output_schema":output_schema}
    raw=json.dumps(doc,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode(); return "sha256:"+hashlib.sha256(raw).hexdigest()
class Cache:
 def __init__(self, root):
  path=os.path.join(root,"indexes","cache.sqlite3"); os.makedirs(os.path.dirname(path),exist_ok=True); self.db=sqlite3.connect(path)
  self.db.execute("CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, envelope_digest TEXT NOT NULL)"); self.db.commit()
 def get(self,k):
  row=self.db.execute("SELECT envelope_digest FROM cache WHERE key=?",(k,)).fetchone(); return row[0] if row else None
 def put(self,k,envelope_digest): self.db.execute("INSERT OR REPLACE INTO cache VALUES (?,?)",(k,envelope_digest)); self.db.commit()
