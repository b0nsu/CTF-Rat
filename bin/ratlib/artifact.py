"""Immutable local SHA-256 object store used by challenge directories."""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, tempfile
from datetime import datetime, timezone

def digest_bytes(data: bytes) -> str: return "sha256:" + hashlib.sha256(data).hexdigest()
def _root(path: str | None = None) -> str: return os.path.abspath(path or os.path.join(os.getcwd(), ".rat"))
def _paths(root: str, digest: str):
    if not digest.startswith("sha256:") or len(digest) != 71: raise ValueError("invalid digest")
    h = digest[7:]; return (os.path.join(root,"objects","sha256",h[:2],h[2:]), os.path.join(root,"metadata","sha256",h[:2],h[2:]+".json"))
def put_bytes(data: bytes, *, kind: str, media_type: str, logical_name: str, root: str | None = None, provenance: dict | None = None) -> dict:
    root=_root(root); digest=digest_bytes(data); obj, meta=_paths(root,digest)
    os.makedirs(os.path.dirname(obj),mode=0o700,exist_ok=True); os.makedirs(os.path.dirname(meta),mode=0o700,exist_ok=True)
    if os.path.exists(obj):
        with open(obj,"rb") as f: old=f.read()
        if old != data: raise RuntimeError("digest collision/corrupt existing object")
    else:
        fd,tmp=tempfile.mkstemp(prefix=".object-",dir=os.path.dirname(obj))
        try:
            with os.fdopen(fd,"wb") as f: f.write(data); f.flush(); os.fsync(f.fileno())
            with open(tmp, "rb") as check:
                if digest_bytes(check.read()) != digest: raise RuntimeError("write digest mismatch")
            try: os.link(tmp,obj)
            except FileExistsError: pass
        finally:
            try: os.unlink(tmp)
            except FileNotFoundError: pass
    record={"schema":"rat.artifact/v1","digest":digest,"size":len(data),"kind":kind,"media_type":media_type,"logical_name":logical_name,"created_at":datetime.now(timezone.utc).isoformat(),"provenance":provenance or {}}
    if not os.path.exists(meta):
        fd,tmp=tempfile.mkstemp(prefix=".metadata-",dir=os.path.dirname(meta))
        with os.fdopen(fd,"w",encoding="utf-8") as f: json.dump(record,f,sort_keys=True); f.write("\n"); f.flush(); os.fsync(f.fileno())
        try: os.link(tmp,meta)
        except FileExistsError: pass
        finally: os.unlink(tmp)
    return record
def put_file(path: str, **kw):
    with open(path,"rb") as f: return put_bytes(f.read(),logical_name=kw.pop("logical_name",os.path.basename(path)),**kw)
def get(digest: str, *, root: str | None = None) -> bytes:
    obj,_=_paths(_root(root),digest)
    with open(obj,"rb") as f: data=f.read()
    if digest_bytes(data)!=digest: raise RuntimeError("artifact corruption")
    return data
def verify(digest: str | None = None, *, root: str | None = None) -> list[str]:
    root=_root(root); failures=[]
    if digest: candidates=[digest]
    else:
        base=os.path.join(root,"objects","sha256"); candidates=[]
        if os.path.isdir(base): candidates=["sha256:"+a+b for a in os.listdir(base) if len(a)==2 for b in os.listdir(os.path.join(base,a))]
    for d in candidates:
        try: get(d,root=root)
        except Exception: failures.append(d)
    return failures
def reachable(root: str) -> set[str]:
    found=set(); import re
    for base,_,files in os.walk(root):
        if "/objects/" in base or "/metadata/" in base: continue
        for name in files:
            try: data=open(os.path.join(base,name),"rb").read().decode("utf-8","ignore")
            except OSError: continue
            found.update(re.findall(r"sha256:[0-9a-f]{64}",data))
    return found
def gc(*,root: str | None=None,dry_run=True) -> list[str]:
    root=_root(root); keep=reachable(root); removed=[]; base=os.path.join(root,"objects","sha256")
    if not os.path.isdir(base): return removed
    for a in os.listdir(base):
        for b in os.listdir(os.path.join(base,a)):
            d="sha256:"+a+b
            if d not in keep:
                removed.append(d)
                if not dry_run:
                    obj,meta=_paths(root,d); os.unlink(obj)
                    if os.path.exists(meta): os.unlink(meta)
    return removed
def main():
    p=argparse.ArgumentParser(); p.add_argument("--root"); sub=p.add_subparsers(dest="cmd",required=True)
    x=sub.add_parser("put"); x.add_argument("file"); x.add_argument("--kind",required=True); x.add_argument("--media-type",required=True); x.add_argument("--logical-name")
    x=sub.add_parser("get"); x.add_argument("digest"); x.add_argument("--output")
    x=sub.add_parser("verify"); x.add_argument("digest",nargs="?")
    x=sub.add_parser("gc"); x.add_argument("--dry-run",action="store_true")
    a=p.parse_args()
    if a.cmd=="put": print(json.dumps(put_file(a.file,kind=a.kind,media_type=a.media_type,logical_name=a.logical_name or os.path.basename(a.file),root=a.root)))
    elif a.cmd=="get":
        data=get(a.digest,root=a.root)
        if a.output: open(a.output,"wb").write(data)
        else: os.write(1,data)
    elif a.cmd=="verify":
        bad=verify(a.digest,root=a.root); print(json.dumps({"ok":not bad,"failures":bad})); raise SystemExit(1 if bad else 0)
    else: print(json.dumps({"dry_run":a.dry_run,"objects":gc(root=a.root,dry_run=a.dry_run)}))
if __name__ == "__main__": main()
