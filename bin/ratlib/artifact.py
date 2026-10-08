"""Immutable local SHA-256 object store used by challenge directories."""
from __future__ import annotations
import argparse, hashlib, json, os, re, shutil, tempfile
from datetime import datetime, timezone

_DIGEST_RE = re.compile(rb"sha256:[0-9a-f]{64}")
_DIGEST_TOKEN_BYTES = len(b"sha256:") + 64
_SCAN_CHUNK_BYTES = 1024 * 1024

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
def metadata(digest: str, *, root: str | None = None) -> dict:
    """Return immutable object metadata only after checking its content."""
    checked_root=_root(root); get(digest,root=checked_root)
    _,path=_paths(checked_root,digest)
    with open(path,encoding="utf-8") as source: record=json.load(source)
    if record.get("schema")!="rat.artifact/v1" or record.get("digest")!=digest:
        raise RuntimeError("artifact metadata corruption")
    return record
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

def _file_references(path: str) -> set[str]:
    """Extract digest references from one file without loading large captures at once."""
    found=set(); tail=b""
    try:
        with open(path,"rb") as source:
            while True:
                chunk=source.read(_SCAN_CHUNK_BYTES)
                if not chunk: break
                data=tail+chunk
                found.update(match.group(0).decode("ascii") for match in _DIGEST_RE.finditer(data))
                tail=data[-(_DIGEST_TOKEN_BYTES-1):]
    except OSError:
        pass
    return found

def reachable(root: str) -> set[str]:
    """Return the transitive artifact closure reachable from mutable control files.

    STATE/tasks/checkpoints/cache indexes/run.json are roots. Artifact payloads are
    immutable graph nodes and may themselves reference child artifacts (for example
    a tool-result envelope referring to stdout/stderr captures). GC must therefore
    mark through reachable object payloads before sweeping, otherwise it can keep an
    evidence envelope while deleting the measurement artifacts that make it valid.
    """
    root=_root(root); found=set()
    for base,dirs,files in os.walk(root):
        relative=os.path.relpath(base,root)
        first=relative.split(os.sep,1)[0] if relative != "." else None
        if first in {"objects","metadata"}:
            dirs[:]=[]
            continue
        for name in files:
            found.update(_file_references(os.path.join(base,name)))
    # ``run.json`` is solve-owned and deliberately sits beside .rat; it is a
    # root reference even though it is outside the object-store directory.
    found.update(_file_references(os.path.join(os.path.dirname(root),"run.json")))

    # Mark the full immutable object graph. Read raw bytes rather than get(): a
    # referenced but corrupt parent should still conservatively retain any child
    # digests visible in its bytes so GC never makes forensic recovery worse.
    pending=list(found); expanded=set()
    while pending:
        digest=pending.pop()
        if digest in expanded:
            continue
        expanded.add(digest)
        try: obj,_=_paths(root,digest)
        except ValueError: continue
        for child in _file_references(obj):
            if child not in found:
                found.add(child); pending.append(child)
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
    x=sub.add_parser("gc"); x.add_argument("--apply",action="store_true")
    a=p.parse_args()
    if a.cmd=="put": print(json.dumps(put_file(a.file,kind=a.kind,media_type=a.media_type,logical_name=a.logical_name or os.path.basename(a.file),root=a.root)))
    elif a.cmd=="get":
        data=get(a.digest,root=a.root)
        if a.output: open(a.output,"wb").write(data)
        else: os.write(1,data)
    elif a.cmd=="verify":
        bad=verify(a.digest,root=a.root); print(json.dumps({"ok":not bad,"failures":bad})); raise SystemExit(1 if bad else 0)
    else: print(json.dumps({"dry_run":not a.apply,"objects":gc(root=a.root,dry_run=not a.apply)}))
if __name__ == "__main__": main()
