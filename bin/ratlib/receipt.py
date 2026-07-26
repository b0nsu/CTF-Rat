"""Broker receipt integrity helpers.

The key is intentionally outside the content-addressed object store.  A
deployment with a privileged broker supplies ``RAT_BROKER_KEY_PATH``; the
local fallback is for single-user development only and is not a hostile-agent
trust boundary.
"""
from __future__ import annotations
import hashlib, hmac, json, os

def _key_path(root):
    configured=os.environ.get("RAT_BROKER_KEY_PATH")
    return os.path.abspath(configured) if configured else os.path.join(root,"broker-private","receipt.key")

def _key(root):
    path=_key_path(root); os.makedirs(os.path.dirname(path),mode=0o700,exist_ok=True)
    try:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    except FileExistsError:
        with open(path,"rb") as source: key=source.read()
    else:
        try:
            key=os.urandom(32); os.write(fd,key); os.fsync(fd)
        finally: os.close(fd)
    mode=os.stat(path).st_mode & 0o777
    if mode & 0o077: raise ValueError("broker receipt key must not be group/world accessible")
    if len(key)<32: raise ValueError("broker receipt key is invalid")
    return key

def payload(receipt):
    if not isinstance(receipt,dict): raise ValueError("receipt must be an object")
    unsigned={k:v for k,v in receipt.items() if k!="signature"}
    return json.dumps(unsigned,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def sign(root, receipt):
    return "hmac-sha256:"+hmac.new(_key(root),payload(receipt),hashlib.sha256).hexdigest()

def verify(root, receipt):
    signature=receipt.get("signature") if isinstance(receipt,dict) else None
    if not isinstance(signature,str) or not signature.startswith("hmac-sha256:"):
        return False
    return hmac.compare_digest(signature,sign(root,receipt))
