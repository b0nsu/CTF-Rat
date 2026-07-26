"""Minimal privileged broker service protocol over a Unix domain socket.

Deploy this process under a broker-owned OS identity with
``RAT_BROKER_KEY_PATH`` pointing to a broker-only file.  Agents receive only
the socket path; peer credentials are checked before any task is loaded.
"""
from __future__ import annotations
import json, os, socket, struct

from .broker import run_task
from .orchestration import GateError, record_verification_from_receipt

MAX_REQUEST=1024*1024

def _peer_uid(conn):
    try:
        raw=conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i"))
        return struct.unpack("3i",raw)[1]
    except (AttributeError,OSError) as exc: raise GateError("broker service requires SO_PEERCRED support") from exc

def _recv(conn):
    data=b""
    while not data.endswith(b"\n"):
        piece=conn.recv(min(65536,MAX_REQUEST-len(data)+1))
        if not piece: break
        data+=piece
        if len(data)>MAX_REQUEST: raise GateError("broker request exceeds maximum size")
    try: request=json.loads(data.decode())
    except (UnicodeDecodeError,json.JSONDecodeError) as exc: raise GateError("invalid broker request") from exc
    return request

def _handle(conn, *, allowed_uid, ctf_home):
    if _peer_uid(conn)!=allowed_uid: raise GateError("broker client UID is not allowed")
    request=_recv(conn)
    if not isinstance(request,dict) or set(request)-{"action","task_id","root","argv","inputs","bindings","wall_seconds","receipt_digest","evidence_ids"}:
        raise GateError("invalid broker request fields")
    root=os.path.abspath(request.get("root") or "")
    home=os.path.abspath(ctf_home)
    if not root or os.path.commonpath([home,root])!=home: raise GateError("broker root is outside CTF_HOME")
    if request.get("action","tool-run")=="verify-promote":
        return record_verification_from_receipt(root,request.get("receipt_digest",""),request.get("evidence_ids",[]))
    if request.get("action","tool-run")!="tool-run": raise GateError("unknown broker request action")
    raw_bindings=request.get("bindings") or {}
    try: bindings={int(index):digest for index,digest in raw_bindings.items()}
    except (AttributeError,ValueError) as exc: raise GateError("broker request bindings are invalid") from exc
    result=run_task(root,request.get("task_id",""),request.get("argv"),inputs=request.get("inputs",[]),bindings=bindings,ctf_home=home,wall_seconds=request.get("wall_seconds"))
    return result

def serve(socket_path, *, allowed_uid, ctf_home, once=False, socket_mode=0o600):
    path=os.path.abspath(socket_path); parent=os.path.dirname(path); os.makedirs(parent,mode=0o700,exist_ok=True)
    if os.path.lexists(path): raise GateError("broker socket path already exists")
    if not isinstance(socket_mode,int) or socket_mode not in {0o600,0o660}: raise GateError("broker socket mode must be 0600 or 0660")
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        listener.bind(path); os.chmod(path,socket_mode); listener.listen(16)
        while True:
            conn,_=listener.accept()
            with conn:
                try: response={"ok":True,"result":_handle(conn,allowed_uid=allowed_uid,ctf_home=ctf_home)}
                except (GateError,OSError,ValueError,TypeError,json.JSONDecodeError) as exc: response={"ok":False,"error":str(exc)}
                conn.sendall(json.dumps(response,sort_keys=True,separators=(",",":")).encode()+b"\n")
            if once: return
    finally:
        listener.close()
        try: os.unlink(path)
        except FileNotFoundError: pass

def request(socket_path, payload):
    data=json.dumps(payload,sort_keys=True,separators=(",",":")).encode()+b"\n"
    if len(data)>MAX_REQUEST: raise GateError("broker request exceeds maximum size")
    conn=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        conn.connect(socket_path); conn.sendall(data); response=_recv(conn)
    except OSError as exc: raise GateError("broker service is unavailable") from exc
    finally: conn.close()
    if not response.get("ok"): raise GateError("broker service denied request: "+str(response.get("error","unknown error")))
    return response["result"]
