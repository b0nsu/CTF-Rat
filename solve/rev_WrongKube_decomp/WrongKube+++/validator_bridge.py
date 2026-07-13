# Source Generated with Decompyle++
# File: validator_bridge.pyc (Python 3.12)

from __future__ import annotations
from ctypes import CDLL, c_char_p, c_void_p
from pathlib import Path
import ctypes
import json
import platform
import subprocess
import sys
from model import ProjectModel
if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    ROOT = Path(sys._MEIPASS)
else:
    ROOT = Path(__file__).resolve().parent.parent
BUILD_DIR = ROOT / 'build'
SOURCE_FILE = ROOT / 'src' / 'challenge_core.c'

def _library_path():
    if platform.system() == 'Windows':
        return BUILD_DIR / 'wrongkube_validator.dll'
    if None.system() == 'Darwin':
        return BUILD_DIR / 'libwrongkube_validator.dylib'
    return None / 'libwrongkube_validator.so'


def ensure_library():
    BUILD_DIR.mkdir(parents = True, exist_ok = True)
    lib_path = _library_path()
    if getattr(sys, 'frozen', False):
        if lib_path.exists():
            return lib_path
        raise None(f'''Bundled validator library is missing: {lib_path}''')
    if lib_path.exists() and SOURCE_FILE.exists() and lib_path.stat().st_mtime >= SOURCE_FILE.stat().st_mtime:
        return lib_path
    if None.system() == 'Windows':
        raise RuntimeError('Windows build is not available in this environment. Compile challenge_core.c with MinGW or MSVC.')
    cmd = [
        'gcc',
        '-shared',
        '-O2',
        '-fPIC',
        str(SOURCE_FILE),
        '-o',
        str(lib_path)]
    subprocess.run(cmd, cwd = ROOT, check = True)
    return lib_path


def _encode_project(project = None):
    payload = {
        'nodes': [],
        'edges': [] }
    for node in project.nodes:
        if not node.props.get('replicas', 1):
            node.props.get('replicas', 1)
        if not node.props.get('port', 0):
            node.props.get('port', 0)
        payload['nodes'].append({
            'id': node.id,
            'type': node.resource_type,
            'name': node.name,
            'namespace': str(node.props.get('namespace', '')),
            'labels': str(node.props.get('labels', '')),
            'selector': str(node.props.get('selector', '')),
            'replicas': int(1),
            'port': int(0),
            'mount': str(node.props.get('mount', '')) })
    for edge in project.edges:
        payload['edges'].append({
            'source_id': edge.source_id,
            'target_id': edge.target_id,
            'binding': edge.binding,
            'role': edge.role,
            'port': edge.port })
    return json.dumps(payload, separators = (',', ':')).encode('utf-8')


class HiddenValidator:

    def __init__(self = None):
        lib_path = ensure_library()
        self.lib = CDLL(str(lib_path))
        self.lib.validate_cluster.argtypes = [
            c_char_p]
        self.lib.validate_cluster.restype = c_void_p
        self.lib.free_result.argtypes = [
            c_void_p]
        self.lib.free_result.restype = None


    def validate(self = None, project = None):
        raw = self.lib.validate_cluster(_encode_project(project))
        if not raw:
            return {
                'ok': False,
                'summary': 'validator returned no data',
                'flag': '',
                'score': 0 }
        text = None.string_at(raw).decode('utf-8', errors = 'replace')
        self.lib.free_result(raw)
        return json.loads(text)
