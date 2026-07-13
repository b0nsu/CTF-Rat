# Source Generated with Decompyle++
# File: model.pyc (Python 3.12)

from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import json
import uuid
RESOURCE_TYPES = [
    'Namespace',
    'Node',
    'Deployment',
    'Pod',
    'Service',
    'Ingress',
    'Secret',
    'ConfigMap']
DEFAULT_PROPS = {
    'Namespace': {
        'namespace': '',
        'labels': '',
        'selector': '',
        'replicas': 1,
        'port': 0,
        'mount': '' },
    'Node': {
        'namespace': '',
        'labels': '',
        'selector': '',
        'replicas': 1,
        'port': 0,
        'mount': '' },
    'Deployment': {
        'namespace': 'core-plane',
        'labels': 'app=reconciler',
        'selector': '',
        'replicas': 1,
        'port': 0,
        'mount': '' },
    'Pod': {
        'namespace': 'core-plane',
        'labels': 'tier=control',
        'selector': '',
        'replicas': 1,
        'port': 0,
        'mount': '' },
    'Service': {
        'namespace': 'edge-mesh',
        'labels': '',
        'selector': 'tier=control',
        'replicas': 1,
        'port': 80,
        'mount': '' },
    'Ingress': {
        'namespace': 'edge-mesh',
        'labels': '',
        'selector': '',
        'replicas': 1,
        'port': 443,
        'mount': '' },
    'Secret': {
        'namespace': 'core-plane',
        'labels': '',
        'selector': '',
        'replicas': 1,
        'port': 0,
        'mount': '' },
    'ConfigMap': {
        'namespace': 'core-plane',
        'labels': '',
        'selector': '',
        'replicas': 1,
        'port': 0,
        'mount': '' } }
NodeModel = <NODE:12>()
EdgeModel = <NODE:12>()
ProjectModel = <NODE:12>()
