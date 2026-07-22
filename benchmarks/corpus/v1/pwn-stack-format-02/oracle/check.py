#!/usr/bin/env python3
import sys
from pathlib import Path
challenge = Path(__file__).parents[1].name
raise SystemExit(0 if sys.stdin.read() == f"verified:{challenge}\n" else 1)
