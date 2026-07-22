#!/usr/bin/env python3
import sys
from pathlib import Path
challenge = Path(__file__).parents[1].name
if sys.stdin.read() == f"solve:{challenge}\n":
    print(f"verified:{challenge}")
    raise SystemExit(0)
print("failed")
raise SystemExit(1)
