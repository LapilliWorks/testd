#!/usr/bin/env python3

from pathlib import Path
from runpy import run_path

if __name__ == '__main__':
	script = Path(__file__).resolve().with_name('test_platform.py')
	raise SystemExit(run_path(str(script))['main']('Linux'))
