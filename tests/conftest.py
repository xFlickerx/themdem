"""Make the repository root and the tests directory importable."""

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TESTS = os.path.dirname(os.path.abspath(__file__))

for path in (_ROOT, _TESTS):
    if path not in sys.path:
        sys.path.insert(0, path)
