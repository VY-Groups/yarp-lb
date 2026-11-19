#!/usr/bin/env python3
"""Apply a per-process file-size cap, then exec the bounded trace collector."""
from __future__ import annotations

import os
import resource
import sys


def main() -> int:
    if len(sys.argv) < 3:
        raise SystemExit("usage: trace_exec.py MAX_FILE_BYTES COMMAND [ARG ...]")
    maximum = int(sys.argv[1])
    if maximum <= 0:
        raise SystemExit("MAX_FILE_BYTES must be positive")
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    limit = maximum if hard == resource.RLIM_INFINITY else min(maximum, hard)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    os.execvp(sys.argv[2], sys.argv[2:])
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
