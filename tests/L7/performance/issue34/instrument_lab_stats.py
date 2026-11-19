#!/usr/bin/env python3
"""Apply the same diagnostics-only GC-pause counter overlay to both checkouts."""
from __future__ import annotations

import argparse
from pathlib import Path


ANCHOR = "    gc2Collections = GC.CollectionCount(2),\n"
ADDITION = "    gcPauseTimeMs = GC.GetTotalPauseDuration().TotalMilliseconds,\n"


def instrument(source: Path) -> None:
    path = source / "tests/L7/GatewayLab/Program.cs"
    text = path.read_text(encoding="utf-8")
    if ADDITION in text:
        return
    if text.count(ANCHOR) != 1:
        raise ValueError(f"expected exactly one lab stats anchor in {path}")
    path.write_text(text.replace(ANCHOR, ANCHOR + ADDITION, 1), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sources", type=Path, nargs="+")
    args = parser.parse_args()
    for source in args.sources:
        instrument(source)
    print(f"Applied diagnostics-only GC pause counter to {len(args.sources)} pinned checkouts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
