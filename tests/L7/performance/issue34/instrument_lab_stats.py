#!/usr/bin/env python3
"""Apply the same diagnostics-only GC-pause counter overlay to both checkouts."""
from __future__ import annotations

import argparse
from pathlib import Path


ANCHOR = "    gc2Collections = GC.CollectionCount(2),\n"
ADDITION = "    gcPauseTimeMs = GC.GetTotalPauseDuration().TotalMilliseconds,\n"
METRIC_CALL = "GatewayOpenTelemetry.RecordProxyResult(ctx, elapsedMs);"
METRIC_CALL_WITH_DIMENSIONS = """var feature = ctx.GetReverseProxyFeature();
                GatewayOpenTelemetry.RecordProxyResult(ctx, elapsedMs,
                    feature.Route.Config.RouteId, feature.Cluster.Config.ClusterId,
                    feature.ProxiedDestination?.DestinationId);"""


def instrument(source: Path) -> None:
    path = source / "tests/L7/GatewayLab/Program.cs"
    text = path.read_text(encoding="utf-8")
    if ADDITION not in text:
        if text.count(ANCHOR) != 1:
            raise ValueError(f"expected exactly one lab stats anchor in {path}")
        text = text.replace(ANCHOR, ANCHOR + ADDITION, 1)

    api_available = (source / "control-center/GatewayOpenTelemetry.cs").is_file()
    old_calls = text.count(METRIC_CALL)
    dimension_calls = text.count(METRIC_CALL_WITH_DIMENSIONS)
    if old_calls == 1 and dimension_calls == 0:
        text = text.replace(METRIC_CALL, METRIC_CALL_WITH_DIMENSIONS, 1)
    elif old_calls == 0 and dimension_calls == 1:
        pass  # idempotent re-application to a dimension-aware overlay
    elif old_calls == 0 and dimension_calls == 0 and not api_available:
        # The documented d2b historical workflow_dispatch baseline predates
        # OTEL. It still receives the identical GC-pause counter overlay.
        pass
    else:
        raise ValueError(f"expected one proxy result metric call in {path}; "
                         f"old={old_calls}, dimension-aware={dimension_calls}, "
                         f"OTEL API present={api_available}")
    path.write_text(text, encoding="utf-8")


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
