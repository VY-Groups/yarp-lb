#!/usr/bin/env python3
"""Summarize exact-base vs candidate GatewayLab allocation pairs."""
import json
import statistics
import sys
from pathlib import Path


def load_sample(path: Path) -> dict:
    report = json.loads((path / "report.json").read_text(encoding="utf-8"))
    if report.get("samplePairs") != 1 or report.get("requestsPerMode") != 10_000:
        raise ValueError(f"{path}: unexpected workload shape")
    pair = report["paired"][0]
    for mode in ("telemetryDisabled", "telemetryEnabled"):
        sample = pair[mode]
        if sample["gatewayAllocatedBytes"] <= 0 or sample["requestsPerSecond"] <= 0:
            raise ValueError(f"{path}: invalid {mode} sample")
    enabled = pair["telemetryEnabled"]
    if any(enabled["collectorRequestsAfterDrain"][signal] < 1 for signal in ("traces", "metrics", "logs")):
        raise ValueError(f"{path}: telemetry-enabled sample failed to drain all signals")
    return {"sourceCommit": report["sourceCommit"], "os": report["os"],
            "enabled": enabled, "disabled": pair["telemetryDisabled"]}


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: compare_paired.py <artifact-root> <base-sha> <candidate-sha>", file=sys.stderr)
        return 64
    root, base_sha, candidate_sha = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
    pairs = []
    for index in range(1, 4):
        before = load_sample(root / f"pair-{index}-before")
        after = load_sample(root / f"pair-{index}-after")
        if before["sourceCommit"] != base_sha or after["sourceCommit"] != candidate_sha:
            raise ValueError(f"pair {index}: report source SHA did not match pinned revisions")
        if before["os"] != after["os"]:
            raise ValueError(f"pair {index}: OS context differed inside pair")
        before_alloc = before["enabled"]["gatewayAllocatedBytesPerRequest"]
        after_alloc = after["enabled"]["gatewayAllocatedBytesPerRequest"]
        before_rps = before["enabled"]["requestsPerSecond"]
        after_rps = after["enabled"]["requestsPerSecond"]
        before_p95 = before["enabled"]["p95Milliseconds"]
        after_p95 = after["enabled"]["p95Milliseconds"]
        pairs.append({"pair": index, "os": before["os"],
                      "beforeBytesPerRequest": before_alloc,
                      "afterBytesPerRequest": after_alloc,
                      "allocationDeltaBytesPerRequest": round(after_alloc - before_alloc, 3),
                      "allocationDeltaPercent": round((after_alloc / before_alloc - 1) * 100, 3),
                      "beforeRps": before_rps, "afterRps": after_rps,
                      "beforeP95Ms": before_p95, "afterP95Ms": after_p95})
    deltas = [pair["allocationDeltaBytesPerRequest"] for pair in pairs]
    report = {"benchmark": "full YARP GatewayLab to two local BackendLab processes",
              "baseSha": base_sha, "candidateSha": candidate_sha,
              "pairs": pairs,
              "medianAllocationDeltaBytesPerRequest": round(statistics.median(deltas), 3),
              "allocationDeltaRangeBytesPerRequest": [min(deltas), max(deltas)],
              "interpretation": "CI loopback allocation diagnostic only; three pairs are not production capacity evidence"}
    (root / "paired-comparison.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    if statistics.median(deltas) >= 0:
        raise ValueError("candidate had no median measured allocation reduction across three pairs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
