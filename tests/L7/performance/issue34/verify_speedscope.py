#!/usr/bin/env python3
"""Fail closed if a converted Speedscope trace has no reviewable stack samples.

JSON validity and nonzero file size are not allocation-stack evidence.
This verifies only Speedscope structure and nonempty stacks; it does not
attribute per-request allocations or certify an optimization.
"""
import argparse
import json
from pathlib import Path
import sys

MAX_JSON_BYTES = 512 * 1024 * 1024


def verify(path: Path) -> dict:
    size = path.stat().st_size
    if size < 2 or size > MAX_JSON_BYTES:
        raise ValueError("Speedscope trace missing or exceeds bounded size")
    with path.open("rb") as stream:
        document = json.load(stream)
    if not isinstance(document, dict):
        raise ValueError("Speedscope trace must be an object")
    shared = document.get("shared")
    frames = shared.get("frames") if isinstance(shared, dict) else None
    profiles = document.get("profiles")
    if not isinstance(frames, list) or not frames or not isinstance(profiles, list) or not profiles:
        raise ValueError("Speedscope trace has no shared frames or profiles")
    if any(not isinstance(f, dict) or not isinstance(f.get("name"), str) or not f["name"]
           for f in frames):
        raise ValueError("Speedscope frame names missing")
    frame_count = len(frames)

    def good_frame(index):
        return type(index) is int and 0 <= index < frame_count

    observed = 0
    for profile in profiles:
        if not isinstance(profile, dict):
            raise ValueError("Malformed Speedscope profile")
        kind = profile.get("type")
        if kind == "sampled":
            samples = profile.get("samples")
            if not isinstance(samples, list):
                raise ValueError("Missing sampled profile stacks")
            for sample in samples:
                if not isinstance(sample, list) or any(not good_frame(i) for i in sample):
                    raise ValueError("Invalid sampled profile frame reference")
                if sample:
                    observed += 1
        elif kind == "evented":
            events = profile.get("events")
            if not isinstance(events, list):
                raise ValueError("Missing evented profile events")
            for event in events:
                if (not isinstance(event, dict) or event.get("type") not in ("O", "C")
                        or not good_frame(event.get("frame"))):
                    raise ValueError("Invalid evented profile frame reference")
                if event["type"] == "O":
                    observed += 1
        else:
            raise ValueError("Unsupported Speedscope profile type")
    if observed == 0:
        raise ValueError("Speedscope conversion contains no stack observations")
    return {"profiles": len(profiles), "frames": frame_count, "stack_observations": observed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    args = parser.parse_args()
    try:
        stats = verify(args.trace)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        print("NO-GO: unusable Speedscope stack evidence: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(stats, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
