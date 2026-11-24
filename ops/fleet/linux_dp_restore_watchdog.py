#!/usr/bin/env python3
"""Fail-closed, continuously reattested offline DP restore process supervisor.

This guards the *real* Linux .NET restore subprocess during an approved Raft
epoch. Losing quorum, changing epoch or running out of bounded lease runway
kills the entire private process group; it never authorizes service promotion,
unmasking or reuse of a possibly installed offline ring. No automatic lease
renewal occurs. A separate issuer with independent RBAC must authorize each
new recovery attempt.
"""
import math
import os
import signal
import subprocess
import time

CHECK_INTERVAL = 1.0
MIN_RUNWAY_SECONDS = 5.0
MAX_RUNTIME_SECONDS = 180.0


def _attest(fence, verify_receipts, phase):
    if fence.current(phase) is not True:
        raise ValueError("independent Raft recovery authority revoked")
    if verify_receipts() is not True:
        raise ValueError("signed two-node writer receipts rejected")
    remaining = fence.remaining_seconds()
    if (type(remaining) not in (float, int) or
            not math.isfinite(remaining) or
            remaining <= MIN_RUNWAY_SECONDS):
        raise ValueError("insufficient pinned recovery epoch runway")
    return remaining


def _kill_group(process):
    # The worker is always launched in a new process session so any helper
    # children are killed too. Never send a signal to the gateway service.
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)


def run_fenced_restore(command, environment, fence, verify_receipts,
                       limit_seconds, *, spawn=subprocess.Popen):
    """Run a signed offline restore, with live quorum/receipt checks <=1s.

    A nonzero exit always refuses. A partially created offline ring stays
    quarantined; cleanup of secrets and all site promotion are NOT authorized
    by this function. Neither the command nor its environment is logged.
    """
    if (type(command) is not list or not command or
            any(type(x) is not str or not x for x in command) or
            type(environment) is not dict or
            type(limit_seconds) not in (float, int) or
            not math.isfinite(limit_seconds) or
            not 0 < limit_seconds <= MAX_RUNTIME_SECONDS):
        raise ValueError("invalid bounded signed restore execution contract")
    # Authenticate immediately before creating the process, not only at the
    # earlier receiver preflight or snapshot transfer boundaries.
    remaining = _attest(fence, verify_receipts, "before-signed-restore")
    if limit_seconds + MIN_RUNWAY_SECONDS > remaining:
        limit_seconds = max(1.0, remaining - MIN_RUNWAY_SECONDS)
    begun = time.monotonic()
    process = spawn(command, shell=False, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    env=environment, start_new_session=True)
    try:
        while True:
            left = min(limit_seconds - (time.monotonic() - begun),
                       fence.remaining_seconds() - MIN_RUNWAY_SECONDS)
            if left <= 0:
                raise ValueError("bounded signed restore deadline exhausted")
            try:
                result = process.wait(timeout=min(CHECK_INTERVAL, left))
            except subprocess.TimeoutExpired:
                _attest(fence, verify_receipts, "before-signed-restore")
                continue
            if result != 0:
                raise ValueError("independent signed .NET snapshot restore refused")
            # The caller will perform its own post-restore quorum check,
            # encrypted-ring validation, and binary hash verification.
            _attest(fence, verify_receipts, "after-signed-restore")
            return result
    except BaseException:
        _kill_group(process)
        raise
    finally:
        _kill_group(process)
