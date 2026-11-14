#!/usr/bin/env python3
"""Disposable REAL GatewayCore server for Playwright browser acceptance.
Only accepts GitHub Actions CI, binds 127.0.0.1, never touches user state.
"""
import argparse
import os
from pathlib import Path
import tempfile
import time
from real_control_center import backend, openssl_state, gateway

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,default=Path("../../control-center"))
    args=p.parse_args()
    if os.environ.get("CI")!="true" or os.environ.get("GITHUB_ACTIONS")!="true":
        raise SystemExit("Refusing to start browser fixture outside disposable CI")
    cwd=args.root.resolve()
    dll=cwd/"bin"/"Release"/"net10.0"/"GatewayCoreYarp.dll"
    if not dll.is_file():
        raise SystemExit("Missing shipping binary; compile first: "+str(dll))
    with tempfile.TemporaryDirectory(prefix="gatewaycore-browser-e2e-") as td, backend() as origin:
        root=Path(td)
        openssl_state(root,origin)
        with gateway(cwd,dll,root,18889) as base:
            print("BROWSER_READY "+base,flush=True)
            while True: time.sleep(1)

if __name__=="__main__":
    main()
