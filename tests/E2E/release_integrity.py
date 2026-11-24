#!/usr/bin/env python3
"""Actual published commercial binary inventory enforcement using disposable keys."""
import os
import subprocess
import tempfile
from pathlib import Path

assert os.environ.get("CI") == "true" and os.environ.get("GITHUB_ACTIONS") == "true"
root=Path.cwd()
fixture=root/"tests/OfflineLicensing/bin/Release/net10.0/OfflineLicensing.dll"
project=root/"control-center/GatewayCoreYarp.csproj"
commit=os.environ["GITHUB_SHA"]
def run(args):
    subprocess.run(["dotnet",*map(str,args)],check=True)
def expect(args,code,marker):
    r=subprocess.run(["dotnet",*map(str,args)],capture_output=True,text=True,timeout=60)
    if r.returncode != code or marker not in r.stdout+r.stderr:
        raise AssertionError(f"Unexpected exit {r.returncode}: {r.stdout} {r.stderr}")
    print("PASS:",marker,flush=True)
with tempfile.TemporaryDirectory(prefix="gc-release-fixture-") as td:
    folder=Path(td)
    entitlement=folder/"entitlement.json"
    release=folder/"release"
    package=folder/"package"
    run([fixture,"--ci-trust",entitlement])
    run([fixture,"--ci-release-key",release])
    publish=["publish",project,"--configuration","Release","--output",package,
             "-p:GatewayCoreCommercial=true",f"-p:GatewayCoreTrustFile={entitlement}",
             "-p:GatewayCoreReleasePackage=true",f"-p:GatewayCoreReleaseTrustFile={release/'release-trust.json'}",
             f"-p:GatewayCoreReleaseSourceCommit={commit}"]
    run(publish)
    dll=package/"GatewayCoreYarp.dll"
    expect([dll,"--verify-release"],78,"Commercial package integrity rejected")
    run([fixture,"--ci-release-manifest",release,package,commit])
    expect([dll,"--verify-release"],0,"COMMERCIAL_RELEASE_INTEGRITY_PASS "+commit)
    injected=package/"injected.txt"
    injected.write_text("disposable unsigned file")
    expect([dll,"--license-init"],78,"Commercial package integrity rejected")
    injected.unlink()
    asset=package/"wwwroot/style.css"
    original=asset.read_bytes()
    asset.write_bytes(original+b"\nmodified")
    expect([dll,"--verify-release"],78,"Commercial package integrity rejected")
    asset.write_bytes(original)
    expect([dll,"--verify-release"],0,"COMMERCIAL_RELEASE_INTEGRITY_PASS "+commit)
    manifest=package/"gatewaycore.integrity"
    manifest.unlink()
    expect([dll,"--verify-release"],78,"Commercial package integrity rejected")
    # A commercial publish without the mandatory release profile must fail.
    bad=subprocess.run(["dotnet","publish",str(project),"--configuration","Release",
                         "--output",str(folder/"unsigned"),"-p:GatewayCoreCommercial=true",
                         f"-p:GatewayCoreTrustFile={entitlement}"],capture_output=True,text=True)
    if bad.returncode==0 or "Commercial publishing requires" not in bad.stdout+bad.stderr:
        raise AssertionError("Unsigned commercial publish not rejected")
    print("COMMERCIAL_RELEASE_PACKAGE_ACCEPTANCE_PASS",flush=True)
