#!/usr/bin/env python3
"""Real commercial-profile .NET gateway + disposable synthetic signing fixture.
Requires a network namespace containing only loopback; no license server,
internet, mocked APIs or external hosts. No production private keys.
"""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import time

from real_control_center import Client, backend, check, eventually, gateway, openssl_state, port

def main():
    if os.environ.get("CI") != "true" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Disposable CI only")
    interfaces = subprocess.check_output(["ip", "-o", "link", "show"], text=True).splitlines()
    check(len(interfaces) == 1 and ": lo:" in interfaces[0], "network namespace contains only loopback")
    check(not subprocess.check_output(["ip", "route"], text=True).strip(), "no external network route")
    authority = Path(sys.argv[1]).resolve()
    cwd = Path("control-center").resolve()
    dll = cwd / "bin/Release/net10.0/GatewayCoreYarp.dll"
    fixture = Path("tests/OfflineLicensing/bin/Release/net10.0/OfflineLicensing.dll").resolve()

    def issue(action, arg, output):
        subprocess.run(["dotnet", str(fixture), action, str(authority), str(arg), str(output)], check=True)
        return output.read_text(encoding="ascii")

    with tempfile.TemporaryDirectory(prefix="commercial-no-egress-") as td, backend() as origin:
        root = Path(td)
        openssl_state(root, origin)
        env = os.environ.copy()
        env.pop("YARP_EC2_LAB_MODE", None)
        env.update(ASPNETCORE_ENVIRONMENT="Production", YARP_CONTROL_PLANE_DIR=str(root/"state"),
                   YARP_RUNTIME_CONFIG_PATH=str(root/"state/config/appsettings.json"),
                   YARP_LINUX_DP_CERT_PFX_PATH=str(root/"secrets/dp.pfx"),
                   YARP_LINUX_DP_CERT_PASSWORD_FILE=str(root/"secrets/dp-password"))
        subprocess.run(["dotnet", str(dll), "--license-init"], cwd=cwd, env=env, check=True)
        listen = port()
        user, password = "commercial_admin", "Commercial-fixture-secret-2026!"
        with gateway(cwd, dll, root, listen) as base:
            anonymous = Client(base)
            check("License Center" in anonymous.request("GET", "/dashboard/license"), "real License Center HTML")
            check("/admin/api/license/" in anonymous.request("GET", "/dashboard/license.js"), "real license frontend script")
            anonymous.request("GET", "/admin/api/license/status", expect=401)
            anonymous.request("GET", "/fixture/check", expect=503)
            admin = Client(base)
            admin.bootstrap(user, password, "commercial@example.invalid")
            check(admin.session()["commercial"] and not admin.session()["licenseActive"], "commercial fresh installation locked")
            admin.request("GET", "/admin/api/state", expect=402)
            admin.request("POST", "/admin/api/inventory", {"id":"blocked"}, expect=402)
            status = admin.request("GET", "/admin/api/license/status")
            check(status["state"] == "unactivated" and not status["trafficAdmitted"], "no unsigned default entitlement")
            request = root/"activation.gcr"
            request.write_text(admin.request("GET", "/admin/api/license/request")["file"], encoding="ascii")
            first = issue("--ci-issue", request, root/"first.lic")
            admin.request("POST", "/admin/api/license/import", {"file":first}, csrf=False, expect=403)
            tampered = first[:-2] + ("A" if first[-2] != "A" else "B") + first[-1]
            admin.request("POST", "/admin/api/license/import", {"file":tampered}, expect=400)
            anonymous.request("GET", "/fixture/check", expect=503)
            active = admin.request("POST", "/admin/api/license/import", {"file":first})
            check(active["active"] and active["edition"] == "standard", "real signed offline license activates gateway")
            check(admin.session()["licenseActive"], "session contract reports active license")
            check("fixture" in admin.request("GET", "/admin/api/state")["routes"], "management API unlocks after activation")
            check(not admin.request("GET", "/admin/api/inventory"), "pre-activation write was denied")
            admin.request("GET", "/admin/api/fleet", expect=402)
            admin.request("GET", "/admin/api/directory", expect=402)
            admin.request("GET", "/admin/api/audit", expect=402)
            admin.request("GET", "/admin/api/metrics")
            admin.request("GET", "/admin/api/tls/inventory")
            eventually(anonymous, "/fixture/check", "e2e-origin:/check")
            check(True, "actual YARP forwarding unlocks without external network")
        with gateway(cwd, dll, root, listen) as base:
            admin = Client(base)
            anonymous = Client(base)
            admin.login(user, password)
            check(admin.session()["licenseActive"], "offline license survives actual process restart")
            eventually(anonymous, "/fixture/check", "e2e-origin:/check")
            request = root/"renewal.gcr"
            request.write_text(admin.request("GET", "/admin/api/license/request")["file"], encoding="ascii")
            second = issue("--ci-issue", request, root/"renewal.lic")
            renewed = admin.request("POST", "/admin/api/license/import", {"file":second})
            check(renewed["revision"] == 2, "actual offline renewal advances revision")
            admin.request("POST", "/admin/api/license/import", {"file":first}, expect=400)
            eventually(anonymous, "/fixture/check", "e2e-origin:/check")
            request = root/"downgrade.gcr"
            request.write_text(admin.request("GET", "/admin/api/license/request")["file"], encoding="ascii")
            downgraded = issue("--ci-downgrade", request, root/"downgrade.lic")
            restricted = admin.request("POST", "/admin/api/license/import", {"file":downgraded})
            check(restricted["state"] == "feature-restricted" and not restricted["trafficAdmitted"],
                  "signed active downgrade removes L7 admission immediately")
            admin.request("GET", "/admin/api/state", expect=402)
            anonymous.request("GET", "/fixture/check", expect=503)
            admin.request("POST", "/admin/api/license/import", {"file":second}, expect=400)
            anonymous.request("GET", "/fixture/check", expect=503)
            check(True, "previously active L7 license cannot roll back signed downgrade")
        with gateway(cwd, dll, root, listen) as base:
            admin = Client(base)
            anonymous = Client(base)
            admin.login(user, password)
            persisted = admin.request("GET", "/admin/api/license/status")
            check(persisted["state"] == "feature-restricted" and not persisted["trafficAdmitted"],
                  "signed L7 downgrade survives actual process restart")
            admin.request("GET", "/admin/api/state", expect=402)
            anonymous.request("GET", "/fixture/check", expect=503)
            request = root/"upgrade.gcr"
            request.write_text(admin.request("GET", "/admin/api/license/request")["file"], encoding="ascii")
            upgraded = issue("--ci-upgrade", request, root/"upgrade.lic")
            forged_upgrade = upgraded[:-2] + ("A" if upgraded[-2] != "A" else "B") + upgraded[-1]
            admin.request("POST", "/admin/api/license/import", {"file":forged_upgrade}, expect=400)
            anonymous.request("GET", "/fixture/check", expect=503)
            restored = admin.request("POST", "/admin/api/license/import", {"file":upgraded})
            check(restored["revision"] == 4 and restored["trafficAdmitted"] and restored["maxNodes"] == 2,
                  "signed upgrade restores L7 and two managed gateway entitlements")
            plan = {"mode":"ha-pair","controlPlane":"single-controller","dataStore":"local-file",
                    "publicVip":"vip.example.invalid","upstreamHealthAware":True,
                    "gateways":[{"id":f"node-{i}","hostname":f"node-{i}.example.invalid",
                                  "agentUrl":f"https://node-{i}.example.invalid/"} for i in (1,2)],
                    "workloads":[{"id":f"origin-{i}","application":"synthetic","url":f"http://127.0.0.1:{18000+i}/",
                                  "zone":"public","hostingEngine":"http"} for i in (1,2)]}
            excess = dict(plan, mode="fleet", gateways=plan["gateways"] + [
                {"id":"node-3","hostname":"node-3.example.invalid","agentUrl":"https://node-3.example.invalid/"}])
            admin.request("POST", "/admin/api/onboarding/validate", {"plan":excess}, expect=402)
            check(admin.request("POST", "/admin/api/onboarding/validate", {"plan":plan})["issues"]==[],
                  "two-node topology within signed entitlement")
            revision = admin.request("GET", "/admin/api/onboarding")["revision"]
            admin.request("POST", "/admin/api/onboarding", {"plan":excess,"confirmDesign":True,
                          "expectedRevision":revision}, expect=402)
            admin.request("POST", "/admin/api/onboarding", {"plan":plan,"confirmDesign":True,
                          "expectedRevision":revision})
            def fleet_row(i):
                return {"id":f"node-{i}","url":f"https://node-{i}.example.invalid/",
                        "clientCertificateThumbprint":"A"*40}
            for i in (1,2):
                admin.request("POST", "/admin/api/fleet", fleet_row(i))
            admin.request("POST", "/admin/api/fleet", fleet_row(3), expect=402)
            check(len(admin.request("GET", "/admin/api/fleet"))==2,"excess local fleet registration denied")
            eventually(anonymous, "/fixture/check", "e2e-origin:/check")
            short_request = root/"short.gcr"
            short_request.write_text(admin.request("GET", "/admin/api/license/request")["file"], encoding="ascii")
            short = issue("--ci-short-renew", short_request, root/"short.lic")
            short_state=admin.request("POST", "/admin/api/license/import", {"file":short})
            check(short_state["revision"]==5 and short_state["trafficAdmitted"],"short signed entitlement initially active")
            # Use the signed UTC deadline; tolerate CI scheduling delay without
            # weakening the expected 503 immediately after expiration.
            from datetime import datetime, timezone
            expiry=datetime.fromisoformat(short_state["expiresAt"].replace("Z","+00:00"))
            time.sleep(max(0,(expiry-datetime.now(timezone.utc)).total_seconds())+0.3)
            anonymous.request("GET", "/fixture/check", expect=503)
            admin.request("GET", "/admin/api/state", expect=402)
            check(not admin.request("GET", "/admin/api/license/status")["trafficAdmitted"],"signed expiry fences new traffic")
            resume_request=root/"resume.gcr"
            resume_request.write_text(admin.request("GET", "/admin/api/license/request")["file"], encoding="ascii")
            resumed=issue("--ci-resume",resume_request,root/"resume.lic")
            check(admin.request("POST", "/admin/api/license/import", {"file":resumed})["revision"]==6,
                  "signed renewal recovers expired installation")
            eventually(anonymous, "/fixture/check", "e2e-origin:/check")
            revoked = issue("--ci-revoke", renewed["allocationId"], root/"revocation.gcv")
            state = admin.request("POST", "/admin/api/license/revoke", {"file":revoked})
            check(state["state"] == "revoked" and not state["active"] and not state["trafficAdmitted"],
                  "explicit signed revocation denies management and new traffic")
            admin.request("GET", "/admin/api/state", expect=402)
            admin.request("POST", "/admin/api/license/import", {"file":second}, expect=400)
            anonymous.request("GET", "/fixture/check", expect=503)
            check(True, "revocation fences new requests in already-running process")
            missing="/admin/api/fleet/rollouts/rollout_"+"A"*24+"/recover"
            admin.request("GET","/admin/api/fleet/rollouts")
            admin.request("POST",missing,{},expect=404)
            admin.request("POST",missing,{},csrf=False,expect=403)
            Client(base).request("GET","/admin/api/fleet/rollouts",expect=401)
            admin.request("POST","/admin/api/fleet/rollout/change-20260101T0000000000000Z-AAAAAAAAAA",{},expect=402)
            check(True,"revoked controller permits only authenticated CSRF-protected journal recovery")
        with gateway(cwd, dll, root, listen) as base:
            admin = Client(base)
            admin.login(user, password)
            check(admin.request("GET", "/admin/api/license/status")["state"] == "revoked", "revoked state survives restart")
            admin.request("GET", "/admin/api/state", expect=402)
            Client(base).request("GET", "/fixture/check", expect=503)
            check(True, "fresh revoked process cannot admit traffic")
            admin.request("GET","/admin/api/fleet/rollouts")
            admin.request("POST","/admin/api/fleet/rollouts/rollout_"+"A"*24+"/recover",{},expect=404)
            admin.request("GET","/admin/api/fleet",expect=402)
            check(True,"journal recovery remains accessible after revoked controller restart")
    print("OFFLINE_COMMERCIAL_GATEWAY_ACCEPTANCE_PASS", flush=True)

if __name__ == "__main__":
    main()
