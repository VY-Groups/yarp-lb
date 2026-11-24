#!/usr/bin/env python3
"""Real commercial-profile .NET gateway + private disposable issuer.
Requires a network namespace containing only loopback; no license server,
internet, mocked APIs or external hosts. No production private keys.
"""
from pathlib import Path
import os
import subprocess
import sys
import tempfile

from real_control_center import Client, backend, check, eventually, gateway, openssl_state, port

def main():
    if os.environ.get("CI") != "true" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Disposable CI only")
    check(sorted(os.listdir("/sys/class/net")) == ["lo"], "network namespace contains only loopback")
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
            check("license/import" in anonymous.request("GET", "/dashboard/license.js"), "real license frontend script")
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
            revoked = issue("--ci-revoke", renewed["allocationId"], root/"revocation.gcv")
            state = admin.request("POST", "/admin/api/license/revoke", {"file":revoked})
            check(state["state"] == "revoked" and not state["active"], "actual offline revocation denies management")
            admin.request("GET", "/admin/api/state", expect=402)
            admin.request("POST", "/admin/api/license/import", {"file":second}, expect=400)
            eventually(anonymous, "/fixture/check", "e2e-origin:/check")
            check(True, "running process preserves previously admitted traffic on revocation")
        with gateway(cwd, dll, root, listen) as base:
            admin = Client(base)
            admin.login(user, password)
            check(admin.request("GET", "/admin/api/license/status")["state"] == "revoked", "revoked state survives restart")
            admin.request("GET", "/admin/api/state", expect=402)
            Client(base).request("GET", "/fixture/check", expect=503)
            check(True, "fresh revoked process cannot admit traffic")
    print("OFFLINE_COMMERCIAL_GATEWAY_ACCEPTANCE_PASS", flush=True)

if __name__ == "__main__":
    main()
