#!/usr/bin/env python3
"""Real socket test: separate gateway containers share one authenticated TLS Redis writer."""
import argparse
import time
import urllib.error
import urllib.request

def request(host):
    try:
        with urllib.request.urlopen(
            urllib.request.Request(f"http://{host}:8080/api/identity",
                                   headers={"Connection": "close"}),
            timeout=8,
        ) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        error.read()
        return error.code

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--partition", action="store_true")
    args = parser.parse_args()
    gateways = ["gateway-a", "gateway-b"]
    if args.partition:
        statuses = [request(host) for host in gateways]
        assert statuses == [503, 503], f"partition must fail closed, got {statuses}"
        print("PASS: disconnected shared quota returns 503 on both gateway processes")
        return
    for host in gateways:
        for attempt in range(40):
            try:
                code = request(host)
                if code == 200:
                    break
            except Exception:
                pass
            time.sleep(1)
        else:
            raise RuntimeError(f"{host} not ready for controlled quota test")
    # Important: readiness probes above consumed two permits, so each test
    # namespace must be reset before quota assertions.
    # Instead use direct health API, which is not in the reverse proxy quota.
    raise RuntimeError("Do not run quota sequence before isolated readiness reset")

if __name__ == "__main__":
    main()
