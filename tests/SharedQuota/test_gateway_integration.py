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
    # Probe direct process health; this endpoint bypasses the proxy quota.
    for host in gateways:
        for attempt in range(60):
            try:
                with urllib.request.urlopen(f"http://{host}:8080/gateway/health", timeout=3) as response:
                    if response.status == 200:
                        break
            except Exception:
                pass
            time.sleep(1)
        else:
            raise RuntimeError(f"{host} failed to start")

    statuses = []
    for index in range(12):
        statuses.append(request(gateways[index % 2]))
    assert statuses.count(200) == 7, f"expected 7 globally admitted requests: {statuses}"
    assert statuses.count(429) == 5, f"expected 5 globally rejected requests: {statuses}"
    print("PASS: 2 real gateway processes share exactly 7 permits, 5 requests rejected")

if __name__ == "__main__":
    main()
