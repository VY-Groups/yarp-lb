# GatewayCore disposable testing server (NOT production)
This builds the **real .NET 10 GatewayCore YARP application** and runs two gateway
containers, two disposable HTTP backends, and an nginx ingress on one Docker host.
It intentionally reuses the tested `tests/CI/stack/Dockerfile.gateway`,
`entrypoint.sh`, `ingress.conf`, and `backend.py` from this Git revision.
There is **no mocked gateway**. This setup is a single-host functional laboratory,
not two physically independent HA hosts and not a production installation.

## Requirements and install on Ubuntu test host
- Docker Engine + Docker Compose v2, OpenSSL, curl, git, build network access to
  .NET container images and NuGet dependencies; free ports 18080 and 18443.
- A dedicated **nonproduction** Docker host. Build pulls external images and
  creates Docker volumes; do not use real CA credentials, real production keys,
  or actual production traffic.
- Checkout the reviewed Git SHA or the testing PR branch and run:

```bash
git clone "$REPOSITORY_URL"
cd yarp-lb
git fetch origin refactor/neutral-gateway-branding-20261114
git checkout refactor/neutral-gateway-branding-20261114
bash ops/test-server/install.sh
bash ops/test-server/smoke.sh
docker compose -f ops/test-server/compose.yml ps
```

Installer defaults to **loopback-only** HTTP :18080 and HTTPS :18443. The latter
uses a generated seven-day local ECDSA P-256 certificate trusted only via the
`--cacert` switch; **never use `curl -k` for acceptance evidence**. The
management and Prometheus endpoints must return HTTP 403 through ingress.

## Traffic generation
Install the `oha` tool on the generator host; do not run sustained load on
the same CPU as the gateway if measuring gateway limits. Begin with:

```bash
curl --noproxy '*' http://127.0.0.1:18080/api/identity
oha -z 30s -q 100 -c 20 --no-tui http://127.0.0.1:18080/api/identity
oha -z 30s -q 50 -c 20 --no-tui http://127.0.0.1:18080/api/body/1048576
```

For another trusted generator on a test VLAN, set `TEST_BIND_IP` to the
**specific test-server LAN IPv4 address** before installation, not 0.0.0.0:
`TEST_BIND_IP=192.0.2.10 bash ops/test-server/install.sh`. Replace that
documentation-only address with the actual test-server interface. Firewall
port 18080 strictly to the generator IPs; HTTPS 18443 remains loopback-only.
Remote generator: `oha -z 30s -q 100 -c 20 --no-tui
http://TEST_SERVER_IP:18080/api/identity`. Use explicit TLS cert/SAN provisioning
before remote HTTPS tests rather than disabling certificate verification.

## Inspection and removal
```bash
docker compose -f ops/test-server/compose.yml logs --tail=100 gateway-a gateway-b ingress
docker compose -f ops/test-server/compose.yml down
```

`down` preserves state volumes. To delete **test-only** state after
verifying no needed evidence remains: `docker compose -f
ops/test-server/compose.yml down --volumes`. Do not delete volumes on an
existing production system. Preserve raw generator JSON, source SHA, CPU/NIC
counters, and the test-server topology with your results.

**Status:** This installer is a staged test kit. Docker compose smoke and
application functionality still require execution on the target host.
Any 30-second result cannot replace the required physical 60-minute per-node
capacity tests, independent-host failover tests, PKI and CAB signoff.
