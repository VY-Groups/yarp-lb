#!/usr/bin/env python3
"""Fail-closed, per-node healthy-state audit metric verification.

No credentials, customer identifiers or fetched response bodies are printed.
This is an operator site check, not a claim of physical acceptance.
"""
import argparse
import json
import math
import os
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

METRICS = (
    "gateway_audit_outbox_enabled",
    "gateway_audit_outbox_pending",
    "gateway_audit_outbox_storage_fault",
    "gateway_audit_outbox_delivery_blocked",
    "gateway_audit_outbox_last_update_unixtime",
)
# A label-free OTLP instrument may still have a bounded standard
# resource identity and Prometheus scrape labels. Enumerate those explicitly;
# arbitrary route, cluster, destination or user-provided dimensions are NOT
# acceptable on these five audit outbox gauges, even without obvious PII.
ALLOWED_LABELS = frozenset((
    "__name__", "job", "instance", "service_instance_id", "service_name",
    "service_version", "service_namespace", "telemetry_sdk_name",
    "telemetry_sdk_language", "telemetry_sdk_version", "otel_scope_name",
    "otel_scope_version", "otel_scope_schema_url", "deployment_environment",
    "host_name",
))


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Prometheus redirect rejected")


def _unique_json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("ambiguous duplicate Prometheus JSON property")
        value[key] = item
    return value


def _api_url(base):
    uri = urlsplit(base)
    if (uri.scheme == "https" or
        (uri.scheme == "http" and uri.hostname in ("localhost", "127.0.0.1", "::1"))):
        if (uri.username is None and uri.password is None and uri.hostname and
            uri.path in ("", "/") and not uri.query and not uri.fragment):
            return base.rstrip("/") + "/api/v1/query"
    raise ValueError("Prometheus must use an HTTPS origin or loopback HTTP, without credentials or query")


def query_metrics(base, timeout=5):
    url = _api_url(base)
    opener = build_opener(ProxyHandler({}), NoRedirect())
    result = {}
    for name in METRICS:
        request = Request(url + "?" + urlencode({"query": name + '{job="otel-collector"}'}),
                          headers={"Accept": "application/json"})
        with opener.open(request, timeout=timeout) as reply:
            if reply.status != 200:
                raise ValueError("Prometheus query returned non-200")
            body = reply.read(256 * 1024 + 1)
            if len(body) > 256 * 1024:
                raise ValueError("Prometheus query response exceeds limit")
            result[name] = json.loads(body.decode("utf-8", "strict"),
                                      object_pairs_hook=_unique_json_object)
    return result


def verify(payloads, expected_nodes, now=None, maximum_age=180):
    now = time.time() if now is None else now
    expected = set(expected_nodes)
    if not expected or len(expected) != len(expected_nodes) or any(
            not isinstance(node, str) or not node or len(node) > 128 or
            any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-."
                for ch in node) for node in expected):
        raise ValueError("provide unique bounded expected service_instance_id values")

    for name in METRICS:
        data = payloads.get(name)
        if not isinstance(data, dict) or data.get("status") != "success":
            raise ValueError(name + ": missing or unsuccessful Prometheus query")
        obj = data.get("data")
        if not isinstance(obj, dict) or obj.get("resultType") != "vector" or not isinstance(
                obj.get("result"), list):
            raise ValueError(name + ": expected Prometheus instant vector")
        found = set()
        for row in obj["result"]:
            if not isinstance(row, dict) or not isinstance(row.get("metric"), dict):
                raise ValueError(name + ": invalid series")
            labels = row["metric"]
            node = labels.get("service_instance_id")
            if labels.get("job") != "otel-collector" or node not in expected or node in found:
                raise ValueError(name + ": wrong, unexpected or duplicate node series")
            if any(key not in ALLOWED_LABELS for key in labels):
                raise ValueError(name + ": unsupported or potentially private metric label")
            sample = row.get("value")
            if not isinstance(sample, list) or len(sample) != 2:
                raise ValueError(name + ": missing instant sample")
            stamp, raw = sample
            if type(stamp) not in (float, int) or isinstance(raw, bool):
                raise ValueError(name + ": invalid sample timestamp/value")
            try:
                value = float(raw)
            except (ValueError, TypeError):
                raise ValueError(name + ": invalid numeric value") from None
            if not math.isfinite(stamp) or not math.isfinite(value) or not value.is_integer():
                raise ValueError(name + ": nonfinite or noninteger gauge")
            if stamp > now + 30 or now - stamp > maximum_age:
                raise ValueError(name + ": stale or future sample")
            if ((name == "gateway_audit_outbox_enabled" and value != 1) or
                (name == "gateway_audit_outbox_pending" and not 0 <= value <= 4096) or
                (name.endswith(("storage_fault", "delivery_blocked")) and value != 0) or
                (name == "gateway_audit_outbox_last_update_unixtime" and
                 (value > now + 30 or now - value > 90))):
                raise ValueError(name + ": unhealthy or disabled audit state")
            found.add(node)
        if found != expected:
            raise ValueError(name + ": missing expected gateway series")
    return len(expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prom-url", default=os.environ.get("PROM_URL"))
    parser.add_argument("--expected-node", action="append", required=True,
                        help="Expected service_instance_id, repeat once per deployed gateway")
    parser.add_argument("--max-sample-age-seconds", type=int, default=180)
    args = parser.parse_args()
    try:
        if not args.prom_url or not 10 <= args.max_sample_age_seconds <= 900:
            raise ValueError("valid Prometheus URL and bounded sample age are required")
        count = verify(query_metrics(args.prom_url), args.expected_node,
                       maximum_age=args.max_sample_age_seconds)
    except (ValueError, UnicodeError, json.JSONDecodeError, HTTPError, URLError,
            TimeoutError, OSError) as error:
        # Error messages never include credentials, query values, event bodies
        # or the response JSON. The operator keeps private diagnostics off CI.
        parser.exit(1, "FAIL: audit metrics acceptance: " + error.__class__.__name__ + "\n")
    print(f"PASS: fresh healthy audit metrics for {count} expected gateway nodes")


if __name__ == "__main__":
    main()
