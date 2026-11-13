import http from 'k6/http';
import { check } from 'k6';
import { Counter, Trend, Rate } from 'k6/metrics';

const negotiatedTls = new Counter('lab_tls_negotiated_responses');

// Only on explicit long-soak jobs: one fixed Trend per five-minute window.
// This avoids unbounded response-path labels or gigabytes of per-request logs.
const soakOriginMs = Number(__ENV.SOAK_START_EPOCH_MS || '0');
const soakWindowSeconds = 300;
const soakWindows = soakOriginMs > 0
  ? Array.from({length: 48}, (_, index) => new Trend('soak_p99_5m_window_' + index))
  : [];
const soakFailures = soakOriginMs > 0
  ? Array.from({length: 48}, (_, index) => new Rate('soak_failure_rate_5m_window_' + index))
  : [];

const duration = __ENV.DURATION || '20s';
const vus = Number(__ENV.VUS || '75');
const labTls = __ENV.LAB_TLS === '1';
const payloadBytes = Number(__ENV.PAYLOAD_BYTES || '0');
const direct = __ENV.MODE === 'direct';

export const options = {
  summaryTrendStats: ['avg','min','med','max','p(90)','p(95)','p(99)'],
  insecureSkipTLSVerify: labTls, // EPHEMERAL localhost test identity only; never production
  noConnectionReuse: __ENV.NO_REUSE === '1',
  scenarios: { sustained: { executor: 'constant-vus', vus, duration } },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    checks: ['rate>0.995'],
    http_req_duration: ['p(95)<2500', 'p(99)<5000'],
  },
};

export default function () {
  // Both direct backends are exercised (70/30) so this baseline is not a
  // single-backend comparison against two destinations.
  const backend = __ITER % 10 < 7 ? 'http://127.0.0.1:18081' : 'http://127.0.0.1:18082';
  const target = direct ? backend : (__ENV.TARGET || 'http://127.0.0.1:18080');
  const path = payloadBytes > 0 ? '/api/payload/' + payloadBytes : '/api/identity';
  const response = http.get(target + path, { timeout: '10s' });
  if (soakWindows.length && Number.isFinite(response.timings.duration)) {
    const bucket = Math.floor((Date.now() - soakOriginMs) / (soakWindowSeconds * 1000));
    if (bucket >= 0 && bucket < soakWindows.length) {
      soakWindows[bucket].add(response.timings.duration);
      soakFailures[bucket].add(response.status !== 200);
    }
  }
  const needsTls = target.startsWith('https://');
  if (needsTls && response.tls_version) negotiatedTls.add(1);
  check(response, {
    'status HTTP 200': r => r.status === 200,
    'response valid': r => typeof r.body === 'string' &&
      (payloadBytes > 0 ? r.body.length === payloadBytes : r.body.includes('"node"')),
    'TLS negotiated on HTTPS': r => !needsTls || (r.tls_version && r.tls_version !== ''),
  });
}
