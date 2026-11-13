import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

const negotiatedTls = new Counter('lab_tls_negotiated_responses');

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
  const needsTls = target.startsWith('https://');
  if (needsTls && response.tls_version) negotiatedTls.add(1);
  check(response, {
    'status HTTP 200': r => r.status === 200,
    'response valid': r => payloadBytes > 0 ? r.body.length === payloadBytes : r.body.includes('"node"'),
    'TLS negotiated on HTTPS': r => !needsTls || (r.tls_version && r.tls_version !== ''),
  });
}
