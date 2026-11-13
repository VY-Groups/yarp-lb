import http from 'k6/http';
import { check } from 'k6';
export const options = {
  scenarios: {
    sustained: { executor: 'constant-vus', vus: 75, duration: '45s' },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<2500', 'p(99)<5000'],
  },
};
const target = __ENV.TARGET || 'http://127.0.0.1:18080';
export default function () {
  const r = http.get(target + '/api/identity', { timeout: '10s' });
  check(r, {
    'HTTP 200': x => x.status === 200,
    'backend identity': x => x.body.includes('"node"'),
  });
}
