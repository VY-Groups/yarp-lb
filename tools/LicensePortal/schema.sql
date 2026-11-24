-- Apply as the database migration owner, not the portal runtime account.
CREATE TABLE IF NOT EXISTS gc_customers (
  id text PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9_-]{1,80}$'),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS gc_subscriptions (
  id text PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9_-]{1,80}$'),
  customer_id text NOT NULL REFERENCES gc_customers(id),
  deployment_id text NOT NULL UNIQUE CHECK (deployment_id ~ '^[A-Za-z0-9_-]{1,80}$'),
  edition text NOT NULL CHECK (edition IN ('evaluation','standard','professional','enterprise','custom')),
  max_nodes int NOT NULL CHECK (max_nodes BETWEEN 1 AND 10000),
  max_sites int NOT NULL CHECK (max_sites BETWEEN 1 AND max_nodes),
  expires_at timestamptz NOT NULL,
  features text[] NOT NULL CHECK (cardinality(features) BETWEEN 1 AND 12),
  terms_revision bigint NOT NULL DEFAULT 1 CHECK (terms_revision > 0),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS gc_license_jobs (
  id uuid PRIMARY KEY,
  subscription_id text NOT NULL REFERENCES gc_subscriptions(id),
  kind text NOT NULL CHECK (kind IN ('issue','revoke','renew_terms')),
  expected_terms_revision bigint NOT NULL CHECK (expected_terms_revision > 0),
  proposed_terms jsonb,
  site_id text,
  request_id text UNIQUE,
  installation_hash text,
  request_file text,
  allocation_id text,
  requested_by text NOT NULL,
  requested_at timestamptz NOT NULL DEFAULT now(),
  approved_by text,
  approved_at timestamptz,
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','approved','rejected')),
  CHECK (approved_by IS NULL OR approved_by <> requested_by),
  CHECK ((state = 'pending' AND approved_by IS NULL AND approved_at IS NULL)
      OR (state <> 'pending' AND approved_by IS NOT NULL AND approved_at IS NOT NULL)),
  CHECK ((kind = 'issue' AND request_id IS NOT NULL AND installation_hash IS NOT NULL
      AND site_id IS NOT NULL AND request_file IS NOT NULL AND allocation_id IS NULL AND proposed_terms IS NULL)
      OR (kind = 'revoke' AND allocation_id IS NOT NULL AND request_id IS NULL
      AND installation_hash IS NULL AND site_id IS NULL AND request_file IS NULL AND proposed_terms IS NULL)
      OR (kind = 'renew_terms' AND proposed_terms IS NOT NULL AND allocation_id IS NULL AND request_id IS NULL
      AND installation_hash IS NULL AND site_id IS NULL AND request_file IS NULL))
);
CREATE TABLE IF NOT EXISTS gc_portal_audit (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  actor text NOT NULL,
  action text NOT NULL,
  subject text NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now()
);
-- The operator portal cannot edit approvals or subscription terms after
-- creation except through the explicitly defined decision function/queries.
-- Provision a separate least-privilege DB runtime identity, restrict
-- UPDATE to job decision columns, deny DELETE and audit UPDATE/TRUNCATE.

-- Separate signing worker owns these records; portal only reads public results.
CREATE TABLE IF NOT EXISTS gc_issuer_authority (
  subscription_id text PRIMARY KEY REFERENCES gc_subscriptions(id),
  key_id text NOT NULL,
  public_key_hash text NOT NULL
);
CREATE TABLE IF NOT EXISTS gc_issuer_allocations (
  subscription_id text NOT NULL REFERENCES gc_subscriptions(id),
  allocation_id text NOT NULL UNIQUE,
  site_id text NOT NULL,
  installation_hash text NOT NULL,
  revision bigint NOT NULL CHECK(revision > 0),
  last_expiry timestamptz NOT NULL,
  revocation_envelope text,
  PRIMARY KEY(subscription_id, installation_hash),
  UNIQUE(installation_hash)
);
CREATE TABLE IF NOT EXISTS gc_issuer_results (
  job_id uuid PRIMARY KEY REFERENCES gc_license_jobs(id),
  envelope text,
  completed_at timestamptz NOT NULL DEFAULT now()
);
