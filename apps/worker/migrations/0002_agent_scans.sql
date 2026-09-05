-- Independent anonymous scans: capabilities are hashed; evidence is encrypted.
CREATE TABLE agent_scan (
  id TEXT PRIMARY KEY,
  payload TEXT NOT NULL,
  revision INTEGER NOT NULL DEFAULT 1,
  read_hash TEXT NOT NULL,
  owner_hash TEXT NOT NULL,
  agent_hash TEXT NOT NULL,
  agent_expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX agent_scan_expiry_idx ON agent_scan(expires_at);
