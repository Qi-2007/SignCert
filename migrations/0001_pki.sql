CREATE TABLE certificates (
  serial TEXT PRIMARY KEY,
  pem TEXT NOT NULL,
  subject TEXT NOT NULL,
  profile TEXT NOT NULL,
  not_before TEXT NOT NULL,
  not_after TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'good' CHECK(status IN ('good','revoked')),
  revoked_at TEXT,
  revocation_reason INTEGER,
  created_at TEXT NOT NULL
);
CREATE INDEX certificates_created ON certificates(created_at);
CREATE TABLE audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action TEXT NOT NULL,
  serial TEXT,
  at TEXT NOT NULL,
  detail TEXT NOT NULL
);
CREATE TABLE timestamps (
  serial TEXT PRIMARY KEY,
  at TEXT NOT NULL,
  received_at TEXT NOT NULL,
  time_mode TEXT NOT NULL CHECK(time_mode IN ('current','custom')),
  hash_algorithm TEXT NOT NULL,
  imprint TEXT NOT NULL,
  token_sha256 TEXT NOT NULL
);
CREATE TABLE crl_sequence (id INTEGER PRIMARY KEY CHECK(id=1), number INTEGER NOT NULL);
INSERT INTO crl_sequence (id,number) VALUES (1,0);
