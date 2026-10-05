-- A single encrypted bootstrap bundle. The primary key is the
-- initialization lock; D1 batch rolls the complete setup back on conflicts.
CREATE TABLE pki_config (
  id INTEGER PRIMARY KEY CHECK(id=1),
  encrypted TEXT NOT NULL,
  created_at TEXT NOT NULL
);
