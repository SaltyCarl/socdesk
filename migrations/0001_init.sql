CREATE TABLE accounts (
  github_id   INTEGER PRIMARY KEY,
  login       TEXT    NOT NULL,
  created_at  TEXT    NOT NULL,
  last_seen   TEXT    NOT NULL,
  banned      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE reports (
  id           TEXT    PRIMARY KEY,
  github_id    INTEGER NOT NULL REFERENCES accounts(github_id),
  ioc_type     TEXT    NOT NULL,
  ioc_value    TEXT    NOT NULL,
  category     TEXT    NOT NULL,
  evidence     TEXT    NOT NULL,
  comment      TEXT,
  status       TEXT    NOT NULL DEFAULT 'queued',
  created_at   TEXT    NOT NULL
);
CREATE INDEX idx_reports_ioc    ON reports(ioc_type, ioc_value);
CREATE INDEX idx_reports_author ON reports(github_id, created_at);
CREATE INDEX idx_reports_status ON reports(status, created_at);
