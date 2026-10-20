-- Application answers, revisions, and the weekly submission limit.
ALTER TABLE partner_applications ADD COLUMN answers TEXT;
ALTER TABLE partner_applications ADD COLUMN revision_requested_at TEXT;
CREATE TABLE IF NOT EXISTS partner_application_sessions (
  user_id INTEGER PRIMARY KEY REFERENCES users(telegram_id),
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS partner_application_submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(telegram_id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_partner_application_submissions_user_time ON partner_application_submissions(user_id, created_at DESC);
