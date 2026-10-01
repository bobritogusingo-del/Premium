-- Partner-programme applications and the admin-controlled recruitment switch.
CREATE TABLE IF NOT EXISTS partner_program_settings (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  recruitment_open INTEGER NOT NULL DEFAULT 0 CHECK(recruitment_open IN (0,1)),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT OR IGNORE INTO partner_program_settings (id, recruitment_open) VALUES (1, 0);
CREATE TABLE IF NOT EXISTS partner_applications (
  user_id INTEGER PRIMARY KEY REFERENCES users(telegram_id),
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  decided_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_partner_applications_status_time ON partner_applications(status, decided_at DESC, created_at DESC);
