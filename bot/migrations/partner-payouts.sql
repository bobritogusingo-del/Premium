-- Payout request state, confirmed amounts, and short-lived admin confirmation sessions.
ALTER TABLE partner_payout_requests ADD COLUMN status TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE partner_payout_requests ADD COLUMN amount_kopeks INTEGER;
ALTER TABLE partner_payout_requests ADD COLUMN confirmed_by INTEGER;
ALTER TABLE partner_payout_requests ADD COLUMN confirmed_at TEXT;
ALTER TABLE partner_payout_requests ADD COLUMN edited_at TEXT;
ALTER TABLE partner_payout_sessions ADD COLUMN request_id INTEGER;
ALTER TABLE partner_payout_sessions ADD COLUMN mode TEXT NOT NULL DEFAULT 'create';
CREATE INDEX IF NOT EXISTS idx_partner_payout_requests_status_time ON partner_payout_requests(status, confirmed_at DESC);
CREATE TABLE IF NOT EXISTS partner_payout_confirm_sessions (
  admin_id INTEGER PRIMARY KEY REFERENCES users(telegram_id),
  request_id INTEGER NOT NULL REFERENCES partner_payout_requests(id),
  expires_at TEXT NOT NULL
);
