-- Adds separate referral-purchase accounting period and interactive admin sessions.
ALTER TABLE orders ADD COLUMN partner_referral_expires_at TEXT;
ALTER TABLE partners ADD COLUMN referral_purchase_expires_at TEXT;
CREATE TABLE IF NOT EXISTS partner_admin_sessions (
  admin_id INTEGER PRIMARY KEY REFERENCES users(telegram_id),
  action TEXT NOT NULL CHECK(action IN ('extend_partner', 'extend_referral')),
  partner_code TEXT NOT NULL REFERENCES partners(code),
  expires_at TEXT NOT NULL
);
