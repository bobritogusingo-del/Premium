-- Keeps an auditable list of accounts that entered each promo code.
-- Existing paid orders are backfilled because an order can only be created
-- after the user entered the code.
CREATE TABLE IF NOT EXISTS promo_entries (
  promo_code TEXT NOT NULL REFERENCES promo_codes(code),
  user_id INTEGER NOT NULL REFERENCES users(telegram_id),
  entered_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (promo_code, user_id)
);
CREATE INDEX IF NOT EXISTS idx_promo_entries_code_entered ON promo_entries(promo_code, entered_at DESC);

INSERT OR IGNORE INTO promo_entries (promo_code, user_id, entered_at)
SELECT promo_code, user_id, created_at
FROM orders
WHERE promo_code IS NOT NULL;
