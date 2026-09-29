-- Schema for a new Premium-only telegram-subscription-bot D1 database.

CREATE TABLE IF NOT EXISTS users (
  telegram_id INTEGER PRIMARY KEY,
  username TEXT,
  first_name TEXT,
  referrer_telegram_id INTEGER,
  referral_reward_granted INTEGER NOT NULL DEFAULT 0 CHECK (referral_reward_granted IN (0, 1)),
  trial_activated INTEGER NOT NULL DEFAULT 0 CHECK (trial_activated IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_users_referrer ON users(referrer_telegram_id);

CREATE TABLE IF NOT EXISTS subscriptions (
  user_id INTEGER NOT NULL REFERENCES users(telegram_id),
  plan TEXT NOT NULL DEFAULT 'premium' CHECK (plan = 'premium'),
  expiration_at TEXT,
  happ_install_id INTEGER,
  happ_install_code TEXT,
  happ_install_link TEXT,
  happ_status TEXT CHECK (happ_status IN ('creating', 'active', 'disabled', 'error')),
  happ_last_error TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, plan),
  UNIQUE (plan, happ_install_id)
);
CREATE INDEX IF NOT EXISTS idx_subscriptions_expiration ON subscriptions(expiration_at);
CREATE INDEX IF NOT EXISTS idx_subscriptions_active_expiration ON subscriptions(happ_status, expiration_at);

CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(telegram_id),
  plan TEXT NOT NULL DEFAULT 'premium' CHECK (plan = 'premium'),
  duration_months INTEGER NOT NULL CHECK (duration_months IN (1, 3, 6, 12)),
  -- Used only by the temporary low-cost test offer. NULL means a normal monthly plan.
  duration_days INTEGER CHECK (duration_days IS NULL OR duration_days > 0),
  amount_rub INTEGER NOT NULL CHECK (amount_rub > 0),
  promo_code TEXT REFERENCES promo_codes(code),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'paid', 'cancelled')),
  quickpay_url TEXT NOT NULL,
  operation_id TEXT UNIQUE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  paid_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_orders_user_created ON orders(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);

CREATE TABLE IF NOT EXISTS promo_codes (
  code TEXT PRIMARY KEY,
  discount_percent INTEGER NOT NULL CHECK (discount_percent BETWEEN 1 AND 99),
  duration_days INTEGER CHECK (duration_days IS NULL OR duration_days BETWEEN 1 AND 3650),
  max_activations INTEGER NOT NULL CHECK (max_activations > 0),
  activation_count INTEGER NOT NULL DEFAULT 0 CHECK (activation_count >= 0),
  free_grant INTEGER NOT NULL DEFAULT 0 CHECK (free_grant IN (0, 1)),
  unlimited_activations INTEGER NOT NULL DEFAULT 0 CHECK (unlimited_activations IN (0, 1)),
  expires_at TEXT,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_by INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_promo_codes_active ON promo_codes(active);

-- Accounts that entered a code are recorded separately from successful payments.
CREATE TABLE IF NOT EXISTS promo_entries (
  promo_code TEXT NOT NULL REFERENCES promo_codes(code),
  user_id INTEGER NOT NULL REFERENCES users(telegram_id),
  entered_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (promo_code, user_id)
);
CREATE INDEX IF NOT EXISTS idx_promo_entries_code_entered ON promo_entries(promo_code, entered_at DESC);

CREATE TABLE IF NOT EXISTS input_sessions (
  user_id INTEGER PRIMARY KEY REFERENCES users(telegram_id),
  kind TEXT NOT NULL CHECK (kind IN ('redeem_promo', 'admin_promo_discount', 'admin_promo_days', 'admin_promo_free_days')),
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id TEXT NOT NULL REFERENCES orders(id), operation_id TEXT NOT NULL UNIQUE,
  amount TEXT NOT NULL, currency TEXT NOT NULL, notification_type TEXT NOT NULL,
  payment_datetime TEXT NOT NULL, sender TEXT, codepro TEXT, label TEXT NOT NULL,
  raw_sha1 TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_payments_order ON payments(order_id);

CREATE TABLE IF NOT EXISTS activation_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(telegram_id), order_id TEXT REFERENCES orders(id),
  event_type TEXT NOT NULL CHECK (event_type IN ('trial', 'payment', 'referral_reward')),
  details TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(order_id, event_type)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_activation_trial_once ON activation_logs(user_id, event_type) WHERE event_type = 'trial';
CREATE INDEX IF NOT EXISTS idx_activation_user_created ON activation_logs(user_id, created_at DESC);


-- Per-user short action window: permits three Telegram actions every two seconds.
CREATE TABLE IF NOT EXISTS telegram_rate_limits (
  user_id INTEGER PRIMARY KEY REFERENCES users(telegram_id),
  window_started_ms INTEGER NOT NULL,
  action_count INTEGER NOT NULL
);
