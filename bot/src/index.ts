import { encryptHappCrypt5 } from "./crypt5";

interface Env {
  DB: D1Database;
  TELEGRAM_BOT_TOKEN: string;
  TELEGRAM_WEBHOOK_SECRET: string;
  YOOMONEY_NOTIFICATION_SECRET: string;
  YOOKASSA_SHOP_ID: string;
  YOOKASSA_SECRET_KEY: string;
  CHANNEL_ID: string;
  CHANNEL_INVITE_URL: string;
  YOOMONEY_RECEIVER: string;
  ADMIN_TELEGRAM_ID?: string;
  HAPP_PREMIUM_PROVIDER_CODE: string;
  HAPP_PREMIUM_AUTH_KEY: string;
  HAPP_INSTALL_LIMIT?: string;
  HAPP_INSTALL_URL_BASE?: string;
}

type Plan = "premium";
type DurationMonths = 1 | 3 | 6 | 12;

const PRODUCTS: Record<Plan, Record<DurationMonths, number>> = {
  premium: { 1: 250, 3: 660, 6: 1200, 12: 2160 },
};
const DURATIONS: DurationMonths[] = [1, 3, 6, 12];
const MEMBER_STATUSES = new Set(["creator", "administrator", "member"]);
// Each Happ link points to this per-installation endpoint. It adds the
// subscription's expiry through Subscription-Userinfo without exposing the
// shared upstream configuration URL to the client.
const HAPP_SUBSCRIPTION_ENDPOINT = "https://telegram-vpn-bot.bobritogusingo.workers.dev/subscription/{INSTALL_CODE}";
const WORKER_URL = "https://telegram-vpn-bot.bobritogusingo.workers.dev";

interface TelegramUser { id: number; is_bot?: boolean; first_name: string; username?: string; }
interface TelegramChat { id: number; }
interface TelegramMessage { message_id: number; chat: TelegramChat; from?: TelegramUser; text?: string; }
interface TelegramCallbackQuery { id: string; from: TelegramUser; data?: string; message?: TelegramMessage; }
interface TelegramUpdate { update_id: number; message?: TelegramMessage; callback_query?: TelegramCallbackQuery; }
interface TelegramApiResponse<T> { ok: boolean; result?: T; description?: string; }
interface ChatMember { status: string; is_member?: boolean; }
interface UserRow {
  telegram_id: number;
  username: string | null;
  first_name: string | null;
  trial_activated: number;
}
interface SubscriptionRow {
  user_id: number;
  plan: Plan;
  expiration_at: string | null;
  happ_install_id: number | null;
  happ_install_code: string | null;
  happ_install_link: string | null;
  happ_status: "creating" | "active" | "disabled" | "error" | null;
}
interface OrderRow {
  id: string; user_id: number; plan: Plan; duration_months: DurationMonths; duration_days: number | null; amount_rub: number; promo_code: string | null;
  status: "pending" | "paid" | "cancelled"; quickpay_url: string; operation_id: string | null;
  created_at: string; paid_at: string | null;
}
interface PaymentRow { order_id: string; operation_id: string; }
interface PromoCodeRow {
  code: string; discount_percent: number; duration_days: number | null;
  max_activations: number; activation_count: number; active: number; free_grant: number;
  unlimited_activations: number; expires_at: string | null;
}
interface PromoAdminRow extends PromoCodeRow { created_at: string; updated_at: string; paid_orders: number; }
interface PromoUserRow { user_id: number; username: string | null; first_name: string | null; used_at: string; usage_type: string; }
interface InputSessionRow { kind: string; expires_at: string; }
interface HappInstall { id: number; code: string; link: string; }
interface SubscriptionProvider {
  ensureSubscription(env: Env, subscription: SubscriptionRow, note: string): Promise<HappInstall>;
  disableSubscription(env: Env, plan: Plan, id: number): Promise<void>;
}

function happConfig(env: Env, _plan: Plan): { provider: string; auth: string; limit: number; base?: string } {
  const keys: (keyof Env)[] = ["HAPP_PREMIUM_PROVIDER_CODE", "HAPP_PREMIUM_AUTH_KEY"];
  requireConfig(env, keys);
  const limit = env.HAPP_INSTALL_LIMIT ? Number(env.HAPP_INSTALL_LIMIT) : 2;
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error("HAPP_INSTALL_LIMIT must be an integer from 1 to 100");
  const base = env.HAPP_INSTALL_URL_BASE?.trim() || undefined;
  const [providerKey, authKey] = keys;
  return { provider: env[providerKey] as string, auth: env[authKey] as string, limit, base };
}

function randomInstallCode(): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return Array.from(bytes, (byte) => alphabet[byte % alphabet.length]).join("");
}
function findField(value: unknown, names: string[]): unknown {
  if (!value || typeof value !== "object") return undefined;
  const record = value as Record<string, unknown>;
  for (const name of names) if (record[name] !== undefined) return record[name];
  for (const child of Object.values(record)) { const found = findField(child, names); if (found !== undefined) return found; }
  return undefined;
}
function buildHappPlainLink(code: string): string {
  // Happ recognises InstallID from the fragment. Unlike a normal query string,
  // the fragment is not sent to the subscription endpoint, but it is available
  // to the client for the Happ installation/device-limit flow.
  const url = HAPP_SUBSCRIPTION_ENDPOINT.replace("{INSTALL_CODE}", encodeURIComponent(code));
  return `${url}#BananchikiVpn?installid=${encodeURIComponent(code)}`;
}
function buildHappLink(_sourceUrl: string, code: string): string {
  // Android Happ Plus supports the encrypted form, which hides the endpoint.
  return encryptHappCrypt5(buildHappPlainLink(code));
}
function parseHappInstall(payload: unknown, fallbackCode: string, base?: string): HappInstall {
  const rc = findField(payload, ["rc"]);
  // Current Happ API: rc=1 is successful; rc=0 contains the error message.
  if (rc !== undefined && ![1, "1", true, "success", "ok"].includes(rc as never)) throw new Error(`Happ rejected install creation: ${String(findField(payload, ["msg", "message"]) ?? rc)}`);
  const rawId = findField(payload, ["id", "install_id", "installId"]);
  const rawCode = findField(payload, ["install_code", "installCode", "code"]);
  const rawLink = findField(payload, ["url", "link", "install_url", "installUrl", "subscription_url", "subscriptionUrl"]);
  const id = Number(rawId);
  const code = typeof rawCode === "string" ? rawCode : fallbackCode;
  const link = typeof rawLink === "string" ? rawLink : base ? buildHappLink(base, code) : "";
  if (!Number.isSafeInteger(id) || id <= 0 || !code || !link) throw new Error("Happ response did not contain a usable install id and public link; configure HAPP_INSTALL_URL_BASE with the original subscription URL");
  return { id, code, link };
}
async function happRequest(env: Env, plan: Plan, path: string, method = "GET", body?: unknown): Promise<unknown> {
  const config = happConfig(env, plan);
  const url = new URL(`https://happ-proxy.com${path}`);
  url.searchParams.set("provider_code", config.provider);
  url.searchParams.set("auth_key", config.auth);
  const response = await fetch(url, { method, headers: body ? { "content-type": "application/json" } : undefined, ...(body ? { body: JSON.stringify(body) } : {}) });
  let payload: unknown;
  try { payload = await response.json(); } catch { throw new Error(`Happ returned non-JSON response (${response.status})`); }
  if (!response.ok) throw new Error(`Happ HTTP error: ${response.status}`);
  return payload;
}
const happSubscriptionProvider: SubscriptionProvider = {
  async ensureSubscription(env, subscription, note) {
    const config = happConfig(env, subscription.plan);
    if (subscription.happ_install_id && subscription.happ_install_link) {
      const payload = await happRequest(env, subscription.plan, `/api/update-install?id=${encodeURIComponent(String(subscription.happ_install_id))}&status=10`);
      const rc = findField(payload, ["rc"]);
      // Happ returns rc=1 for success on the current API; older responses may use rc=0.
      if (rc !== undefined && ![0, "0", 1, "1", true, "success", "ok"].includes(rc as never)) throw new Error(`Happ rejected install activation: ${String(findField(payload, ["msg", "message"]) ?? rc)}`);
      // Rebuild the public URL from the stored Happ code. This also repairs
      // links issued before the documented fragment format was applied.
      const code = subscription.happ_install_code ?? "";
      const link = code && config.base ? buildHappLink(config.base, code) : subscription.happ_install_link;
      return { id: subscription.happ_install_id, code, link };
    }
    const code = subscription.happ_install_code ?? randomInstallCode();
    const path = `/api/add-install?install_limit=${config.limit}&install_code=${encodeURIComponent(code)}&note=${encodeURIComponent(note)}`;
    return parseHappInstall(await happRequest(env, subscription.plan, path), code, config.base);
  },
  async disableSubscription(env, plan, id) {
    const payload = await happRequest(env, plan, `/api/update-install?id=${encodeURIComponent(String(id))}&status=5`);
    const rc = findField(payload, ["rc"]);
    if (rc !== undefined && ![0, "0", true, "success", "ok"].includes(rc as never)) throw new Error(`Happ rejected install disable: ${String(findField(payload, ["msg", "message"]) ?? rc)}`);
  },
};
async function reissueHappSubscription(env: Env, userId: number, plan: Plan): Promise<void> {
  const previous = await getActiveSubscription(env, userId, plan);
  if (!previous) throw new Error(`No active ${plan.toUpperCase()} subscription to reissue`);

  // Create the replacement before switching the database record. Thus a
  // temporary Happ API failure never takes away the current working link.
  const config = happConfig(env, plan);
  const code = randomInstallCode();
  const payload = await happRequest(
    env,
    plan,
    `/api/add-install?install_limit=${config.limit}&install_code=${encodeURIComponent(code)}&note=${encodeURIComponent("User-requested Happ reissue")}`,
  );
  const replacement = parseHappInstall(payload, code, config.base);
  const result = await env.DB.prepare(
    `UPDATE subscriptions
     SET happ_install_id = ?, happ_install_code = ?, happ_install_link = ?, happ_status = 'active', happ_last_error = NULL, updated_at = datetime('now')
     WHERE user_id = ? AND plan = ? AND expiration_at IS NOT NULL AND expiration_at > datetime('now')`,
  ).bind(replacement.id, replacement.code, replacement.link, userId, plan).run();
  if (Number(result.meta.changes ?? 0) !== 1) {
    // The new Happ link is not handed out if the subscription disappeared or
    // expired during the request; disable it to avoid an orphaned installation.
    try { await happSubscriptionProvider.disableSubscription(env, plan, replacement.id); } catch (error) { console.error("Could not disable unused replacement Happ install", error); }
    throw new Error("Subscription changed while the replacement link was being created");
  }

  // A disabled old link cannot be re-imported. If Happ's disable request is
  // temporarily unavailable, the Worker endpoint has already stopped serving
  // the old install code, and the failure is logged for later inspection.
  if (previous.happ_install_id) {
    try { await happSubscriptionProvider.disableSubscription(env, plan, previous.happ_install_id); }
    catch (error) { console.error(`Could not disable previous Happ install ${previous.happ_install_id}`, error); }
  }
}

async function getSubscription(env: Env, userId: number, plan: Plan): Promise<SubscriptionRow | null> {
  return env.DB.prepare("SELECT * FROM subscriptions WHERE user_id = ? AND plan = ?").bind(userId, plan).first<SubscriptionRow>();
}
async function getActiveSubscription(env: Env, userId: number, plan: Plan): Promise<SubscriptionRow | null> {
  return env.DB.prepare("SELECT * FROM subscriptions WHERE user_id = ? AND plan = ? AND expiration_at IS NOT NULL AND expiration_at > datetime('now')").bind(userId, plan).first<SubscriptionRow>();
}
function isRenewalSubscription(subscription: SubscriptionRow | null): boolean {
  if (!subscription?.expiration_at) return false;
  const expiration = new Date(`${subscription.expiration_at.replace(" ", "T")}Z`).getTime();
  return Number.isFinite(expiration) && expiration > Date.now() - 7 * 86_400_000;
}
// Reserving the row in D1 prevents overlapping webhook deliveries from making
// duplicate Happ installs for the same user and plan.
async function deliverSubscription(env: Env, userId: number, plan: Plan, note: string): Promise<string> {
  let reservation = await getActiveSubscription(env, userId, plan);
  if (!reservation) throw new Error(`No active ${plan.toUpperCase()} subscription to deliver`);
  if (!reservation.happ_install_id) {
    // Another request owns a fresh creation reservation and must not fall
    // through to add-install. A five-minute lease also lets a later webhook
    // recover if its creator died between reserving the row and calling Happ.
    const code = reservation.happ_install_code ?? randomInstallCode();
    const result = await env.DB.prepare(
      `UPDATE subscriptions SET happ_install_code = ?, happ_status = 'creating', updated_at = datetime('now')
       WHERE user_id = ? AND plan = ? AND happ_install_id IS NULL
         AND (happ_status IS NULL OR happ_status = 'error'
              OR (happ_status = 'creating' AND updated_at <= datetime('now', '-5 minutes')))
         AND expiration_at IS NOT NULL AND expiration_at > datetime('now')`,
    ).bind(code, userId, plan).run();
    if (Number(result.meta.changes ?? 0) === 0) {
      const fresh = await getActiveSubscription(env, userId, plan);
      if (fresh?.happ_install_id && fresh.happ_install_link) return fresh.happ_install_link;
      throw new Error(`${plan.toUpperCase()} Happ installation is being created; retry delivery`);
    }
    reservation = (await getActiveSubscription(env, userId, plan)) ?? reservation;
  }
  try {
    const install = await happSubscriptionProvider.ensureSubscription(env, reservation, note);
    await env.DB.prepare(`UPDATE subscriptions SET happ_install_id = ?, happ_install_code = ?, happ_install_link = ?, happ_status = 'active', updated_at = datetime('now') WHERE user_id = ? AND plan = ?`).bind(install.id, install.code, install.link, userId, plan).run();
    return install.link;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    await env.DB.prepare(
      "UPDATE subscriptions SET happ_status = 'error', happ_last_error = ?, updated_at = datetime('now') WHERE user_id = ? AND plan = ? AND happ_status = 'creating'",
    ).bind(message.slice(0, 1000), userId, plan).run();
    throw error;
  }
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function textResponse(body: string, status = 200): Response {
  return new Response(body, { status, headers: { "content-type": "text/plain; charset=utf-8" } });
}

async function fetchPremiumSource(env: Env): Promise<Response> {
  const sourceUrl = happConfig(env, "premium").base;
  if (!sourceUrl) throw new Error("HAPP_INSTALL_URL_BASE is required");
  const source = new URL(sourceUrl);
  if (source.protocol !== "https:" || source.username || source.password) throw new Error("Invalid Happ subscription source URL");
  const response = await fetch(source.toString(), { headers: { accept: "application/json, text/plain;q=0.9, */*;q=0.1" } });
  if (!response.ok) throw new Error(`Subscription source failed: ${response.status}`);
  return response;
}

function makeExpiredSubscriptionNotice(sourceText: string): string {
  // Happ reads JSON subscription entries and uses their remarks as the names
  // shown in the server list. We retain the current validated config shape,
  // but replace every outbound with a blackhole so these entries can never
  // provide network access after the paid period ends.
  const parsed: unknown = JSON.parse(sourceText);
  if (!Array.isArray(parsed) || parsed.length === 0 || !parsed[0] || typeof parsed[0] !== "object") {
    throw new Error("Premium source is not a JSON subscription array");
  }
  const template = parsed[0] as Record<string, unknown>;
  const notices = ["⛔ Подписка закончилась", "🔄 Её можно продлить", "🤖 В нашем боте"];
  return JSON.stringify(notices.map((remarks) => {
    const notice = JSON.parse(JSON.stringify(template)) as Record<string, unknown>;
    notice.remarks = remarks;
    if (!Array.isArray(notice.outbounds) || notice.outbounds.length === 0) throw new Error("Premium source has no outbounds");
    notice.outbounds = notice.outbounds.map((outbound) => {
      const tag = outbound && typeof outbound === "object" ? (outbound as Record<string, unknown>).tag : undefined;
      if (typeof tag !== "string" || tag.length === 0) throw new Error("Premium source has an invalid outbound tag");
      return { tag, protocol: "blackhole" };
    });
    return notice;
  }));
}

async function serveHappSubscription(env: Env, installCode: string): Promise<Response> {
  if (!/^[A-Za-z0-9]{8,128}$/.test(installCode)) return textResponse("Not found", 404);
  const subscription = await env.DB.prepare(
    `SELECT expiration_at, happ_status FROM subscriptions
     WHERE plan = 'premium' AND happ_install_code = ? AND expiration_at IS NOT NULL`,
  ).bind(installCode).first<Pick<SubscriptionRow, "expiration_at" | "happ_status">>();
  if (!subscription?.expiration_at) return textResponse("Subscription inactive", 403);

  const expiresAt = new Date(`${subscription.expiration_at.replace(" ", "T")}Z`).getTime();
  if (!Number.isFinite(expiresAt)) throw new Error("Invalid subscription expiry");
  const source = await fetchPremiumSource(env);
  const headers = new Headers();
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");

  if (expiresAt <= Date.now()) {
    const sourceText = await source.text();
    return new Response(makeExpiredSubscriptionNotice(sourceText), { status: 200, headers });
  }
  if (subscription.happ_status !== "active") return textResponse("Subscription inactive", 403);

  // Only expiry is supplied: Happ shows the date without a traffic counter or
  // provider description. The value is a Unix timestamp in seconds.
  headers.set("content-type", source.headers.get("content-type") || "application/json; charset=utf-8");
  headers.set("subscription-userinfo", `expire=${Math.floor(expiresAt / 1000)}`);
  return new Response(source.body, { status: 200, headers });
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[character] as string);
}

async function yoomoneyPaymentPage(env: Env, orderId: string, paymentType: string | null): Promise<Response> {
  requireConfig(env, ["YOOMONEY_RECEIVER"]);
  if (paymentType !== "AC" && paymentType !== "PC") return textResponse("Payment method not found", 404);
  const order = await env.DB.prepare("SELECT id, amount_rub, status FROM orders WHERE id = ?").bind(orderId).first<Pick<OrderRow, "id" | "amount_rub" | "status">>();
  if (!order) return textResponse("Order not found", 404);
  if (order.status !== "pending") return textResponse("Этот заказ уже оплачен или отменён. Вернитесь в бот, чтобы создать новый заказ.", 409);
  const fields: Record<string, string> = {
    receiver: env.YOOMONEY_RECEIVER,
    label: order.id,
    "quickpay-form": "button",
    paymentType,
    sum: String(order.amount_rub),
    targets: "Подписка PREMIUM",
  };
  const inputs = Object.entries(fields).map(([name, value]) =>
    `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`,
  ).join("");
  const methodName = paymentType === "AC" ? "картой" : "из кошелька ЮMoney";
  return new Response(`<!doctype html><html lang="ru"><meta charset="utf-8"><title>Переход к оплате</title><body><p>Перенаправляем к оплате ${methodName}…</p><form id="payment" method="post" action="https://yoomoney.ru/quickpay/confirm.xml">${inputs}<button type="submit">Перейти к оплате</button></form><script>document.getElementById('payment').submit()</script></body></html>`, {
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  });
}

function requireConfig(env: Env, keys: (keyof Env)[]): void {
  for (const key of keys) {
    const value = env[key];
    if (typeof value !== "string" || value.trim() === "" || value.includes("REPLACE_WITH")) {
      throw new Error(`Missing configuration: ${String(key)}`);
    }
  }
}

async function telegramApi<T>(env: Env, method: string, payload: Record<string, unknown>): Promise<T> {
  requireConfig(env, ["TELEGRAM_BOT_TOKEN"]);
  const response = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = (await response.json()) as TelegramApiResponse<T>;
  if (!response.ok || !data.ok) {
    throw new Error(`Telegram ${method} failed: ${data.description ?? response.status}`);
  }
  return data.result as T;
}

async function sendMessage(env: Env, chatId: number, text: string, replyMarkup?: unknown): Promise<void> {
  await telegramApi(env, "sendMessage", {
    chat_id: chatId,
    text,
    ...(replyMarkup ? { reply_markup: replyMarkup } : {}),
  });
}

function protectedLinkBlock(link: string): string {
  // Telegram's expandable quote keeps a long crypt5 link tidy; <code> gives
  // it a one-tap copy affordance in supported Telegram clients.
  return `<blockquote expandable><code>${escapeHtml(link)}</code></blockquote>`;
}
function happPlatformKeyboard(showReissue = false, showDevices = false): unknown {
  const rows: Array<Array<{ text: string; callback_data: string }>> = [
    [
      { text: "🤖 Android — Happ", callback_data: "happ:android" },
      { text: "🍎 iPhone/iPad — Happ", callback_data: "happ:ios" },
    ],
  ];
  if (showDevices) rows.push([{ text: "📱 Устройства", callback_data: "happ:devices" }]);
  if (showReissue) rows.push([{ text: "🔄 Перевыпустить ссылку", callback_data: "happ:reissue" }]);
  rows.push([{ text: "📖 Нужна инструкция", callback_data: "happ:guide" }]);
  return { inline_keyboard: rows };
}
async function sendSubscriptionChoice(env: Env, chatId: number, header: string, showReissue = false, showDevices = false): Promise<void> {
  await telegramApi(env, "sendMessage", {
    chat_id: chatId,
    text: `${escapeHtml(header)}\n\nВыберите устройство — бот пришлёт подходящую ссылку.`,
    parse_mode: "HTML",
    reply_markup: happPlatformKeyboard(showReissue, showDevices),
  });
}
async function sendSubscriptionLink(env: Env, chatId: number, header: string, link: string): Promise<void> {
  await telegramApi(env, "sendMessage", {
    chat_id: chatId,
    text: `${escapeHtml(header)}\n\n${protectedLinkBlock(link)}`,
    parse_mode: "HTML",
    reply_markup: { inline_keyboard: [[{ text: "📖 Нужна инструкция", callback_data: "happ:guide" }]] },
  });
}
async function sendPlatformSubscriptionLink(env: Env, chatId: number, telegramId: number, platform: "android" | "ios"): Promise<void> {
  const subscription = await getActiveSubscription(env, telegramId, "premium");
  const config = happConfig(env, "premium");
  if (!subscription?.happ_install_code || !config.base) {
    await sendMessage(env, chatId, "Не удалось найти активную ссылку. Откройте /menu ещё раз через минуту.");
    return;
  }
  const link = platform === "android"
    ? buildHappLink(config.base, subscription.happ_install_code)
    : buildHappPlainLink(subscription.happ_install_code);
  const device = platform === "android" ? "Android (Happ)" : "iPhone/iPad (Happ)";
  await sendSubscriptionLink(env, chatId, `Ссылка для ${device}:`, link);
}

interface HappDeviceAction { token: string; install_code: string; hwid: string; }
let deviceActionTableReady: Promise<void> | null = null;

async function ensureDeviceActionTable(env: Env): Promise<void> {
  if (!deviceActionTableReady) {
    deviceActionTableReady = env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS happ_device_actions (
        token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, install_code TEXT NOT NULL,
        hwid TEXT NOT NULL, expires_at TEXT NOT NULL
      )`,
    ).run().then(() => undefined).catch((error) => { deviceActionTableReady = null; throw error; });
  }
  await deviceActionTableReady;
}

interface HappDevice { hwid: string; name: string | null; }

function collectHappDevices(value: unknown, output = new Map<string, HappDevice>()): Map<string, HappDevice> {
  if (Array.isArray(value)) {
    for (const item of value) collectHappDevices(item, output);
  } else if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const hwid = typeof record.hwid === "string" ? record.hwid.trim() : "";
    // Happ supplies device_name with every normal list-hwid item. It is the
    // human-readable model/host name, unlike the technical HWID identifier.
    const rawName = record.device_name ?? record.deviceName;
    const name = typeof rawName === "string" && rawName.trim() ? rawName.trim() : null;
    if (hwid) {
      const previous = output.get(hwid);
      output.set(hwid, { hwid, name: name ?? previous?.name ?? null });
    }
    for (const item of Object.values(record)) collectHappDevices(item, output);
  }
  return output;
}

async function listHappDevices(env: Env, subscription: SubscriptionRow): Promise<HappDevice[]> {
  if (!subscription.happ_install_code && !subscription.happ_install_id) return [];
  const selector = subscription.happ_install_code
    ? `install_code=${encodeURIComponent(subscription.happ_install_code)}`
    : `install_id=${encodeURIComponent(String(subscription.happ_install_id))}`;
  const payload = await happRequest(env, subscription.plan, `/api/list-hwid?${selector}`);
  const rc = findField(payload, ["rc"]);
  if (rc !== undefined && ![1, "1", true, "success", "ok"].includes(rc as never)) {
    throw new Error(`Happ rejected device list: ${String(findField(payload, ["msg", "message"]) ?? rc)}`);
  }
  return [...collectHappDevices(payload).values()];
}

function deviceLabel(device: HappDevice): string {
  // Never expose a raw HWID to subscribers or the administrator. Some old
  // Happ responses do not include a model name, so use a clear safe fallback.
  return device.name ?? "Неизвестное устройство";
}

async function sendHappDevices(env: Env, chatId: number, telegramId: number): Promise<void> {
  const subscription = await getActiveSubscription(env, telegramId, "premium");
  if (!subscription?.happ_install_code) {
    await sendMessage(env, chatId, "Активная подписка или её ссылка не найдена. Откройте /menu ещё раз через минуту.");
    return;
  }
  const devices = await listHappDevices(env, subscription);
  const limit = happConfig(env, "premium").limit;
  if (devices.length === 0) {
    await sendMessage(env, chatId, `Подключённых устройств нет. Доступно: ${limit} из ${limit}.`);
    return;
  }
  await ensureDeviceActionTable(env);
  const rows: Array<Array<{ text: string; callback_data: string }>> = [];
  for (const device of devices) {
    const token = randomInstallCode();
    await env.DB.prepare(
      `INSERT OR REPLACE INTO happ_device_actions (token, user_id, install_code, hwid, expires_at)
       VALUES (?, ?, ?, ?, datetime('now', '+10 minutes'))`,
    ).bind(token, telegramId, subscription.happ_install_code, device.hwid).run();
    rows.push([{ text: `Отключить ${deviceLabel(device)}`, callback_data: `happ:device:remove:${token}` }]);
  }
  await sendMessage(env, chatId, `Подключённые устройства: ${devices.length} из ${limit}\n\nВыберите устройство, которое хотите отключить:`, { inline_keyboard: rows });
}

async function removeHappDevice(env: Env, telegramId: number, token: string): Promise<boolean> {
  if (!/^[A-Za-z0-9]{12}$/.test(token)) return false;
  await ensureDeviceActionTable(env);
  const action = await env.DB.prepare(
    `SELECT token, install_code, hwid FROM happ_device_actions
     WHERE token = ? AND user_id = ? AND expires_at > datetime('now')`,
  ).bind(token, telegramId).first<HappDeviceAction>();
  if (!action) return false;
  const subscription = await getActiveSubscription(env, telegramId, "premium");
  if (!subscription?.happ_install_code || subscription.happ_install_code !== action.install_code) return false;
  const devices = await listHappDevices(env, subscription);
  if (!devices.some((device) => device.hwid === action.hwid)) return false;
  const payload = await happRequest(env, subscription.plan,
    `/api/delete-hwid?install_code=${encodeURIComponent(subscription.happ_install_code)}&hwid=${encodeURIComponent(action.hwid)}`,
  );
  const rc = findField(payload, ["rc"]);
  if (rc !== undefined && ![1, "1", true, "success", "ok"].includes(rc as never)) {
    throw new Error(`Happ rejected device removal: ${String(findField(payload, ["msg", "message"]) ?? rc)}`);
  }
  await env.DB.prepare("DELETE FROM happ_device_actions WHERE token = ?").bind(token).run();
  return true;
}

async function answerCallback(env: Env, callbackQueryId: string, text?: string): Promise<void> {
  try {
    await telegramApi(env, "answerCallbackQuery", {
      callback_query_id: callbackQueryId,
      ...(text ? { text } : {}),
    });
  } catch (error) {
    // An expired callback query must not prevent handling its action.
    console.error("answerCallbackQuery failed", error);
  }
}

async function upsertUser(env: Env, user: TelegramUser): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO users (telegram_id, username, first_name)
     VALUES (?, ?, ?)
     ON CONFLICT(telegram_id) DO UPDATE SET
       username = excluded.username,
       first_name = excluded.first_name,
       updated_at = datetime('now')`,
  ).bind(user.id, user.username ?? null, user.first_name ?? null).run();
}

async function getUser(env: Env, telegramId: number): Promise<UserRow | null> {
  return env.DB.prepare("SELECT * FROM users WHERE telegram_id = ?").bind(telegramId).first<UserRow>();
}

async function isChannelMember(env: Env, telegramId: number): Promise<boolean> {
  try {
    requireConfig(env, ["CHANNEL_ID"]);
    const member = await telegramApi<ChatMember>(env, "getChatMember", {
      chat_id: env.CHANNEL_ID,
      user_id: telegramId,
    });
    return MEMBER_STATUSES.has(member.status) || (member.status === "restricted" && member.is_member === true);
  } catch (error) {
    console.error(`getChatMember failed for channel ${env.CHANNEL_ID}: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

function membershipKeyboard(env: Env): unknown {
  const buttons: Array<Array<Record<string, string>>> = [];
  if (env.CHANNEL_INVITE_URL && !env.CHANNEL_INVITE_URL.includes("REPLACE_WITH")) {
    buttons.push([{ text: "Подписаться на канал", url: env.CHANNEL_INVITE_URL }]);
  }
  buttons.push([{ text: "Я подписался — проверить", callback_data: "check_membership" }]);
  return { inline_keyboard: buttons };
}

async function sendMembershipPrompt(env: Env, chatId: number): Promise<void> {
  const invite = env.CHANNEL_INVITE_URL && !env.CHANNEL_INVITE_URL.includes("REPLACE_WITH")
    ? `\nСсылка на канал: ${env.CHANNEL_INVITE_URL}`
    : "";
  await sendMessage(
    env,
    chatId,
    `Чтобы пользоваться ботом, подпишитесь на наш канал, а затем нажмите «Я подписался — проверить».${invite}`,
    membershipKeyboard(env),
  );
}

async function ensureMembership(env: Env, chatId: number, telegramId: number): Promise<boolean> {
  const member = await isChannelMember(env, telegramId);
  if (!member) await sendMembershipPrompt(env, chatId);
  return member;
}

function planKeyboard(): unknown {
  return { inline_keyboard: [
    [{ text: "Выбрать срок Premium", callback_data: "plan:premium" }],
    [{ text: "Попробовать бесплатно — 3 дня", callback_data: "trial" }],
  ] };
}

function durationKeyboard(plan: Plan): unknown {
  return {
    inline_keyboard: DURATIONS.map((duration) => [
      { text: `${duration} мес. — ${PRODUCTS[plan][duration]} ₽`, callback_data: `duration:${plan}:${duration}` },
    ]),
  };
}

function adminKeyboard(): unknown {
  return { inline_keyboard: [
    [{ text: "Создать скидочный промокод", callback_data: "admin:promo:discount" }],
    [{ text: "Создать промокод на дни", callback_data: "admin:promo:days" }],
    [{ text: "Создать бесплатные дни", callback_data: "admin:promo:free_days" }],
    [{ text: "📋 Список промокодов", callback_data: "admin:promo:hub" }],
  ] };
}
function isAdmin(env: Env, telegramId: number): boolean {
  return Boolean(env.ADMIN_TELEGRAM_ID && String(telegramId) === env.ADMIN_TELEGRAM_ID);
}
function normalizePromoCode(value: string): string | null {
  const code = value.trim().toUpperCase();
  return /^[A-Z0-9_-]{3,32}$/.test(code) ? code : null;
}
function promoPrice(days: number, discountPercent: number): number {
  return Math.max(1, Math.round((250 * days / 30) * (100 - discountPercent) / 100));
}
function parsePromoExpiry(value: string | undefined): string | null | undefined {
  if (!value) return null;
  const match = /^(\d{2})\.(\d{2})\.(\d{4})$/.exec(value);
  if (!match) return undefined;
  const [, dayText, monthText, yearText] = match;
  const day = Number(dayText); const month = Number(monthText); const year = Number(yearText);
  const check = new Date(Date.UTC(year, month - 1, day));
  if (check.getUTCFullYear() !== year || check.getUTCMonth() !== month - 1 || check.getUTCDate() !== day) return undefined;
  // Promocodes are entered and shown in Moscow time; 23:59:59 MSK is 20:59:59 UTC.
  return `${yearText}-${monthText}-${dayText} 20:59:59`;
}
async function setInputSession(env: Env, userId: number, kind: string): Promise<void> {
  await env.DB.prepare(`INSERT INTO input_sessions (user_id, kind, expires_at)
    VALUES (?, ?, datetime('now', '+10 minutes'))
    ON CONFLICT(user_id) DO UPDATE SET kind = excluded.kind, expires_at = excluded.expires_at`).bind(userId, kind).run();
}
async function takeInputSession(env: Env, userId: number): Promise<InputSessionRow | null> {
  const session = await env.DB.prepare("SELECT kind, expires_at FROM input_sessions WHERE user_id = ? AND expires_at > datetime('now')").bind(userId).first<InputSessionRow>();
  if (session) await env.DB.prepare("DELETE FROM input_sessions WHERE user_id = ?").bind(userId).run();
  return session ?? null;
}
async function getPromoCode(env: Env, code: string): Promise<PromoCodeRow | null> {
  return env.DB.prepare(`SELECT code, discount_percent, duration_days, max_activations, activation_count, active, free_grant,
      unlimited_activations, expires_at
    FROM promo_codes
    WHERE code = ? AND active = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))`)
    .bind(code).first<PromoCodeRow>();
}
async function reservePromo(env: Env, userId: number, code: string): Promise<boolean> {
  const existing = await env.DB.prepare("SELECT code FROM promo_reservations WHERE user_id = ?").bind(userId).first<{ code: string }>();
  if (existing) return existing.code === code;
  const result = await env.DB.prepare(`UPDATE promo_codes SET activation_count = activation_count + 1, updated_at = datetime('now')
    WHERE code = ? AND active = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))
      AND (unlimited_activations = 1 OR activation_count < max_activations)`).bind(code).run();
  if (Number(result.meta.changes ?? 0) !== 1) return false;
  await env.DB.batch([
    env.DB.prepare("INSERT INTO promo_reservations (user_id, code) VALUES (?, ?)").bind(userId, code),
    // Kept independently of payment status so the admin can distinguish
    // accounts that merely entered a code from successful purchasers.
    env.DB.prepare("INSERT OR IGNORE INTO promo_entries (promo_code, user_id) VALUES (?, ?)").bind(code, userId),
  ]);
  return true;
}
function formatPromoExpiry(expiresAt: string | null): string {
  return expiresAt ? expiresAt.slice(0, 10).split("-").reverse().join(".") : "без даты окончания";
}
function formatPromoLimit(promo: PromoCodeRow): string {
  return promo.unlimited_activations === 1 ? "∞" : String(promo.max_activations);
}
function promoKind(promo: PromoCodeRow): string {
  if (promo.free_grant === 1) return `${promo.duration_days} бесплатных дней`;
  return promo.duration_days ? `${promo.duration_days} дней, скидка ${promo.discount_percent}%` : `скидка ${promo.discount_percent}%`;
}
function promoCurrentWhere(alias = ""): string {
  const p = alias ? `${alias}.` : "";
  return `${p}active = 1 AND (${p}expires_at IS NULL OR ${p}expires_at > datetime('now')) AND (${p}unlimited_activations = 1 OR ${p}activation_count < ${p}max_activations)`;
}
function promoExpiredWhere(alias = ""): string {
  const p = alias ? `${alias}.` : "";
  // “Expired” includes time expiration, a used-up activation limit, and an
  // admin-disabled code. It remains visible for three days, then disappears
  // from the admin UI while the audit records remain intact in D1.
  return `NOT (${promoCurrentWhere(alias)}) AND COALESCE(CASE WHEN ${p}expires_at IS NOT NULL AND ${p}expires_at <= datetime('now') THEN ${p}expires_at ELSE ${p}updated_at END, ${p}created_at) > datetime('now', '-3 days')`;
}
async function sendPromoHub(env: Env, chatId: number): Promise<void> {
  const [current, expired] = await env.DB.batch([
    env.DB.prepare(`SELECT COUNT(*) AS count FROM promo_codes p WHERE ${promoCurrentWhere("p")}`),
    env.DB.prepare(`SELECT COUNT(*) AS count FROM promo_codes p WHERE ${promoExpiredWhere("p")}`),
  ]);
  const currentCount = Number((current.results?.[0] as { count?: number } | undefined)?.count ?? 0);
  const expiredCount = Number((expired.results?.[0] as { count?: number } | undefined)?.count ?? 0);
  await sendMessage(env, chatId, "Промокоды", { inline_keyboard: [
    [{ text: `✅ Действующие (${currentCount})`, callback_data: "admin:promo:list:current:0" }],
    [{ text: `⌛ Истёкшие за 3 дня (${expiredCount})`, callback_data: "admin:promo:list:expired:0" }],
  ] });
}
async function sendPromoList(env: Env, chatId: number, category: "current" | "expired", page: number): Promise<void> {
  const safePage = Math.max(0, Math.min(1000, page));
  const pageSize = 10;
  const where = category === "current" ? promoCurrentWhere("p") : promoExpiredWhere("p");
  const countRow = await env.DB.prepare(`SELECT COUNT(*) AS count FROM promo_codes p WHERE ${where}`).first<{ count: number }>();
  const total = Number(countRow?.count ?? 0);
  const title = category === "current" ? "Действующие промокоды" : "Истёкшие промокоды за последние 3 дня";
  if (total === 0) { await sendMessage(env, chatId, `${title}: нет.`); return; }
  const lastPage = Math.max(0, Math.ceil(total / pageSize) - 1);
  const currentPage = Math.min(safePage, lastPage);
  const result = await env.DB.prepare(`SELECT p.code, p.discount_percent, p.duration_days, p.max_activations, p.activation_count, p.active, p.free_grant,
      p.unlimited_activations, p.expires_at, p.created_at, p.updated_at,
      (SELECT COUNT(*) FROM orders o WHERE o.promo_code = p.code AND o.status = 'paid') AS paid_orders
    FROM promo_codes p WHERE ${where}
    ORDER BY p.updated_at DESC, p.created_at DESC, p.code ASC LIMIT ? OFFSET ?`)
    .bind(pageSize, currentPage * pageSize).all<PromoAdminRow>();
  const rows = result.results.map((promo) => [{
    text: `${category === "current" ? "✅" : "⌛"} ${promo.code} · ${promo.activation_count}/${formatPromoLimit(promo)}`,
    callback_data: `admin:promo:view:${promo.code}:${category}`,
  }]);
  const navigation: Array<{ text: string; callback_data: string }> = [];
  if (currentPage > 0) navigation.push({ text: "‹ Назад", callback_data: `admin:promo:list:${category}:${currentPage - 1}` });
  if (currentPage < lastPage) navigation.push({ text: "Вперёд ›", callback_data: `admin:promo:list:${category}:${currentPage + 1}` });
  if (navigation.length) rows.push(navigation);
  rows.push([{ text: "‹ К разделам", callback_data: "admin:promo:hub" }]);
  await sendMessage(env, chatId, `${title}: ${total}\nСтраница ${currentPage + 1} из ${lastPage + 1}\n\nНажмите на промокод, чтобы открыть информацию:`, { inline_keyboard: rows });
}
async function getPromoEnteredUsers(env: Env, code: string): Promise<PromoUserRow[]> {
  const result = await env.DB.prepare(`SELECT e.user_id, u.username, u.first_name, e.entered_at AS used_at, 'ввёл промокод' AS usage_type
    FROM promo_entries e JOIN users u ON u.telegram_id = e.user_id
    WHERE e.promo_code = ? ORDER BY e.entered_at DESC LIMIT 20`).bind(code).all<PromoUserRow>();
  return result.results;
}
async function getPromoPurchasers(env: Env, code: string): Promise<PromoUserRow[]> {
  const result = await env.DB.prepare(`SELECT user_id, username, first_name, used_at, usage_type FROM (
      SELECT o.user_id, u.username, u.first_name, o.paid_at AS used_at, 'оплатил заказ' AS usage_type
      FROM orders o JOIN users u ON u.telegram_id = o.user_id
      WHERE o.promo_code = ? AND o.status = 'paid'
      UNION ALL
      SELECT a.user_id, u.username, u.first_name, a.created_at AS used_at, 'получил бесплатные дни' AS usage_type
      FROM activation_logs a JOIN users u ON u.telegram_id = a.user_id WHERE a.details LIKE ?
    ) ORDER BY used_at DESC LIMIT 1000`).bind(code, `Free promo ${code}:%`).all<PromoUserRow>();
  return result.results;
}
async function formatPromoPeople(env: Env, users: PromoUserRow[], emptyText: string): Promise<string> {
  if (!users.length) return emptyText;
  const lines: string[] = [];
  for (const user of users) {
    const subscription = await getSubscription(env, user.user_id, "premium");
    let devices = "нет данных";
    if (subscription?.happ_install_code || subscription?.happ_install_id) {
      try {
        const happDevices = await listHappDevices(env, subscription);
        devices = happDevices.length ? happDevices.map(deviceLabel).join(", ") : "нет";
      } catch { devices = "не удалось получить"; }
    }
    const account = user.username ? `@${user.username}` : (user.first_name ? escapeHtml(user.first_name) : "без имени");
    lines.push(`• ${account} · ID <code>${user.user_id}</code>\n  ${user.usage_type}; ${formatPromoExpiry(user.used_at)}\n  Устройства: ${escapeHtml(devices)}`);
  }
  return lines.join("\n");
}
function formatPaidPromoUsersQuotes(users: PromoUserRow[]): string[] {
  if (!users.length) return ["Пока нет успешных покупок или выдач."];
  // Telegram accepts at most 4096 characters per message. Split only when a
  // very large promo exceeds that; every part remains a collapsed quote.
  const chunks: string[] = [];
  let lines: string[] = [];
  let length = 0;
  for (const user of users) {
    const account = user.username ? `@${escapeHtml(user.username)}` : (user.first_name ? escapeHtml(user.first_name) : "без имени");
    const line = `• ${account} · <code>${user.user_id}</code> — ${user.usage_type}`;
    if (lines.length && length + line.length + 1 > 3000) {
      chunks.push(`<blockquote expandable>${lines.join("\n")}</blockquote>`);
      lines = []; length = 0;
    }
    lines.push(line); length += line.length + 1;
  }
  if (lines.length) chunks.push(`<blockquote expandable>${lines.join("\n")}</blockquote>`);
  return chunks;
}
async function sendPromoInfo(env: Env, chatId: number, code: string, category: "current" | "expired" = "current"): Promise<void> {
  const promo = await env.DB.prepare(`SELECT p.code, p.discount_percent, p.duration_days, p.max_activations, p.activation_count,
      p.active, p.free_grant, p.unlimited_activations, p.expires_at, p.created_at, p.updated_at,
      (SELECT COUNT(*) FROM orders o WHERE o.promo_code = p.code AND o.status = 'paid') AS paid_orders
    FROM promo_codes p WHERE p.code = ?`).bind(code).first<PromoAdminRow>();
  if (!promo) { await sendMessage(env, chatId, "Промокод не найден."); return; }
  const current = promo.active === 1 && (promo.expires_at === null || new Date(`${promo.expires_at.replace(" ", "T")}Z`).getTime() > Date.now()) && (promo.unlimited_activations === 1 || promo.activation_count < promo.max_activations);
  const status = current ? "активен" : "истёк или отключён";
  const [enteredUsers, purchasers] = await Promise.all([
    getPromoEnteredUsers(env, promo.code),
    getPromoPurchasers(env, promo.code),
  ]);
  const entered = await formatPromoPeople(env, enteredUsers, "Пока никто не вводил код.");
  const paidUserQuotes = formatPaidPromoUsersQuotes(purchasers);
  const back = `admin:promo:list:${category}:0`;
  const keyboard = current
    ? { inline_keyboard: [[{ text: "🗑 Удалить промокод", callback_data: `admin:promo:delete:${promo.code}` }], [{ text: "📋 К списку", callback_data: back }]] }
    : { inline_keyboard: [[{ text: "📋 К списку", callback_data: back }]] };
  await telegramApi(env, "sendMessage", {
    chat_id: chatId,
    parse_mode: "HTML",
    text: `Промокод: <code>${escapeHtml(promo.code)}</code>\n\nСтатус: ${status}\nУсловия: ${escapeHtml(promoKind(promo))}\nАктивации: ${promo.activation_count} из ${formatPromoLimit(promo)}\nОплаченные покупки: ${promo.paid_orders}\nДействует до: ${formatPromoExpiry(promo.expires_at)}\nСоздан: ${formatPromoExpiry(promo.created_at)}\n\n<b>Кто ввёл промокод:</b>\n${entered}\n\n<b>Кто купил или получил дни:</b>\n${paidUserQuotes[0]}`, 
    reply_markup: keyboard,
  });
  for (let index = 1; index < paidUserQuotes.length; index += 1) {
    await telegramApi(env, "sendMessage", {
      chat_id: chatId,
      parse_mode: "HTML",
      text: `<b>Кто купил или получил дни — продолжение:</b>\n${paidUserQuotes[index]}`,
    });
  }
}
async function takePromoReservation(env: Env, userId: number, code: string): Promise<boolean> {
  const result = await env.DB.prepare("DELETE FROM promo_reservations WHERE user_id = ? AND code = ?").bind(userId, code).run();
  return Number(result.meta.changes ?? 0) === 1;
}

async function sendPlans(env: Env, chatId: number, telegramId: number): Promise<void> {
  const user = await getUser(env, telegramId);
  const trialText = user?.trial_activated
    ? "\nПробный период уже активирован."
    : "\nДоступен бесплатный пробный период на 3 дня (один раз на аккаунт).";
  await sendMessage(
    env,
    chatId,
    `Premium — единая подписка без лишних развилок.${trialText}\n\nПодписку можно подключить на 2 устройства.\n\nВыберите удобный срок или начните с трёх бесплатных дней.`, 
    planKeyboard(),
  );
}

async function sendSubscriptionStatus(env: Env, chatId: number, telegramId: number): Promise<void> {
  const subscription = await getActiveSubscription(env, telegramId, "premium");
  if (!subscription?.expiration_at) {
    await sendMessage(env, chatId, "Сейчас у вас нет активной подписки Premium.");
    return;
  }
  const expiration = new Date(`${subscription.expiration_at.replace(" ", "T")}Z`);
  const days = Math.max(1, Math.ceil((expiration.getTime() - Date.now()) / 86_400_000));
  const date = subscription.expiration_at.slice(0, 10).split("-").reverse().join(".");
  // If an installation was deliberately reset (for example, after its
  // two-device allocation became unusable), /menu creates a fresh Happ
  // InstallID for the same active subscription.
  let current = subscription;
  if (!current.happ_install_code) {
    try {
      await deliverSubscription(env, telegramId, "premium", "Regenerated Happ installation");
      current = (await getActiveSubscription(env, telegramId, "premium")) ?? current;
    } catch (error) {
      console.error(`Could not regenerate Happ installation for ${telegramId}`, error);
    }
  }
  const header = `Активная подписка: Premium\nОсталось: ${days} дн.\nДействует до: ${date}`;
  if (current.happ_install_code) await sendSubscriptionChoice(env, chatId, `${header}\n\nВаша ссылка Happ:`, true, true);
  else await sendMessage(env, chatId, `${header}\n\nНе удалось подготовить ссылку. Попробуйте снова через минуту.`);
}

async function createYooKassaPayment(env: Env, orderId: string, amountRub: number): Promise<string> {
  requireConfig(env, ["YOOKASSA_SHOP_ID", "YOOKASSA_SECRET_KEY"]);
  const authorization = btoa(`${env.YOOKASSA_SHOP_ID}:${env.YOOKASSA_SECRET_KEY}`);
  const response = await fetch("https://api.yookassa.ru/v3/payments", {
    method: "POST",
    headers: { authorization: `Basic ${authorization}`, "content-type": "application/json", "Idempotence-Key": orderId },
    body: JSON.stringify({
      amount: { value: amountRub.toFixed(2), currency: "RUB" },
      capture: true,
      confirmation: { type: "redirect", return_url: `${WORKER_URL}/` },
      metadata: { order_id: orderId },
    }),
  });
  let payment: unknown;
  try { payment = await response.json(); } catch { throw new Error(`YooKassa returned non-JSON response (${response.status})`); }
  if (!response.ok) throw new Error(`YooKassa payment creation failed (${response.status})`);
  const confirmation = payment && typeof payment === "object" ? (payment as Record<string, unknown>).confirmation : null;
  const confirmationUrl = confirmation && typeof confirmation === "object" ? (confirmation as Record<string, unknown>).confirmation_url : null;
  if (typeof confirmationUrl !== "string" || !confirmationUrl.startsWith("https://")) throw new Error("YooKassa response did not include a valid confirmation URL");
  return confirmationUrl;
}

async function createOrder(
  env: Env,
  chatId: number,
  telegramId: number,
  plan: Plan,
  duration: DurationMonths,
  options?: { amountRub?: number; durationDays?: number; displayPeriod?: string; testOrder?: boolean; promoCode?: string },
): Promise<void> {
  requireConfig(env, ["YOOKASSA_SHOP_ID", "YOOKASSA_SECRET_KEY"]);
  const amount = options?.amountRub ?? PRODUCTS[plan][duration];
  const durationDays = options?.durationDays ?? null;
  const displayPeriod = options?.displayPeriod ?? `${duration} мес.`;
  const renewal = isRenewalSubscription(await getSubscription(env, telegramId, plan));
  const orderId = crypto.randomUUID();
  const placeholderUrl = `${WORKER_URL}/`;

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO orders (id, user_id, plan, duration_months, duration_days, amount_rub, promo_code, quickpay_url)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(orderId, telegramId, plan, duration, durationDays, amount, options?.promoCode ?? null, placeholderUrl),
    env.DB.prepare("UPDATE users SET updated_at = datetime('now') WHERE telegram_id = ?").bind(telegramId),
  ]);
  let paymentUrl: string;
  try { paymentUrl = await createYooKassaPayment(env, orderId, amount); }
  catch (error) { await env.DB.prepare("UPDATE orders SET status = 'cancelled' WHERE id = ? AND status = 'pending'").bind(orderId).run(); throw error; }
  await env.DB.prepare("UPDATE orders SET quickpay_url = ? WHERE id = ? AND status = 'pending'").bind(paymentUrl, orderId).run();

  await sendMessage(
    env,
    chatId,
    `${options?.testOrder ? "Тестовый заказ" : renewal ? "Заказ на продление" : "Покупка Premium"}: ${displayPeriod} — ${amount} ₽.\n\nПосле подтверждения платежа бот ${renewal ? "продлит доступ" : "оформит подписку"} и пришлёт ссылку на подписку.`,
    { inline_keyboard: [[{ text: "Оплатить через ЮKassa", url: paymentUrl }]] },
  );
}

async function activateFreePromoDays(env: Env, chatId: number, telegramId: number, code: string, days: number): Promise<void> {
  const wasActive = isRenewalSubscription(await getSubscription(env, telegramId, "premium"));
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO subscriptions (user_id, plan, expiration_at)
       VALUES (?, 'premium', datetime('now', ?))
       ON CONFLICT(user_id, plan) DO UPDATE SET
         expiration_at = datetime(CASE WHEN subscriptions.expiration_at > datetime('now') THEN subscriptions.expiration_at ELSE datetime('now') END, ?),
         updated_at = datetime('now')`,
    ).bind(telegramId, `+${days} days`, `+${days} days`),
    // The existing production schema records non-trial grants as "payment";
    // the details field preserves that this was a free promo issue.
    env.DB.prepare("INSERT INTO activation_logs (user_id, order_id, event_type, details) VALUES (?, NULL, 'payment', ?)")
      .bind(telegramId, `Free promo ${code}: ${days} days`),
  ]);
  await deliverSubscription(env, telegramId, "premium", `Telegram promo ${code}`);
  const status = wasActive ? `Подписка продлена на ${days} дней.` : `Premium активирован на ${days} дней.`;
  await sendSubscriptionChoice(env, chatId, `Промокод ${code} применён — ${status}\n\nВаша ссылка на подписку:`);
}

async function activateTrial(env: Env, chatId: number, telegramId: number): Promise<void> {
  // The subscription upsert is guarded by trial_activated = 0 before that flag
  // is flipped, so repeated callbacks cannot add another three days.
  const results = await env.DB.batch([
    env.DB.prepare(
      `UPDATE subscriptions
       SET happ_install_id = NULL, happ_install_code = NULL, happ_install_link = NULL,
           happ_status = NULL, updated_at = datetime('now')
       WHERE user_id = ? AND plan = 'premium' AND happ_status = 'disabled'
         AND expiration_at IS NOT NULL AND expiration_at <= datetime('now', '-7 days')
         AND EXISTS (SELECT 1 FROM users WHERE telegram_id = ? AND trial_activated = 0)`,
    ).bind(telegramId, telegramId),
    env.DB.prepare(
      `INSERT INTO subscriptions (user_id, plan, expiration_at)
       SELECT ?, 'premium', datetime(
         COALESCE((SELECT CASE WHEN expiration_at > datetime('now') THEN expiration_at ELSE datetime('now') END
                   FROM subscriptions WHERE user_id = ? AND plan = 'premium'), datetime('now')),
         '+3 days'
       )
       WHERE EXISTS (SELECT 1 FROM users WHERE telegram_id = ? AND trial_activated = 0)
       ON CONFLICT(user_id, plan) DO UPDATE SET
         expiration_at = datetime(CASE WHEN subscriptions.expiration_at > datetime('now') THEN subscriptions.expiration_at ELSE datetime('now') END, '+3 days'),
         updated_at = datetime('now')`,
    ).bind(telegramId, telegramId, telegramId),
    env.DB.prepare("UPDATE users SET trial_activated = 1, updated_at = datetime('now') WHERE telegram_id = ? AND trial_activated = 0").bind(telegramId),
    env.DB.prepare(
      `INSERT OR IGNORE INTO activation_logs (user_id, order_id, event_type, details)
       SELECT ?, NULL, 'trial', 'free 3-day Premium trial'
       WHERE EXISTS (SELECT 1 FROM users WHERE telegram_id = ? AND trial_activated = 1)`,
    ).bind(telegramId, telegramId),
  ]);
  const changed = Number(results[2]?.meta?.changes ?? 0) > 0;
  const subscription = await getActiveSubscription(env, telegramId, "premium");
  if (!subscription) {
    await sendMessage(env, chatId, "Бесплатный пробный период уже был активирован ранее.");
    return;
  }
  await deliverSubscription(env, telegramId, "premium", "Telegram Premium trial");
  const prefix = changed ? "Пробный период активирован." : "Пробный период уже активирован; восстанавливаем доступ.";
  await sendSubscriptionChoice(env, chatId, [prefix, "Тариф: Premium", "Срок: 3 дня (пробный период)", "", "Ссылка на подписку Happ:"].join("\n"));
}

let rateLimitTableReady: Promise<void> | null = null;

async function allowTelegramAction(env: Env, userId: number): Promise<boolean> {
  // The table is created lazily, so the protection can be deployed without
  // interrupting the existing bot or requiring a separate database migration.
  if (!rateLimitTableReady) {
    rateLimitTableReady = env.DB.prepare(
      "CREATE TABLE IF NOT EXISTS telegram_rate_limits (user_id INTEGER PRIMARY KEY, window_started_ms INTEGER NOT NULL, action_count INTEGER NOT NULL)",
    ).run().then(() => undefined).catch((error) => { rateLimitTableReady = null; throw error; });
  }
  try {
    await rateLimitTableReady;
    const now = Date.now();
    const result = await env.DB.prepare(
      `INSERT INTO telegram_rate_limits (user_id, window_started_ms, action_count) VALUES (?, ?, 1)
       ON CONFLICT(user_id) DO UPDATE SET
         action_count = CASE WHEN ? - window_started_ms >= 2000 THEN 1 ELSE action_count + 1 END,
         window_started_ms = CASE WHEN ? - window_started_ms >= 2000 THEN excluded.window_started_ms ELSE window_started_ms END
       RETURNING action_count`,
    ).bind(userId, now, now, now).first<{ action_count: number }>();
    return (result?.action_count ?? 1) <= 3;
  } catch (error) {
    // A temporary database problem must not make the bot unavailable.
    console.error("Rate-limit check failed", error);
    return true;
  }
}

async function rejectFrequentAction(env: Env, chatId: number): Promise<void> {
  await sendMessage(env, chatId, "Слишком часто. Подождите пару секунд.");
}

function parseDuration(value: string): DurationMonths | null {
  const duration = Number(value);
  return DURATIONS.includes(duration as DurationMonths) ? (duration as DurationMonths) : null;
}

async function handleCallback(env: Env, callback: TelegramCallbackQuery): Promise<void> {
  const chatId = callback.message?.chat.id ?? callback.from.id;
  const data = callback.data ?? "";
  await upsertUser(env, callback.from);
  await answerCallback(env, callback.id);
  // Payment creation and promo redemption must stay responsive even during
  // repeated taps; the normal per-user limit protects the remaining UI.
  const exemptFromRateLimit = data === "promo:redeem"
    || data.startsWith("promo_duration:")
    || data.startsWith("duration:");
  // The owner is never rate-limited, so administrative recovery remains available.
  if (!isAdmin(env, callback.from.id) && !exemptFromRateLimit && !(await allowTelegramAction(env, callback.from.id))) {
    await rejectFrequentAction(env, chatId);
    return;
  }

  if (data === "admin:promo:hub") {
    if (!isAdmin(env, callback.from.id)) { await sendMessage(env, chatId, "Команда доступна только администратору."); return; }
    await sendPromoHub(env, chatId);
    return;
  }
  if (data.startsWith("admin:promo:list:")) {
    if (!isAdmin(env, callback.from.id)) { await sendMessage(env, chatId, "Команда доступна только администратору."); return; }
    const [, , , categoryRaw, pageRaw] = data.split(":");
    const category = categoryRaw === "expired" ? "expired" : "current";
    const page = Number(pageRaw);
    await sendPromoList(env, chatId, category, Number.isInteger(page) && page >= 0 ? page : 0);
    return;
  }
  if (data.startsWith("admin:promo:view:")) {
    if (!isAdmin(env, callback.from.id)) { await sendMessage(env, chatId, "Команда доступна только администратору."); return; }
    const [, , , codeRaw, categoryRaw] = data.split(":");
    const code = normalizePromoCode(codeRaw ?? "");
    if (!code) { await sendMessage(env, chatId, "Промокод не найден."); return; }
    await sendPromoInfo(env, chatId, code, categoryRaw === "expired" ? "expired" : "current");
    return;
  }
  if (data.startsWith("admin:promo:delete:")) {
    if (!isAdmin(env, callback.from.id)) { await sendMessage(env, chatId, "Команда доступна только администратору."); return; }
    const code = normalizePromoCode(data.slice("admin:promo:delete:".length));
    if (!code) { await sendMessage(env, chatId, "Промокод не найден."); return; }
    const result = await env.DB.prepare("UPDATE promo_codes SET active = 0, updated_at = datetime('now') WHERE code = ? AND active = 1").bind(code).run();
    await sendMessage(env, chatId, Number(result.meta.changes ?? 0) === 1 ? `Промокод ${code} удалён и больше не применяется.` : "Промокод уже удалён или не найден.");
    return;
  }
  if (data === "admin:promo:discount" || data === "admin:promo:days" || data === "admin:promo:free_days") {
    if (!isAdmin(env, callback.from.id)) { await sendMessage(env, chatId, "Команда доступна только администратору."); return; }
    const freeDays = data === "admin:promo:free_days";
    const days = data === "admin:promo:days";
    await setInputSession(env, callback.from.id, freeDays ? "admin_promo_free_days" : days ? "admin_promo_days" : "admin_promo_discount");
    await sendMessage(env, chatId, freeDays
      ? "Отправьте: КОД КОЛИЧЕСТВО_ДНЕЙ КОЛИЧЕСТВО_АКТИВАЦИЙ [ДД.ММ.ГГГГ]\n0 активаций = без лимита. Дата необязательна.\nПример: GIFT7 7 0 31.12.2026"
      : days
        ? "Отправьте: КОД КОЛИЧЕСТВО_ДНЕЙ СКИДКА_ПРОЦЕНТОВ КОЛИЧЕСТВО_АКТИВАЦИЙ [ДД.ММ.ГГГГ]\n0 активаций = без лимита. Дата необязательна.\nПример: PROMO14 14 25 30 31.12.2026"
        : "Отправьте: КОД СКИДКА_ПРОЦЕНТОВ КОЛИЧЕСТВО_АКТИВАЦИЙ [ДД.ММ.ГГГГ]\n0 активаций = без лимита. Дата необязательна.\nПример: SALE20 20 0 31.12.2026");
    return;
  }
  if (data === "promo:redeem") {
    await setInputSession(env, callback.from.id, "redeem_promo");
    await sendMessage(env, chatId, "Отправьте промокод одним сообщением.");
    return;
  }
  if (data === "happ:devices") {
    if (!(await ensureMembership(env, chatId, callback.from.id))) return;
    try {
      await sendHappDevices(env, chatId, callback.from.id);
    } catch (error) {
      console.error(`Could not list Happ devices for ${callback.from.id}`, error);
      await sendMessage(env, chatId, "Не удалось получить список устройств. Попробуйте через минуту.");
    }
    return;
  }
  if (data.startsWith("happ:device:remove:")) {
    if (!(await ensureMembership(env, chatId, callback.from.id))) return;
    try {
      const removed = await removeHappDevice(env, callback.from.id, data.slice("happ:device:remove:".length));
      if (!removed) {
        await sendMessage(env, chatId, "Эта кнопка устарела. Откройте «📱 Устройства» ещё раз.");
        return;
      }
      await sendMessage(env, chatId, "Устройство отключено.");
      await sendHappDevices(env, chatId, callback.from.id);
    } catch (error) {
      console.error(`Could not remove Happ device for ${callback.from.id}`, error);
      await sendMessage(env, chatId, "Не удалось отключить устройство. Попробуйте через минуту.");
    }
    return;
  }
  if (data === "happ:reissue") {
    if (!(await ensureMembership(env, chatId, callback.from.id))) return;
    try {
      await reissueHappSubscription(env, callback.from.id, "premium");
      await sendSubscriptionChoice(env, chatId, "Ссылка перевыпущена. Старая ссылка больше не работает.");
    } catch (error) {
      console.error(`Could not reissue Happ subscription for ${callback.from.id}`, error);
      await sendMessage(env, chatId, "Не удалось перевыпустить ссылку. Попробуйте через минуту.");
    }
    return;
  }
  if (data === "happ:android" || data === "happ:ios") {
    if (!(await ensureMembership(env, chatId, callback.from.id))) return;
    await sendPlatformSubscriptionLink(env, chatId, callback.from.id, data === "happ:android" ? "android" : "ios");
    return;
  }
  if (data === "happ:guide") {
    await sendMessage(env, chatId,
      "Как подключить Happ:\n\n1. Установите приложение:\n• Android — Happ из Google Play (Play Маркет).\n• iPhone/iPad (iOS) — обычный Happ из App Store.\n\n2. В боте выберите кнопку своего устройства.\n3. Нажмите на моноширинную ссылку — она скопируется в буфер обмена.\n4. Откройте Happ и нажмите «+».\n5. Выберите «Импортировать из буфера обмена», подтвердите добавление и включите подключение.\n\nНе передавайте вашу ссылку другим людям.",
    );
    return;
  }
  if (data === "check_membership") {
    if (await ensureMembership(env, chatId, callback.from.id)) {
      await sendMessage(env, chatId, "Подписка подтверждена.");
      await sendPlans(env, chatId, callback.from.id);
    }
    return;
  }

  if (!(await ensureMembership(env, chatId, callback.from.id))) return;

  if (data === "trial") {
    await activateTrial(env, chatId, callback.from.id);
    return;
  }
  if (data === "plans") {
    await sendPlans(env, chatId, callback.from.id);
    return;
  }
  if (data.startsWith("plan:")) {
    const plan = data.slice("plan:".length);
    if (plan === "premium") {
      await sendMessage(env, chatId, `Premium — выберите срок подписки.\n\nПодписку можно подключить на 2 устройства:`, durationKeyboard(plan));
    }
    return;
  }
  if (data.startsWith("promo_duration:")) {
    const [, code, durationValue] = data.split(":");
    const promo = code ? await getPromoCode(env, code) : null;
    const duration = durationValue ? parseDuration(durationValue) : null;
    if (!promo || promo.duration_days || !duration) { await sendMessage(env, chatId, "Промокод недействителен."); return; }
    if (!(await takePromoReservation(env, callback.from.id, promo.code))) { await sendMessage(env, chatId, "Сначала введите промокод заново."); return; }
    const amount = Math.max(1, Math.round(PRODUCTS.premium[duration] * (100 - promo.discount_percent) / 100));
    await createOrder(env, chatId, callback.from.id, "premium", duration, { amountRub: amount, displayPeriod: `${duration} мес. со скидкой ${promo.discount_percent}%`, promoCode: promo.code });
    return;
  }
  if (data.startsWith("duration:")) {
    const [, planValue, durationValue] = data.split(":");
    if (planValue === "premium" && durationValue) {
      const duration = parseDuration(durationValue);
      if (duration) await createOrder(env, chatId, callback.from.id, planValue, duration);
    }
  }
}

function isCommand(text: string, command: string): boolean {
  const first = text.trim().split(/\s+/)[0].toLowerCase();
  return first === command || first.startsWith(`${command}@`);
}

async function sendOrders(env: Env, chatId: number): Promise<void> {
  const result = await env.DB.prepare(
    `SELECT id, user_id, plan, duration_months, amount_rub, status, created_at, paid_at
     FROM orders ORDER BY created_at DESC LIMIT 20`,
  ).all<Pick<OrderRow, "id" | "user_id" | "plan" | "duration_months" | "amount_rub" | "status" | "created_at" | "paid_at">>();
  if (result.results.length === 0) {
    await sendMessage(env, chatId, "Заказов пока нет.");
    return;
  }
  const lines = result.results.map((order) =>
    `${order.status.toUpperCase()} ${order.id}\nuser ${order.user_id} · ${order.plan.toUpperCase()} ${order.duration_months}м · ${order.amount_rub} ₽ · ${order.created_at}`,
  );
  await sendMessage(env, chatId, `Последние заказы:\n\n${lines.join("\n\n")}`);
}

async function handleMessage(env: Env, message: TelegramMessage): Promise<void> {
  if (!message.from || !message.text || message.from.is_bot) return;
  const text = message.text.trim();
  await upsertUser(env, message.from);
  // A promo code is sent as a one-message form, so it must not be rejected
  // by the general interaction limiter. Promo reservations still enforce
  // their own activation limits.
  const promoInput = isCommand(text, "/promo") || Boolean(await env.DB.prepare(
    "SELECT 1 FROM input_sessions WHERE user_id = ? AND kind = 'redeem_promo' AND expires_at > datetime('now')",
  ).bind(message.from.id).first());
  // The owner is never rate-limited, so administrative recovery remains available.
  if (!isAdmin(env, message.from.id) && !promoInput && !(await allowTelegramAction(env, message.from.id))) {
    await rejectFrequentAction(env, message.chat.id);
    return;
  }

  // Commands must always win over a pending form input. In particular, this
  // lets the administrator reopen /admin after abandoning a promo draft.
  if (isCommand(text, "/admin")) {
    await env.DB.prepare("DELETE FROM input_sessions WHERE user_id = ?").bind(message.from.id).run();
    if (!isAdmin(env, message.from.id)) await sendMessage(env, message.chat.id, "Команда доступна только администратору.");
    else await sendMessage(env, message.chat.id, "Админ-панель промокодов:", adminKeyboard());
    return;
  }

  const session = await takeInputSession(env, message.from.id);
  if (session) {
    if (session.kind === "redeem_promo") {
      const code = normalizePromoCode(text);
      const promo = code ? await getPromoCode(env, code) : null;
      if (!promo) { await sendMessage(env, message.chat.id, "Промокод не найден или отключён."); return; }
      if (!(await reservePromo(env, message.from.id, promo.code))) { await sendMessage(env, message.chat.id, "Лимит активаций этого промокода закончился."); return; }
      if (promo.duration_days) {
        if (promo.free_grant === 1) {
          await takePromoReservation(env, message.from.id, promo.code);
          await activateFreePromoDays(env, message.chat.id, message.from.id, promo.code, promo.duration_days);
        } else {
          const amount = promoPrice(promo.duration_days, promo.discount_percent);
          await createOrder(env, message.chat.id, message.from.id, "premium", 1, { amountRub: amount, durationDays: promo.duration_days, displayPeriod: `${promo.duration_days} дней со скидкой ${promo.discount_percent}%`, promoCode: promo.code });
          await takePromoReservation(env, message.from.id, promo.code);
        }
      } else {
        const buttons = DURATIONS.map((duration) => [{ text: `${duration} мес. — ${Math.max(1, Math.round(PRODUCTS.premium[duration] * (100 - promo.discount_percent) / 100))} ₽`, callback_data: `promo_duration:${promo.code}:${duration}` }]);
        await sendMessage(env, message.chat.id, `Промокод ${promo.code} применён: скидка ${promo.discount_percent}%. Выберите срок:`, { inline_keyboard: buttons });
      }
      return;
    }
    if ((session.kind === "admin_promo_discount" || session.kind === "admin_promo_days" || session.kind === "admin_promo_free_days") && isAdmin(env, message.from.id)) {
      const parts = text.trim().split(/\s+/);
      const code = normalizePromoCode(parts[0] ?? "");
      const freeDays = session.kind === "admin_promo_free_days";
      const hasDays = session.kind === "admin_promo_days" || freeDays;
      const days = hasDays ? Number(parts[1]) : null;
      // The legacy schema caps the numeric discount at 99. Free days are
      // identified by free_grant, not by a 100% numeric discount.
      const percentIndex = session.kind === "admin_promo_days" ? 2 : 1;
      const activationIndex = freeDays ? 2 : session.kind === "admin_promo_days" ? 3 : 2;
      const expiryIndex = activationIndex + 1;
      const expectedParts = [activationIndex + 1, activationIndex + 2];
      const percent = freeDays ? 99 : Number(parts[percentIndex]);
      const activations = Number(parts[activationIndex]);
      const expiry = parsePromoExpiry(parts[expiryIndex]);
      if (!code || !expectedParts.includes(parts.length) || !Number.isInteger(percent) || (!freeDays && (percent < 1 || percent > 99)) || !Number.isInteger(activations) || activations < 0 || activations > 100000 || expiry === undefined || (days !== null && (!Number.isInteger(days) || days < 1 || days > 3650))) {
        await sendMessage(env, message.chat.id, freeDays ? "Неверный формат. Пример: GIFT7 7 0 31.12.2026" : session.kind === "admin_promo_days" ? "Неверный формат. Пример: PROMO14 14 25 30 31.12.2026" : "Неверный формат. Пример: SALE20 20 0 31.12.2026");
        return;
      }
      const unlimited = activations === 0 ? 1 : 0;
      // The old table requires a positive max_activations. A harmless sentinel
      // is used for unlimited codes; the unlimited flag controls all checks.
      const storedLimit = unlimited ? 1 : activations;
      await env.DB.prepare(`INSERT INTO promo_codes (code, discount_percent, duration_days, max_activations, activation_count, active, free_grant, unlimited_activations, expires_at, created_by)
        VALUES (?, ?, ?, ?, 0, 1, ?, ?, ?, ?) ON CONFLICT(code) DO UPDATE SET discount_percent = excluded.discount_percent, duration_days = excluded.duration_days, max_activations = excluded.max_activations, activation_count = 0, active = 1, free_grant = excluded.free_grant, unlimited_activations = excluded.unlimited_activations, expires_at = excluded.expires_at, created_by = excluded.created_by, updated_at = datetime('now')`).bind(code, percent, days, storedLimit, freeDays ? 1 : 0, unlimited, expiry, message.from.id).run();
      const description = freeDays ? `${days} бесплатных дней` : days === null ? `скидка ${percent}% на обычные тарифы` : `${days} дней, скидка ${percent}%, цена ${promoPrice(days, percent)} ₽`;
      const limitText = unlimited ? "без лимита" : String(activations);
      const expiryText = expiry ? ` Действует до: ${formatPromoExpiry(expiry)}.` : " Без даты окончания.";
      await telegramApi(env, "sendMessage", {
        chat_id: message.chat.id,
        text: `Промокод создан:\n<code>${code}</code>\n\n${escapeHtml(description)}. Активаций: ${limitText}.${expiryText}`,
        parse_mode: "HTML",
      });
      return;
    }
  }

  if (isCommand(text, "/admin")) {
    if (!isAdmin(env, message.from.id)) await sendMessage(env, message.chat.id, "Команда доступна только администратору.");
    else await sendMessage(env, message.chat.id, "Админ-панель промокодов:", adminKeyboard());
    return;
  }

  if (isCommand(text, "/orders")) {
    if (env.ADMIN_TELEGRAM_ID && String(message.from.id) === env.ADMIN_TELEGRAM_ID) {
      await sendOrders(env, message.chat.id);
    } else {
      await sendMessage(env, message.chat.id, "Команда доступна только администратору.");
    }
    return;
  }

  if (isCommand(text, "/promo")) {
    await setInputSession(env, message.from.id, "redeem_promo");
    await sendMessage(env, message.chat.id, "Отправьте промокод одним сообщением.");
    return;
  }

  if (isCommand(text, "/start")) {
    await sendMessage(env, message.chat.id, "Привет! 👋\n\nДобро пожаловать в BananchikiVpn. Сервис помогает с доступом к интернету при белых списках и ограничениях сети.");
    if (!(await ensureMembership(env, message.chat.id, message.from.id))) return;
    await sendPlans(env, message.chat.id, message.from.id);
    return;
  }

  if (isCommand(text, "/menu")) {
    if (!(await ensureMembership(env, message.chat.id, message.from.id))) return;
    await sendSubscriptionStatus(env, message.chat.id, message.from.id);
    return;
  }

  if (isCommand(text, "/sub")) {
    if (!(await ensureMembership(env, message.chat.id, message.from.id))) return;
    await sendMessage(env, message.chat.id, "Premium — выберите срок подписки.\n\nПодписку можно подключить на 2 устройства:", durationKeyboard("premium"));
    return;
  }

  if (isCommand(text, "/plans") || isCommand(text, "/buy")) {
    if (!(await ensureMembership(env, message.chat.id, message.from.id))) return;
    await sendPlans(env, message.chat.id, message.from.id);
    return;
  }

  if (isCommand(text, "/trial")) {
    if (!(await ensureMembership(env, message.chat.id, message.from.id))) return;
    await activateTrial(env, message.chat.id, message.from.id);
    return;
  }

  await sendMessage(
    env,
    message.chat.id,
    "Напишите /start — я проверю подписку на канал и помогу оформить Premium. Один раз можно начать с бесплатных трёх дней.",
  );
}

function rubleKopeks(value: string): number | null {
  if (!/^\d+(?:\.\d{1,2})?$/.test(value)) return null;
  const [whole, fraction = ""] = value.split(".");
  const result = Number(whole) * 100 + Number(fraction.padEnd(2, "0"));
  return Number.isSafeInteger(result) ? result : null;
}

function constantTimeEqual(left: string, right: string): boolean {
  let difference = left.length ^ right.length;
  const max = Math.max(left.length, right.length);
  for (let index = 0; index < max; index += 1) {
    difference |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
}

async function sha1Hex(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-1", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function signedYoomoneyString(params: URLSearchParams, secret: string): string {
  // This is the exact official YooMoney check string, in this order.
  return [
    params.get("notification_type") ?? "",
    params.get("operation_id") ?? "",
    params.get("amount") ?? "",
    params.get("currency") ?? "",
    params.get("datetime") ?? "",
    params.get("sender") ?? "",
    params.get("codepro") ?? "",
    secret,
    params.get("label") ?? "",
  ].join("&");
}

async function fulfilPaidOrder(env: Env, order: OrderRow): Promise<{ buyer: UserRow; link: string }> {
  const buyer = await getUser(env, order.user_id);
  if (!buyer) throw new Error("order owner does not exist");
  const link = await deliverSubscription(env, buyer.telegram_id, order.plan, `YooMoney ${order.plan.toUpperCase()} ${order.duration_months}m`);
  return { buyer, link };
}

interface PaidNotification {
  operationId: string; amount: string; currency: string; notificationType: string;
  paymentDatetime: string; sender: string; codepro: string; label: string; rawHash: string;
}

async function finalizePaidOrder(env: Env, order: OrderRow, notification: PaidNotification): Promise<string> {
  const { operationId, amount, currency, notificationType, paymentDatetime, sender, codepro, label, rawHash } = notification;
  const existingPayment = await env.DB.prepare("SELECT order_id, operation_id FROM payments WHERE operation_id = ?").bind(operationId).first<PaymentRow>();
  if (existingPayment && existingPayment.order_id !== order.id) throw new Error("operation already belongs to another order");
  if (order.status === "paid") {
    if (order.operation_id === operationId || existingPayment?.order_id === order.id) {
      await fulfilPaidOrder(env, order);
      return "OK";
    }
    throw new Error("order is already paid with another operation");
  }
  if (order.status !== "pending") throw new Error("order is not payable");
  const buyer = await getUser(env, order.user_id);
  if (!buyer) throw new Error("order owner does not exist");
  const renewal = isRenewalSubscription(await getSubscription(env, order.user_id, order.plan));
  const results = await env.DB.batch([
    env.DB.prepare(`INSERT OR IGNORE INTO payments
      (order_id, operation_id, amount, currency, notification_type, payment_datetime, sender, codepro, label, raw_sha1)
      SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM orders WHERE id = ? AND status = 'pending')
      AND NOT EXISTS (SELECT 1 FROM payments WHERE operation_id = ?)`)
      .bind(order.id, operationId, amount, currency, notificationType, paymentDatetime, sender, codepro, label, rawHash, order.id, operationId),
    env.DB.prepare(`UPDATE orders SET status = 'paid', paid_at = datetime('now'), operation_id = ?
      WHERE id = ? AND status = 'pending' AND EXISTS (SELECT 1 FROM payments WHERE operation_id = ? AND order_id = ?)`)
      .bind(operationId, order.id, operationId, order.id),
    env.DB.prepare(`UPDATE subscriptions SET happ_install_id = NULL, happ_install_code = NULL, happ_install_link = NULL,
      happ_status = NULL, updated_at = datetime('now') WHERE user_id = ? AND plan = ? AND happ_status = 'disabled'
      AND expiration_at IS NOT NULL AND expiration_at <= datetime('now', '-7 days')`).bind(order.user_id, order.plan),
    env.DB.prepare(`INSERT INTO subscriptions (user_id, plan, expiration_at) VALUES (?, ?, datetime('now', ?))
      ON CONFLICT(user_id, plan) DO UPDATE SET expiration_at = datetime(CASE WHEN subscriptions.expiration_at > datetime('now')
      THEN subscriptions.expiration_at ELSE datetime('now') END, ?), updated_at = datetime('now')`)
      .bind(order.user_id, order.plan, order.duration_days ? `+${order.duration_days} days` : `+${order.duration_months} months`, order.duration_days ? `+${order.duration_days} days` : `+${order.duration_months} months`),
    env.DB.prepare(`INSERT OR IGNORE INTO activation_logs (user_id, order_id, event_type, details)
      SELECT ?, ?, 'payment', ? WHERE EXISTS (SELECT 1 FROM orders WHERE id = ? AND status = 'paid')`)
      .bind(order.user_id, order.id, `${notificationType} operation ${operationId}`, order.id),
  ]);
  if (Number(results[1]?.meta?.changes ?? 0) === 0) return "OK";
  await fulfilPaidOrder(env, order);
  try {
    const period = order.duration_days ? `${order.duration_days} дней` : `${order.duration_months} мес.`;
    const status = renewal ? `Подписка продлена на ${period}.` : `Premium оформлен на ${period}.`;
    await sendSubscriptionChoice(env, order.user_id, `Оплата подтверждена — ${status}\n\nВаша ссылка на подписку:\n\nНомер заказа: ${order.id}`);
  } catch (error) { console.error("Could not notify buyer after payment", error); }
  return "OK";
}

async function processYoomoneyNotification(env: Env, body: string): Promise<string> {
  if (body.length > 64 * 1024) throw new Error("notification body is too large");
  requireConfig(env, ["YOOMONEY_NOTIFICATION_SECRET"]);
  const params = new URLSearchParams(body);
  const notificationType = params.get("notification_type");
  const operationId = params.get("operation_id");
  const amount = params.get("amount");
  const withdrawAmount = params.get("withdraw_amount");
  const currency = params.get("currency");
  const paymentDatetime = params.get("datetime");
  const sender = params.get("sender") ?? "";
  const codepro = params.get("codepro") ?? "";
  const unaccepted = params.get("unaccepted") ?? "false";
  const label = params.get("label");
  const receivedHash = params.get("sha1_hash");
  if (!notificationType || !operationId || !amount || !currency || !paymentDatetime || !label || !receivedHash) throw new Error("missing YooMoney notification fields");
  const expectedHash = await sha1Hex(signedYoomoneyString(params, env.YOOMONEY_NOTIFICATION_SECRET));
  if (!constantTimeEqual(expectedHash, receivedHash.toLowerCase())) throw new Error("invalid YooMoney signature");
  if (codepro.toLowerCase() === "true") throw new Error("code-protected payment is not accepted");
  if (unaccepted.toLowerCase() === "true") throw new Error("unaccepted payment is not accepted");
  if (currency !== "643" && currency !== "RUB") throw new Error("unsupported payment currency");

  const order = await env.DB.prepare("SELECT * FROM orders WHERE id = ?").bind(label).first<OrderRow>();
  if (!order) throw new Error("unknown order label");
  // YooMoney may deduct its card-payment fee from the receiver's credit.
  // In that case `amount` is lower than the requested sum, while
  // `withdraw_amount` remains the exact amount paid by the buyer.
  const receivedKopeks = rubleKopeks(amount);
  const withdrawnKopeks = withdrawAmount ? rubleKopeks(withdrawAmount) : null;
  const expectedKopeks = order.amount_rub * 100;
  if (receivedKopeks !== expectedKopeks && withdrawnKopeks !== expectedKopeks) {
    throw new Error("payment amount does not match order");
  }
  return finalizePaidOrder(env, order, {
    operationId, amount, currency, notificationType, paymentDatetime, sender, codepro,
    label, rawHash: receivedHash,
  });
}

async function processYooKassaNotification(env: Env, body: string): Promise<string> {
  if (body.length > 64 * 1024) throw new Error("notification body is too large");
  let payload: unknown;
  try { payload = JSON.parse(body); } catch { throw new Error("invalid JSON notification"); }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("invalid notification object");
  const event = payload as Record<string, unknown>;
  if (event.event !== "payment.succeeded" || !event.object || typeof event.object !== "object" || Array.isArray(event.object)) throw new Error("unsupported notification");
  const payment = event.object as Record<string, unknown>;
  if (payment.status !== "succeeded") throw new Error("payment is not succeeded");
  if (typeof payment.id !== "string" || !payment.id) throw new Error("missing payment id");
  if (!payment.metadata || typeof payment.metadata !== "object" || Array.isArray(payment.metadata)) throw new Error("missing payment metadata");
  const orderId = (payment.metadata as Record<string, unknown>).order_id;
  if (typeof orderId !== "string" || !orderId) throw new Error("missing order id");
  if (!payment.amount || typeof payment.amount !== "object" || Array.isArray(payment.amount)) throw new Error("missing payment amount");
  const amount = payment.amount as Record<string, unknown>;
  if (amount.currency !== "RUB" || typeof amount.value !== "string") throw new Error("unsupported payment currency or amount");
  const order = await env.DB.prepare("SELECT * FROM orders WHERE id = ?").bind(orderId).first<OrderRow>();
  if (!order) throw new Error("unknown order id");
  const amountKopeks = rubleKopeks(amount.value);
  if (amountKopeks === null || amountKopeks !== order.amount_rub * 100) throw new Error("payment amount does not match order");
  const paymentDatetime = typeof payment.created_at === "string" ? payment.created_at : new Date().toISOString();
  return finalizePaidOrder(env, order, {
    operationId: payment.id, amount: amount.value, currency: "RUB", notificationType: "YooKassa",
    paymentDatetime, sender: "", codepro: "false", label: orderId, rawHash: "",
  });
}

async function handleTelegramWebhook(env: Env, request: Request): Promise<Response> {
  requireConfig(env, ["TELEGRAM_WEBHOOK_SECRET"]);
  if (request.headers.get("X-Telegram-Bot-Api-Secret-Token") !== env.TELEGRAM_WEBHOOK_SECRET) {
    return textResponse("forbidden", 403);
  }
  let update: TelegramUpdate;
  try {
    update = (await request.json()) as TelegramUpdate;
  } catch {
    return textResponse("invalid json", 400);
  }
  try {
    if (update.callback_query) await handleCallback(env, update.callback_query);
    else if (update.message) await handleMessage(env, update.message);
    return json({ ok: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`Telegram update handling failed: ${message}`, error);
    // Telegram can retry a webhook after a 5xx. The update was valid, so keep
    // the response successful while logging the actionable server-side error.
    return json({ ok: true });
  }
}

async function ensureTelegramWebhook(env: Env): Promise<void> {
  requireConfig(env, ["TELEGRAM_BOT_TOKEN", "TELEGRAM_WEBHOOK_SECRET"]);
  const webhookUrl = "https://telegram-vpn-bot.bobritogusingo.workers.dev/telegram";
  await telegramApi<boolean>(env, "setWebhook", {
    url: webhookUrl,
    secret_token: env.TELEGRAM_WEBHOOK_SECRET,
    allowed_updates: ["message", "callback_query"],
    drop_pending_updates: false,
  });
}

async function disableExpiredSubscriptions(env: Env): Promise<void> {
  const expired = await env.DB.prepare(
    `SELECT user_id, plan, happ_install_id FROM subscriptions
     WHERE happ_install_id IS NOT NULL AND happ_status = 'active'
       AND expiration_at IS NOT NULL AND expiration_at <= datetime('now') LIMIT 100`,
  ).all<Pick<SubscriptionRow, "user_id" | "plan" | "happ_install_id">>();
  for (const subscription of expired.results) {
    if (!subscription.happ_install_id) continue;
    try {
      // Keep the Happ installation registered so its two-device record remains
      // intact and Happ can fetch the expiry notice from this Worker. The
      // Worker serves only blackhole entries after expiration; no usable
      // server configuration remains available. The local disabled status
      // preserves the existing seven-day renewal/new-link rule.
      await env.DB.prepare(
        "UPDATE subscriptions SET happ_status = 'disabled', updated_at = datetime('now') WHERE user_id = ? AND plan = ? AND happ_install_id = ? AND happ_status = 'active'",
      ).bind(subscription.user_id, subscription.plan, subscription.happ_install_id).run();
    } catch (error) {
      console.error(`Could not mark expired ${subscription.plan} subscription for ${subscription.user_id}`, error);
    }
  }
}

export default {
  async scheduled(_controller: ScheduledController, env: Env, _ctx: ExecutionContext): Promise<void> {
    try {
      await ensureTelegramWebhook(env);
    } catch (error) {
      console.error("Could not configure Telegram webhook", error);
    }
    await disableExpiredSubscriptions(env);
  },
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (request.method === "GET" && url.pathname.startsWith("/subscription/")) {
        return await serveHappSubscription(env, url.pathname.slice("/subscription/".length));
      }
      if (request.method === "GET" && url.pathname.startsWith("/pay/")) {
        const orderId = url.pathname.slice("/pay/".length);
        return await yoomoneyPaymentPage(env, orderId, url.searchParams.get("method"));
      }
      if (request.method === "GET" && url.pathname === "/health") {
        // A successful health check also repairs the Telegram webhook. This
        // makes recovery independent of the maintenance schedule and does
        // not expose credentials or change subscription data.
        await ensureTelegramWebhook(env);
        const webhookInfo = await telegramApi<unknown>(env, "getWebhookInfo", {});
        return json({ ok: true, service: "telegram-subscription-bot", webhook: webhookInfo });
      }
      if (request.method === "POST" && url.pathname === "/telegram") {
        return await handleTelegramWebhook(env, request);
      }
      if (request.method === "POST" && url.pathname === "/yookassa") {
        const body = await request.text();
        try {
          return textResponse(await processYooKassaNotification(env, body));
        } catch (error) {
          console.error("YooKassa notification rejected", error);
          return textResponse("invalid notification", 400);
        }
      }
      if (request.method === "POST" && url.pathname === "/yoomoney") {
        const body = await request.text();
        try {
          return textResponse(await processYoomoneyNotification(env, body));
        } catch (error) {
          console.error("YooMoney notification rejected", error);
          return textResponse("invalid notification", 400);
        }
      }
      return json({ error: "Not found" }, 404);
    } catch (error) {
      console.error("Request failed", error);
      return json({ error: "Server configuration or internal error" }, 500);
    }
  },
};

