require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const OpenAI = require('openai');
const axios = require('axios');
const Stripe = require('stripe');

const app = express();
const PORT = process.env.PORT || 3001;
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://www.typyzpiwnicy.pl';
const TRIAL_DAYS = Math.max(Number.parseInt(process.env.TRIAL_DAYS || '3', 10) || 3, 1);
const stripe = process.env.STRIPE_SECRET_KEY ? Stripe(process.env.STRIPE_SECRET_KEY) : null;

const missingRequiredEnv = ['DATABASE_URL', 'JWT_SECRET'].filter(key => !process.env[key]);
if (missingRequiredEnv.length) {
  console.error(`Missing required environment variables: ${missingRequiredEnv.join(', ')}`);
  process.exit(1);
}

app.set('trust proxy', 1);

// ─── DB ───────────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// ─── OPENAI ───────────────────────────────────────────────────────────────────
let openaiClient = null;
function getOpenAIClient() {
  if (!process.env.OPENAI_API_KEY) return null;
  if (!openaiClient) openaiClient = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
  return openaiClient;
}

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
const allowedOrigins = new Set([
  FRONTEND_URL,
  'https://www.typyzpiwnicy.pl',
  'https://typyzpiwnicy.pl',
  'http://localhost:3000',
  'http://localhost:3001',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  ...(process.env.CORS_ORIGINS || '').split(',').map(origin => origin.trim()).filter(Boolean)
]);
app.use(cors({
  origin: function(origin, callback) {
    // Pozwala na zapytania bez origin (np. mobilki) lub te z listy allowed
    if (!origin || allowedOrigins.has(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Błąd CORS: Ten adres nie ma uprawnień!'));
    }
  },
  credentials: true,
}));

app.post('/api/billing/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) {
    return res.status(503).send('Stripe webhook is not configured');
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers['stripe-signature'],
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('Stripe webhook signature error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    await handleStripeEvent(event);
    res.json({ received: true });
  } catch (err) {
    console.error('Stripe webhook handler error:', err);
    res.status(500).send('Webhook handler failed');
  }
});

app.use(express.json({ limit: '10mb' }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Only images allowed'));
  },
});

// ─── RATE LIMITING ────────────────────────────────────────────────────────────
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Too many requests' } });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, message: { error: 'Too many requests' } });
const scanLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 20, message: { error: 'Scan limit reached (20/hour)' } });

// ─── DB INIT ──────────────────────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE,
      password_hash VARCHAR(255) NOT NULL DEFAULT '',
      language VARCHAR(5) DEFAULT 'pl',
      currency VARCHAR(3) DEFAULT 'PLN',
      league_tier VARCHAR(20) DEFAULT 'gold',
      tax_enabled BOOLEAN DEFAULT FALSE,
      weekly_email_enabled BOOLEAN DEFAULT FALSE,
      weekly_email_last_sent_at TIMESTAMP,
      discord_id TEXT UNIQUE,
      discord_name TEXT,
      avatar TEXT,
      is_premium BOOLEAN DEFAULT FALSE,
      admin_premium BOOLEAN DEFAULT FALSE,
      admin_note TEXT,
      last_seen_at TIMESTAMP,
      last_login_at TIMESTAMP,
      trial_started_at TIMESTAMP,
      daily_count INTEGER DEFAULT 0,
      daily_reset DATE DEFAULT CURRENT_DATE,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS bets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      date DATE NOT NULL,
      bookmaker VARCHAR(100),
      category VARCHAR(50),
      stake DECIMAL(10,2) NOT NULL,
      odds DECIMAL(10,4) NOT NULL,
      tax_enabled BOOLEAN NOT NULL DEFAULT FALSE,
      tax_rate DECIMAL(5,4) NOT NULL DEFAULT 0.12,
      bet_type VARCHAR(50) DEFAULT 'single',
      notes TEXT,
      status VARCHAR(20) DEFAULT 'pending',
      selections JSONB DEFAULT '[]',
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_bets_user_id ON bets(user_id);
    CREATE INDEX IF NOT EXISTS idx_bets_status ON bets(status);
    CREATE INDEX IF NOT EXISTS idx_bets_date ON bets(date);

    CREATE TABLE IF NOT EXISTS stripe_processed_payments (
      stripe_object_id TEXT PRIMARY KEY,
      processed_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS billing_events (
      id BIGSERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      provider VARCHAR(30) NOT NULL DEFAULT 'stripe',
      purchase_type VARCHAR(50) NOT NULL,
      status VARCHAR(30) NOT NULL,
      amount_total BIGINT,
      currency VARCHAR(10),
      external_id TEXT UNIQUE,
      customer_id TEXT,
      subscription_id TEXT,
      occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb
    );

    CREATE INDEX IF NOT EXISTS idx_billing_events_user_id ON billing_events(user_id);
    CREATE INDEX IF NOT EXISTS idx_billing_events_occurred_at ON billing_events(occurred_at DESC);

    CREATE TABLE IF NOT EXISTS admin_audit_log (
      id BIGSERIAL PRIMARY KEY,
      admin_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      target_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      action VARCHAR(80) NOT NULL,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_admin_audit_target ON admin_audit_log(target_user_id, created_at DESC);
  `);

  await pool.query(`
    ALTER TABLE bets ADD COLUMN IF NOT EXISTS tax_enabled BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE bets ADD COLUMN IF NOT EXISTS tax_rate DECIMAL(5,4) NOT NULL DEFAULT 0.12;
  `);

  // Dodaj kolumny jeśli tabela users już istnieje (migracja)
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_id TEXT UNIQUE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_name TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS is_premium BOOLEAN DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS admin_premium BOOLEAN DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS admin_note TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMP;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS currency VARCHAR(3) DEFAULT 'PLN';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS league_tier VARCHAR(20) DEFAULT 'gold';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS weekly_email_enabled BOOLEAN DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS weekly_email_last_sent_at TIMESTAMP;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS trial_started_at TIMESTAMP;
    ALTER TABLE users ALTER COLUMN trial_started_at DROP DEFAULT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_premium BOOLEAN DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_premium BOOLEAN DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT UNIQUE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT UNIQUE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_subscription_status TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS premium_until TIMESTAMP;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS daily_count INTEGER DEFAULT 0;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS daily_reset DATE DEFAULT CURRENT_DATE;
    ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
    ALTER TABLE users ALTER COLUMN password_hash SET DEFAULT '';
  `).catch(() => {}); // ignoruj błędy jeśli kolumny już istnieją

  // Migracja: Google i Facebook OAuth
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id TEXT UNIQUE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS facebook_id TEXT UNIQUE;
  `).catch(() => {});

  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS admin_premium BOOLEAN DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS admin_note TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMP;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP;
  `).catch(() => {});

  await pool.query(`
    UPDATE users
    SET admin_premium = TRUE
    WHERE is_premium = TRUE
      AND COALESCE(admin_premium, FALSE) = FALSE
      AND COALESCE(discord_premium, FALSE) = FALSE
      AND COALESCE(stripe_premium, FALSE) = FALSE
      AND premium_until IS NULL;
  `).catch(() => {});

  await pool.query(`
    UPDATE users
    SET discord_premium = TRUE
    WHERE is_premium = TRUE
      AND COALESCE(admin_premium, FALSE) = FALSE
      AND COALESCE(discord_premium, FALSE) = FALSE
      AND COALESCE(stripe_premium, FALSE) = FALSE
      AND premium_until IS NULL;
  `).catch(() => {});

  await pool.query(`
    UPDATE users
    SET is_premium = TRUE
    WHERE COALESCE(premium_until, NOW()) > NOW();
  `).catch(() => {});

  console.log('✅ Database initialized');
}

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function splitEnvList(...values) {
  const set = new Set();
  values.forEach(value => {
    String(value || '')
      .split(',')
      .map(item => item.trim().toLowerCase())
      .filter(Boolean)
      .forEach(item => set.add(item));
  });
  return set;
}

function isAdminIdentity(row) {
  if (!row) return false;
  const ids = splitEnvList(process.env.ADMIN_USER_IDS, process.env.ADMIN_IDS);
  const emails = splitEnvList(process.env.ADMIN_EMAILS, process.env.ADMIN_EMAIL);
  const usernames = splitEnvList(process.env.ADMIN_USERNAMES, process.env.ADMIN_USERNAME);
  return (
    ids.has(String(row.id || '').toLowerCase()) ||
    emails.has(String(row.email || '').toLowerCase()) ||
    usernames.has(String(row.username || '').toLowerCase())
  );
}

async function adminMiddleware(req, res, next) {
  try {
    const { rows } = await pool.query(
      'SELECT id, username, email FROM users WHERE id=$1',
      [req.user.id]
    );
    const admin = rows[0];
    if (!admin) return res.status(404).json({ error: 'User not found' });
    if (!isAdminIdentity(admin)) return res.status(403).json({ error: 'Admin only' });
    req.admin = admin;
    next();
  } catch (err) {
    console.error('Admin auth error:', err);
    res.status(500).json({ error: 'Server error' });
  }
}

const VALID_STATUSES = new Set(['pending', 'won', 'lost', 'void']);
const VALID_BET_TYPES = new Set(['single', 'accumulator', 'system']);
const VALID_LANGUAGES = new Set(['pl', 'en', 'de', 'ru', 'cs', 'es', 'it']);
const VALID_CURRENCIES = new Set(['PLN', 'EUR', 'USD', 'CZK']);
const PROVIDER_COLUMNS = {
  discord: 'discord_id',
  google: 'google_id',
  facebook: 'facebook_id',
};

function todayISO() {
  return new Date().toISOString().split('T')[0];
}

function normalizeEmail(email) {
  return email ? String(email).trim().toLowerCase() : null;
}

function normalizeLanguage(value) {
  const language = String(value || '').trim().toLowerCase();
  return VALID_LANGUAGES.has(language) ? language : 'pl';
}

function normalizeCurrency(value) {
  const currency = String(value || '').trim().toUpperCase();
  return VALID_CURRENCIES.has(currency) ? currency : 'PLN';
}

function normalizeText(value, maxLength) {
  if (value === undefined || value === null) return null;
  const text = String(value).trim();
  if (!text) return null;
  return text.slice(0, maxLength);
}

function parseBoolean(value) {
  return value === true || value === 1 || ['true', '1', 'on', 'yes'].includes(String(value || '').toLowerCase());
}

function parsePositiveNumber(value, min = 0) {
  const normalized = typeof value === 'string' ? value.replace(',', '.') : value;
  const number = Number(normalized);
  return Number.isFinite(number) && number > min ? number : null;
}

function isValidDateString(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(value || ''))) return false;
  const date = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

function safeUsername(value, fallback = 'user') {
  const base = String(value || fallback)
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-zA-Z0-9_]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 45);
  return base || fallback;
}

async function getAvailableUsername(base) {
  const cleanBase = safeUsername(base);
  for (let i = 0; i < 100; i++) {
    const suffix = i === 0 ? '' : `_${i}`;
    const candidate = `${cleanBase.slice(0, 50 - suffix.length)}${suffix}`;
    const { rows } = await pool.query(
      'SELECT id FROM users WHERE LOWER(username)=LOWER($1) LIMIT 1',
      [candidate]
    );
    if (!rows.length) return candidate;
  }
  return `${safeUsername(cleanBase, 'user').slice(0, 32)}_${Date.now().toString(36)}`;
}

function publicUser(row) {
  const isPremium = Boolean(row.is_premium);
  const trialActive = Boolean(row.trial_active);
  return {
    id: row.id,
    username: row.username,
    email: row.email,
    avatar: row.avatar,
    is_premium: isPremium,
    is_admin: isAdminIdentity(row),
    has_stripe_customer: Boolean(row.stripe_customer_id),
    trial_active: trialActive,
    trial_available: Boolean(row.trial_available),
    trial_ends_at: row.trial_ends_at,
    trial_days: TRIAL_DAYS,
    premium_until: row.premium_until,
    can_add: Boolean(isPremium || trialActive),
    language: row.language,
    currency: row.currency || 'PLN',
    league_tier: row.league_tier || 'gold',
    tax_enabled: row.tax_enabled,
    weekly_email_enabled: Boolean(row.weekly_email_enabled),
  };
}

function effectivePremiumSql(alias = 'users') {
  const p = alias ? `${alias}.` : '';
  return `(COALESCE(${p}admin_premium, false) OR COALESCE(${p}discord_premium, false) OR COALESCE(${p}stripe_premium, false) OR COALESCE(${p}premium_until, NOW()) > NOW())`;
}

function trialActiveSql(alias = 'users') {
  const p = alias ? `${alias}.` : '';
  return `(${p}trial_started_at IS NOT NULL AND ${p}trial_started_at + (${TRIAL_DAYS} * INTERVAL '1 day') > NOW())`;
}

function trialEndsSql(alias = 'users') {
  const p = alias ? `${alias}.` : '';
  return `(CASE WHEN ${p}trial_started_at IS NULL THEN NULL ELSE ${p}trial_started_at + (${TRIAL_DAYS} * INTERVAL '1 day') END)`;
}

function trialAvailableSql(alias = 'users') {
  const p = alias ? `${alias}.` : '';
  return `(${p}trial_started_at IS NULL)`;
}

function accessPayload(row) {
  const isPremium = Boolean(row?.is_premium);
  const trialActive = Boolean(row?.trial_active);
  return {
    trial_active: trialActive,
    trial_available: Boolean(row?.trial_available),
    trial_ends_at: row?.trial_ends_at || null,
    trial_days: TRIAL_DAYS,
    premium_until: row?.premium_until || null,
    is_premium: isPremium,
    can_add: Boolean(isPremium || trialActive),
  };
}

const LEAGUE_TIERS = ['bronze', 'silver', 'gold', 'platinum', 'diamond', 'elite'];
function normalizeLeagueTier(value) {
  const tier = String(value || '').trim().toLowerCase();
  return LEAGUE_TIERS.includes(tier) ? tier : null;
}

async function getUserAccess(userId) {
  const { rows } = await pool.query(
    `SELECT id, username, email, avatar, language, currency, league_tier, tax_enabled, weekly_email_enabled, stripe_customer_id, premium_until,
            ${effectivePremiumSql('users')} AS is_premium,
            ${trialActiveSql('users')} AS trial_active,
            ${trialAvailableSql('users')} AS trial_available,
            ${trialEndsSql('users')} AS trial_ends_at
     FROM users WHERE id=$1`,
    [userId]
  );
  return rows[0] || null;
}

function signUserToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );
}

async function updateOAuthUser(id, providerColumn, providerId, email, avatar, isPremium) {
  let safeEmail = email;
  if (safeEmail) {
    const { rows } = await pool.query(
      'SELECT id FROM users WHERE LOWER(email)=LOWER($1) AND id<>$2 LIMIT 1',
      [safeEmail, id]
    );
    if (rows.length) safeEmail = null;
  }

  const params = [providerId, safeEmail, avatar, id];
  let premiumSql = '';
  if (typeof isPremium === 'boolean') {
    params.push(isPremium);
    premiumSql = `, discord_premium=$${params.length}, is_premium=($${params.length} OR COALESCE(stripe_premium, false) OR COALESCE(admin_premium, false) OR COALESCE(premium_until, NOW()) > NOW())`;
  }

  const { rows } = await pool.query(`
    UPDATE users
    SET ${providerColumn}=$1,
        email=COALESCE($2, email),
        avatar=COALESCE($3, avatar),
        last_login_at=NOW(),
        last_seen_at=NOW()
        ${premiumSql}
    WHERE id=$4
    RETURNING id, username, email, avatar, ${effectivePremiumSql('')} AS is_premium, ${trialActiveSql('')} AS trial_active, ${trialAvailableSql('')} AS trial_available, ${trialEndsSql('')} AS trial_ends_at, stripe_customer_id, premium_until, language, currency, league_tier, tax_enabled, weekly_email_enabled
  `, params);
  return rows[0];
}

async function upsertOAuthUser({ provider, providerId, username, email, avatar, isPremium }) {
  const providerColumn = PROVIDER_COLUMNS[provider];
  if (!providerColumn || !providerId) throw new Error('Invalid OAuth provider');

  const cleanEmail = normalizeEmail(email);
  const { rows: providerRows } = await pool.query(
    `SELECT id FROM users WHERE ${providerColumn}=$1 LIMIT 1`,
    [providerId]
  );
  if (providerRows.length) {
    return updateOAuthUser(providerRows[0].id, providerColumn, providerId, cleanEmail, avatar, isPremium);
  }

  if (cleanEmail) {
    const { rows: emailRows } = await pool.query(
      'SELECT id FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1',
      [cleanEmail]
    );
    if (emailRows.length) {
      return updateOAuthUser(emailRows[0].id, providerColumn, providerId, cleanEmail, avatar, isPremium);
    }
  }

  const finalUsername = await getAvailableUsername(username || `${provider}_${providerId}`);
  const discordPremium = provider === 'discord' ? Boolean(isPremium) : false;
  const { rows } = await pool.query(`
    INSERT INTO users (${providerColumn}, username, email, avatar, password_hash, is_premium, discord_premium, last_login_at, last_seen_at)
    VALUES ($1, $2, $3, $4, '', $5, $6, NOW(), NOW())
    RETURNING id, username, email, avatar, ${effectivePremiumSql('')} AS is_premium, ${trialActiveSql('')} AS trial_active, ${trialAvailableSql('')} AS trial_available, ${trialEndsSql('')} AS trial_ends_at, stripe_customer_id, premium_until, language, currency, league_tier, tax_enabled, weekly_email_enabled
  `, [providerId, finalUsername, cleanEmail, avatar || null, discordPremium, discordPremium]);
  return rows[0];
}

function stripeActiveStatus(status) {
  return ['active', 'trialing'].includes(status);
}

function oneTimePremiumDays() {
  return Math.max(Number.parseInt(process.env.STRIPE_ONETIME_PREMIUM_DAYS || '30', 10) || 30, 1);
}

function publicStripePrice(price) {
  if (!price) return null;
  const rawAmount = price.unit_amount ?? price.unit_amount_decimal;
  const amount = Number.isFinite(Number(rawAmount)) ? Math.round(Number(rawAmount)) : null;
  return {
    unit_amount: amount,
    currency: String(price.currency || 'pln').toUpperCase(),
    interval: price.recurring?.interval || null,
    interval_count: price.recurring?.interval_count || null,
  };
}

async function retrievePublicStripePrice(priceId) {
  if (!stripe || !priceId) return null;
  try {
    return publicStripePrice(await stripe.prices.retrieve(priceId));
  } catch (err) {
    console.error('Stripe price lookup error:', err.message);
    return null;
  }
}

function stripeOccurredAt(unixSeconds) {
  const seconds = Number(unixSeconds);
  return Number.isFinite(seconds) && seconds > 0 ? new Date(seconds * 1000) : new Date();
}

async function resolveBillingUserId({ userId, customerId, subscriptionId }) {
  const parsedUserId = Number.parseInt(userId, 10);
  if (Number.isInteger(parsedUserId) && parsedUserId > 0) return parsedUserId;

  if (customerId) {
    const { rows } = await pool.query(
      'SELECT id FROM users WHERE stripe_customer_id=$1 LIMIT 1',
      [String(customerId)]
    );
    if (rows[0]?.id) return rows[0].id;
  }

  if (subscriptionId) {
    const { rows } = await pool.query(
      'SELECT id FROM users WHERE stripe_subscription_id=$1 LIMIT 1',
      [String(subscriptionId)]
    );
    if (rows[0]?.id) return rows[0].id;
  }

  return null;
}

async function recordBillingEvent({
  userId,
  customerId,
  subscriptionId,
  purchaseType,
  status,
  amountTotal,
  currency,
  externalId,
  occurredAt,
  metadata,
}) {
  if (!purchaseType || !status || !externalId) return null;
  const resolvedUserId = await resolveBillingUserId({ userId, customerId, subscriptionId });
  const safeAmount = Number.isFinite(Number(amountTotal)) ? Math.max(Math.round(Number(amountTotal)), 0) : null;
  const safeCurrency = currency ? String(currency).trim().toLowerCase().slice(0, 10) : null;
  const safeMetadata = metadata && typeof metadata === 'object' ? metadata : {};

  const { rows } = await pool.query(
    `INSERT INTO billing_events
      (user_id, provider, purchase_type, status, amount_total, currency, external_id,
       customer_id, subscription_id, occurred_at, metadata)
     VALUES ($1, 'stripe', $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)
     ON CONFLICT (external_id) DO UPDATE SET
       user_id=COALESCE(EXCLUDED.user_id, billing_events.user_id),
       status=EXCLUDED.status,
       amount_total=COALESCE(EXCLUDED.amount_total, billing_events.amount_total),
       currency=COALESCE(EXCLUDED.currency, billing_events.currency),
       customer_id=COALESCE(EXCLUDED.customer_id, billing_events.customer_id),
       subscription_id=COALESCE(EXCLUDED.subscription_id, billing_events.subscription_id),
       occurred_at=LEAST(billing_events.occurred_at, EXCLUDED.occurred_at),
       metadata=billing_events.metadata || EXCLUDED.metadata
     RETURNING *`,
    [
      resolvedUserId,
      String(purchaseType).slice(0, 50),
      String(status).slice(0, 30),
      safeAmount,
      safeCurrency,
      String(externalId),
      customerId ? String(customerId) : null,
      subscriptionId ? String(subscriptionId) : null,
      occurredAt instanceof Date ? occurredAt : new Date(occurredAt || Date.now()),
      JSON.stringify(safeMetadata),
    ]
  );
  return rows[0] || null;
}

async function recordAdminAction(adminUserId, targetUserId, action, details = {}) {
  await pool.query(
    `INSERT INTO admin_audit_log (admin_user_id, target_user_id, action, details)
     VALUES ($1, $2, $3, $4::jsonb)`,
    [adminUserId || null, targetUserId || null, String(action).slice(0, 80), JSON.stringify(details || {})]
  );
}

function stripeInvoiceSubscriptionId(invoice) {
  const value = invoice?.subscription || invoice?.parent?.subscription_details?.subscription;
  return typeof value === 'string' ? value : value?.id || null;
}

async function syncStripeHistoryForUser(userId) {
  if (!stripe) throw new Error('Stripe is not configured');
  const { rows } = await pool.query(
    'SELECT id, stripe_customer_id FROM users WHERE id=$1 LIMIT 1',
    [userId]
  );
  const user = rows[0];
  if (!user) return { found: false, imported: 0 };
  if (!user.stripe_customer_id) return { found: true, imported: 0, no_customer: true };

  let imported = 0;
  const [invoices, paymentIntents] = await Promise.all([
    stripe.invoices.list({ customer: user.stripe_customer_id, limit: 100 }),
    stripe.paymentIntents.list({ customer: user.stripe_customer_id, limit: 100 }),
  ]);

  for (const invoice of invoices.data || []) {
    const paid = invoice.status === 'paid';
    await recordBillingEvent({
      userId: user.id,
      customerId: user.stripe_customer_id,
      subscriptionId: stripeInvoiceSubscriptionId(invoice),
      purchaseType: 'subscription_invoice',
      status: paid ? 'paid' : (invoice.status || 'open'),
      amountTotal: paid ? (invoice.amount_paid ?? invoice.total) : (invoice.amount_due ?? invoice.total),
      currency: invoice.currency,
      externalId: `invoice:${invoice.id}`,
      occurredAt: stripeOccurredAt(invoice.status_transitions?.paid_at || invoice.created),
      metadata: { billing_reason: invoice.billing_reason || null, imported_by_admin: true },
    });
    imported++;
  }

  for (const paymentIntent of paymentIntents.data || []) {
    if (paymentIntent.metadata?.purchase_type !== 'premium_onetime') continue;
    await recordBillingEvent({
      userId: user.id,
      customerId: user.stripe_customer_id,
      purchaseType: 'premium_onetime',
      status: paymentIntent.status === 'succeeded' ? 'paid' : paymentIntent.status,
      amountTotal: paymentIntent.amount_received || paymentIntent.amount,
      currency: paymentIntent.currency,
      externalId: `payment:${paymentIntent.id}`,
      occurredAt: stripeOccurredAt(paymentIntent.created),
      metadata: { premium_days: paymentIntent.metadata?.premium_days || null, imported_by_admin: true },
    });
    imported++;
  }

  return { found: true, imported };
}

async function syncStripeSubscription({ userId, customerId, subscriptionId, status }) {
  const stripePremium = stripeActiveStatus(status);
  const params = [
    customerId || null,
    subscriptionId || null,
    status || null,
    stripePremium,
  ];

  let where = '';
  if (userId) {
    params.push(Number(userId));
    where = `id=$${params.length}`;
  } else if (customerId) {
    params.push(customerId);
    where = `stripe_customer_id=$${params.length}`;
  } else if (subscriptionId) {
    params.push(subscriptionId);
    where = `stripe_subscription_id=$${params.length}`;
  } else {
    return null;
  }

  const { rows } = await pool.query(`
    UPDATE users
    SET stripe_customer_id=COALESCE($1, stripe_customer_id),
        stripe_subscription_id=COALESCE($2, stripe_subscription_id),
        stripe_subscription_status=COALESCE($3, stripe_subscription_status),
        stripe_premium=$4,
        is_premium=($4 OR COALESCE(discord_premium, false) OR COALESCE(admin_premium, false) OR COALESCE(premium_until, NOW()) > NOW())
    WHERE ${where}
        RETURNING id, username, email, avatar, is_premium, language, currency, league_tier, tax_enabled, weekly_email_enabled
  `, params);
  return rows[0] || null;
}

async function markStripeObjectProcessed(idempotencyKey) {
  if (!idempotencyKey) return true;
  const { rowCount } = await pool.query(
    `INSERT INTO stripe_processed_payments (stripe_object_id)
     VALUES ($1)
     ON CONFLICT (stripe_object_id) DO NOTHING`,
    [String(idempotencyKey)]
  );
  return rowCount > 0;
}

async function grantOneTimePremium({
  userId,
  customerId,
  days,
  idempotencyKey,
  amountTotal,
  currency,
  occurredAt,
}) {
  if (!userId && !customerId) return null;
  const shouldGrant = await markStripeObjectProcessed(idempotencyKey);
  if (!shouldGrant) {
    await recordBillingEvent({
      userId,
      customerId,
      purchaseType: 'premium_onetime',
      status: 'paid',
      amountTotal,
      currency,
      externalId: idempotencyKey ? `payment:${idempotencyKey}` : null,
      occurredAt,
      metadata: { premium_days: days || oneTimePremiumDays() },
    });
    if (userId) return getUserAccess(Number(userId));
    return null;
  }

  const validDays = Math.max(Number.parseInt(days || oneTimePremiumDays(), 10) || oneTimePremiumDays(), 1);
  const params = [customerId || null, validDays];
  let where;
  if (userId) {
    params.push(Number(userId));
    where = `id=$${params.length}`;
  } else {
    params.push(customerId);
    where = `stripe_customer_id=$${params.length}`;
  }

  const { rows } = await pool.query(`
    UPDATE users
    SET stripe_customer_id=COALESCE($1, stripe_customer_id),
        premium_until=GREATEST(COALESCE(premium_until, NOW()), NOW()) + ($2::int * INTERVAL '1 day'),
        is_premium=TRUE
    WHERE ${where}
        RETURNING id, username, email, avatar, is_premium, language, currency, league_tier, tax_enabled, weekly_email_enabled, premium_until
  `, params);
  const user = rows[0] || null;
  await recordBillingEvent({
    userId: user?.id || userId,
    customerId,
    purchaseType: 'premium_onetime',
    status: 'paid',
    amountTotal,
    currency,
    externalId: idempotencyKey ? `payment:${idempotencyKey}` : null,
    occurredAt,
    metadata: { premium_days: validDays },
  });
  return user;
}

async function handleStripeEvent(event) {
  if (event.type === 'checkout.session.completed' || event.type === 'checkout.session.async_payment_succeeded') {
    const session = event.data.object;
    if (session.mode === 'subscription') {
      let status = 'active';
      if (session.subscription && stripe) {
        const subscription = await stripe.subscriptions.retrieve(session.subscription);
        status = subscription.status || status;
      }
      await syncStripeSubscription({
        userId: session.client_reference_id || session.metadata?.user_id,
        customerId: session.customer,
        subscriptionId: session.subscription,
        status,
      });
      await recordBillingEvent({
        userId: session.client_reference_id || session.metadata?.user_id,
        customerId: session.customer,
        subscriptionId: session.subscription,
        purchaseType: 'subscription',
        status: status || 'active',
        amountTotal: session.amount_total,
        currency: session.currency,
        externalId: `checkout:${session.id}`,
        occurredAt: stripeOccurredAt(session.created),
        metadata: { checkout_mode: session.mode },
      });
    }
    if (session.mode === 'payment' && (session.payment_status === 'paid' || event.type === 'checkout.session.async_payment_succeeded')) {
      await grantOneTimePremium({
        userId: session.client_reference_id || session.metadata?.user_id,
        customerId: session.customer,
        days: session.metadata?.premium_days,
        idempotencyKey: session.payment_intent || session.id,
        amountTotal: session.amount_total,
        currency: session.currency,
        occurredAt: stripeOccurredAt(session.created),
      });
    }
    return;
  }

  if (event.type === 'payment_intent.succeeded') {
    const paymentIntent = event.data.object;
    if (paymentIntent.metadata?.purchase_type === 'premium_onetime') {
      await grantOneTimePremium({
        userId: paymentIntent.metadata?.user_id,
        customerId: paymentIntent.customer,
        days: paymentIntent.metadata?.premium_days,
        idempotencyKey: paymentIntent.id,
        amountTotal: paymentIntent.amount_received || paymentIntent.amount,
        currency: paymentIntent.currency,
        occurredAt: stripeOccurredAt(paymentIntent.created),
      });
    }
    return;
  }

  if (event.type === 'invoice.paid' || event.type === 'invoice.payment_failed') {
    const invoice = event.data.object;
    const subscriptionId = stripeInvoiceSubscriptionId(invoice);
    let invoiceUserId = invoice.metadata?.user_id;
    if (!invoiceUserId && subscriptionId && stripe) {
      try {
        const subscription = await stripe.subscriptions.retrieve(subscriptionId);
        invoiceUserId = subscription.metadata?.user_id;
      } catch (err) {
        console.error('Stripe invoice subscription lookup error:', err.message);
      }
    }
    const paid = event.type === 'invoice.paid';
    await recordBillingEvent({
      userId: invoiceUserId,
      customerId: invoice.customer,
      subscriptionId,
      purchaseType: 'subscription_invoice',
      status: paid ? 'paid' : 'failed',
      amountTotal: paid ? (invoice.amount_paid ?? invoice.total) : (invoice.amount_due ?? invoice.total),
      currency: invoice.currency,
      externalId: `invoice:${invoice.id}`,
      occurredAt: stripeOccurredAt(invoice.status_transitions?.paid_at || invoice.created),
      metadata: {
        billing_reason: invoice.billing_reason || null,
        hosted_invoice_url: invoice.hosted_invoice_url || null,
      },
    });
    return;
  }

  if (event.type === 'customer.subscription.created' || event.type === 'customer.subscription.updated') {
    const subscription = event.data.object;
    await syncStripeSubscription({
      userId: subscription.metadata?.user_id,
      customerId: subscription.customer,
      subscriptionId: subscription.id,
      status: subscription.status,
    });
    return;
  }

  if (event.type === 'customer.subscription.deleted') {
    const subscription = event.data.object;
    await syncStripeSubscription({
      userId: subscription.metadata?.user_id,
      customerId: subscription.customer,
      subscriptionId: subscription.id,
      status: subscription.status || 'canceled',
    });
  }
}

// ─── DISCORD: sprawdź rolę premium przez Bot Token ────────────────────────────
async function checkPremiumRole(discordUserId) {
  const { DISCORD_BOT_TOKEN, DISCORD_GUILD_ID, DISCORD_PREMIUM_ROLE_NAME = 'Premium' } = process.env;
  if (!DISCORD_BOT_TOKEN || !DISCORD_GUILD_ID) return false;
  try {
    const memberRes = await axios.get(
      `https://discord.com/api/v10/guilds/${DISCORD_GUILD_ID}/members/${discordUserId}`,
      { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
    );
    const rolesRes = await axios.get(
      `https://discord.com/api/v10/guilds/${DISCORD_GUILD_ID}/roles`,
      { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
    );
    const premiumRole = rolesRes.data.find(
      r => r.name.toLowerCase() === DISCORD_PREMIUM_ROLE_NAME.toLowerCase()
    );
    if (!premiumRole) return false;
    return memberRes.data.roles.includes(premiumRole.id);
  } catch (err) {
    // user nie jest na serwerze lub bot nie ma uprawnień → nie premium
    return false;
  }
}

// ─── MIDDLEWARE: trial/Premium access for adding slips ───────────────────────
async function checkBetAccess(req, res, next) {
  try {
    const { rows } = await pool.query(
      `SELECT ${effectivePremiumSql('users')} AS is_premium,
              ${trialActiveSql('users')} AS trial_active,
              ${trialAvailableSql('users')} AS trial_available,
              ${trialEndsSql('users')} AS trial_ends_at
       FROM users WHERE id=$1`,
      [req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    const user = rows[0];

    if (user.is_premium || user.trial_active) return next();

    return res.status(402).json({
      error: user.trial_available ? 'Trial not activated' : 'Trial expired',
      message: user.trial_available
        ? 'Aktywuj 3-dniowy okres probny, zeby korzystac z tej funkcji.'
        : 'Twoj 3-dniowy okres probny minal. Kup Premium, zeby dalej dodawac kupony bez limitu.',
      trial_active: false,
      trial_available: Boolean(user.trial_available),
      trial_ends_at: user.trial_ends_at,
      is_premium: false,
    });
  } catch (err) {
    console.error('checkAccess error:', err);
    res.status(500).json({ error: 'Server error' });
  }
}

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { username, email, password, language = 'pl', currency = 'PLN' } = req.body;
  const cleanUsername = normalizeText(username, 50);
  const cleanEmail = normalizeEmail(email);
  if (!cleanUsername || !cleanEmail || !password) return res.status(400).json({ error: 'Missing fields' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short' });
  if (cleanUsername.length < 3 || cleanUsername.length > 50) return res.status(400).json({ error: 'Invalid username length' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) return res.status(400).json({ error: 'Invalid email' });

  try {
    const existing = await pool.query(
      'SELECT id FROM users WHERE LOWER(username)=LOWER($1) OR LOWER(email)=LOWER($2) LIMIT 1',
      [cleanUsername, cleanEmail]
    );
    if (existing.rows.length) return res.status(409).json({ error: 'Username or email already taken' });

    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      `INSERT INTO users (username, email, password_hash, language, currency)
       VALUES ($1, $2, $3, $4, $5)
      RETURNING id, username, email, language, currency, league_tier, tax_enabled, weekly_email_enabled, ${effectivePremiumSql('')} AS is_premium, ${trialActiveSql('')} AS trial_active, ${trialAvailableSql('')} AS trial_available, ${trialEndsSql('')} AS trial_ends_at, stripe_customer_id, premium_until, avatar`,
      [cleanUsername, cleanEmail, hash, normalizeLanguage(language), normalizeCurrency(currency)]
    );
    const token = signUserToken(rows[0]);
    res.json({ token, user: publicUser(rows[0]) });
  } catch (e) {
    if (e.code === '23505') {
      const field = e.constraint?.includes('email') ? 'Email' : 'Username';
      return res.status(409).json({ error: `${field} already taken` });
    }
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { login, password } = req.body;
  if (!login || !password) return res.status(400).json({ error: 'Missing fields' });

  try {
    const { rows } = await pool.query(
      `SELECT users.*, ${effectivePremiumSql('users')} AS effective_is_premium,
              ${trialActiveSql('users')} AS trial_active,
              ${trialAvailableSql('users')} AS trial_available,
              ${trialEndsSql('users')} AS trial_ends_at
       FROM users WHERE LOWER(email)=LOWER($1) OR LOWER(username)=LOWER($1)`,
      [login.toLowerCase().trim()]
    );
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    await pool.query(
      'UPDATE users SET last_login_at=NOW(), last_seen_at=NOW() WHERE id=$1',
      [rows[0].id]
    ).catch(() => {});

    const token = signUserToken(rows[0]);
    res.json({
      token,
      user: {
        id: rows[0].id,
        username: rows[0].username,
        email: rows[0].email,
      language: rows[0].language,
      currency: rows[0].currency || 'PLN',
      league_tier: rows[0].league_tier || 'gold',
      tax_enabled: rows[0].tax_enabled,
        weekly_email_enabled: Boolean(rows[0].weekly_email_enabled),
        is_premium: rows[0].effective_is_premium,
        is_admin: isAdminIdentity(rows[0]),
        has_stripe_customer: Boolean(rows[0].stripe_customer_id),
        trial_active: rows[0].trial_active,
        trial_available: rows[0].trial_available,
        trial_ends_at: rows[0].trial_ends_at,
        trial_days: TRIAL_DAYS,
        premium_until: rows[0].premium_until,
        can_add: Boolean(rows[0].effective_is_premium || rows[0].trial_active),
        avatar: rows[0].avatar
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  await pool.query('UPDATE users SET last_seen_at=NOW() WHERE id=$1', [req.user.id]).catch(() => {});
  const { rows } = await pool.query(
      `SELECT id, username, email, language, currency, league_tier, tax_enabled, weekly_email_enabled,
            ${effectivePremiumSql('users')} AS is_premium,
            ${trialActiveSql('users')} AS trial_active,
            ${trialAvailableSql('users')} AS trial_available,
            ${trialEndsSql('users')} AS trial_ends_at,
            stripe_customer_id, premium_until, avatar
     FROM users WHERE id=$1`,
    [req.user.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Not found' });

  const user = rows[0];
  res.json(publicUser(user));
});

app.post('/api/trial/activate', authMiddleware, async (req, res) => {
  try {
    const current = await getUserAccess(req.user.id);
    if (!current) return res.status(404).json({ error: 'User not found' });

    if (!current.trial_available) {
      return res.json({ user: publicUser(current), access: accessPayload(current), already_started: true });
    }

    const { rows } = await pool.query(
      `UPDATE users
       SET trial_started_at=NOW()
       WHERE id=$1 AND trial_started_at IS NULL
        RETURNING id, username, email, avatar, language, currency, league_tier, tax_enabled, weekly_email_enabled, stripe_customer_id, premium_until,
                 ${effectivePremiumSql('')} AS is_premium,
                 ${trialActiveSql('')} AS trial_active,
                 ${trialAvailableSql('')} AS trial_available,
                 ${trialEndsSql('')} AS trial_ends_at`,
      [req.user.id]
    );
    const user = rows[0] || await getUserAccess(req.user.id);
    res.json({ user: publicUser(user), access: accessPayload(user), activated: true });
  } catch (err) {
    console.error('Trial activation error:', err);
    res.status(500).json({ error: 'Could not activate trial' });
  }
});

app.patch('/api/auth/settings', authMiddleware, async (req, res) => {
  const { language, currency, tax_enabled, weekly_email_enabled } = req.body;
  const weeklySetting = weekly_email_enabled === undefined ? null : parseBoolean(weekly_email_enabled);
  const { rows } = await pool.query(
    `UPDATE users
     SET language=$1, currency=$2, tax_enabled=$3, weekly_email_enabled=COALESCE($4, weekly_email_enabled)
     WHERE id=$5
     RETURNING language, currency, tax_enabled, weekly_email_enabled`,
    [normalizeLanguage(language), normalizeCurrency(currency), parseBoolean(tax_enabled), weeklySetting, req.user.id]
  );
  res.json({ ok: true, settings: rows[0] || {} });
});

function plainMoney(value, currency = 'PLN', language = 'pl') {
  try {
    return new Intl.NumberFormat(language === 'en' ? 'en-US' : 'pl-PL', {
      style: 'currency',
      currency: String(currency || 'PLN').toUpperCase(),
    }).format(Number(value || 0));
  } catch {
    return `${Number(value || 0).toFixed(2)} ${String(currency || 'PLN').toUpperCase()}`;
  }
}

function plainPct(value) {
  return `${Number(value || 0).toFixed(1).replace('.', ',')}%`;
}

async function buildWeeklySummary(userId) {
  const { rows: userRows } = await pool.query(
    'SELECT id, username, email, language, currency, weekly_email_enabled FROM users WHERE id=$1',
    [userId]
  );
  const user = userRows[0] || null;
  if (!user) return null;

  const profitSql = `CASE
    WHEN status='won' THEN stake * (CASE WHEN tax_enabled THEN 1 - tax_rate ELSE 1 END) * odds - stake
    WHEN status='lost' THEN -stake
    ELSE 0
  END`;

  const { rows: summaryRows } = await pool.query(`
    SELECT
      COUNT(*)::int AS total,
      (COUNT(*) FILTER (WHERE status IN ('won','lost')))::int AS settled,
      COALESCE(SUM(stake), 0) AS stake,
      COALESCE(SUM(${profitSql}), 0) AS profit,
      COALESCE(SUM(stake) FILTER (WHERE status IN ('won','lost')), 0) AS settled_stake,
      (COUNT(*) FILTER (WHERE status='pending'))::int AS pending
    FROM bets
    WHERE user_id=$1 AND date >= CURRENT_DATE - INTERVAL '6 days'
  `, [userId]);

  const { rows: bestRows } = await pool.query(`
    SELECT COALESCE(NULLIF(category, ''), NULLIF(bet_type, ''), 'Inne') AS name,
           COUNT(*)::int AS total,
           COALESCE(SUM(${profitSql}), 0) AS profit
    FROM bets
    WHERE user_id=$1 AND date >= CURRENT_DATE - INTERVAL '6 days'
    GROUP BY 1
    ORDER BY profit DESC, total DESC
    LIMIT 1
  `, [userId]);

  const { rows: logRows } = await pool.query(`
    SELECT DISTINCT created_at::date AS day
    FROM bets
    WHERE user_id=$1 AND created_at >= NOW() - INTERVAL '60 days'
    ORDER BY day DESC
  `, [userId]);

  const days = new Set(logRows.map(r => String(r.day).slice(0, 10)));
  let cursor = new Date().toISOString().slice(0, 10);
  if (!days.has(cursor) && logRows[0]?.day) cursor = String(logRows[0].day).slice(0, 10);
  let logStreak = 0;
  while (days.has(cursor)) {
    logStreak++;
    const d = new Date(`${cursor}T12:00:00Z`);
    d.setUTCDate(d.getUTCDate() - 1);
    cursor = d.toISOString().slice(0, 10);
  }

  const s = summaryRows[0] || {};
  const settledStake = Number(s.settled_stake || 0);
  const profit = Number(s.profit || 0);
  return {
    user,
    total: Number(s.total || 0),
    settled: Number(s.settled || 0),
    pending: Number(s.pending || 0),
    stake: Number(s.stake || 0),
    profit,
    roi: settledStake ? profit / settledStake * 100 : 0,
    best: bestRows[0] || null,
    logStreak,
  };
}

function weeklyEmailHtml(summary) {
  const lang = summary.user.language || 'pl';
  const currency = summary.user.currency || 'PLN';
  const bestName = summary.best?.name || '-';
  return `
    <div style="font-family:Arial,sans-serif;background:#08080e;color:#f5f2ff;padding:28px">
      <div style="max-width:620px;margin:0 auto;background:#11111c;border:1px solid #27273a;border-radius:18px;padding:24px">
        <h1 style="margin:0 0 8px">Twój tydzień w Typach z Piwnicy</h1>
        <p style="color:#aaa6c3;margin:0 0 20px">Krótki raport z ostatnich 7 dni.</p>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
          <div style="background:#08080e;border-radius:14px;padding:14px"><small>Profit</small><strong style="display:block;font-size:28px;color:${summary.profit >= 0 ? '#2ed17a' : '#ff5252'}">${plainMoney(summary.profit, currency, lang)}</strong></div>
          <div style="background:#08080e;border-radius:14px;padding:14px"><small>ROI</small><strong style="display:block;font-size:28px">${plainPct(summary.roi)}</strong></div>
          <div style="background:#08080e;border-radius:14px;padding:14px"><small>Najlepszy sport/typ</small><strong style="display:block;font-size:22px">${bestName}</strong></div>
          <div style="background:#08080e;border-radius:14px;padding:14px"><small>Seria dodawania</small><strong style="display:block;font-size:22px">${summary.logStreak} dni</strong></div>
        </div>
        <p style="color:#aaa6c3;font-size:13px;margin-top:20px">To podsumowanie historii, nie porada bukmacherska ani gwarancja wyniku.</p>
      </div>
    </div>
  `;
}

async function sendWeeklyEmail(summary) {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.EMAIL_FROM || process.env.RESEND_FROM;
  if (!apiKey || !from || !summary.user.email) return { sent: false, configured: false };
  await axios.post('https://api.resend.com/emails', {
    from,
    to: summary.user.email,
    subject: `Twój tydzień: ${plainMoney(summary.profit, summary.user.currency, summary.user.language)}, ROI ${plainPct(summary.roi)}`,
    html: weeklyEmailHtml(summary),
  }, {
    headers: { Authorization: `Bearer ${apiKey}` },
  });
  await pool.query('UPDATE users SET weekly_email_last_sent_at=NOW() WHERE id=$1', [summary.user.id]);
  return { sent: true, configured: true };
}

app.get('/api/summary/weekly', authMiddleware, async (req, res) => {
  const summary = await buildWeeklySummary(req.user.id);
  if (!summary) return res.status(404).json({ error: 'User not found' });
  res.json(summary);
});

app.post('/api/summary/weekly/test-email', authMiddleware, async (req, res) => {
  const summary = await buildWeeklySummary(req.user.id);
  if (!summary) return res.status(404).json({ error: 'User not found' });
  const result = await sendWeeklyEmail(summary);
  res.json({ ok: true, ...result, summary });
});

app.post('/api/cron/weekly-emails', async (req, res) => {
  const secret = process.env.WEEKLY_EMAIL_CRON_SECRET || process.env.CRON_SECRET;
  if (!secret || req.headers['x-cron-secret'] !== secret) return res.status(401).json({ error: 'Unauthorized' });
  const { rows: users } = await pool.query(`
    SELECT id FROM users
    WHERE weekly_email_enabled = TRUE
      AND email IS NOT NULL
      AND (weekly_email_last_sent_at IS NULL OR weekly_email_last_sent_at < NOW() - INTERVAL '6 days')
    ORDER BY weekly_email_last_sent_at NULLS FIRST, id ASC
    LIMIT 200
  `);
  let sent = 0;
  let skipped = 0;
  for (const user of users) {
    const summary = await buildWeeklySummary(user.id);
    if (!summary || !summary.total) { skipped++; continue; }
    const result = await sendWeeklyEmail(summary);
    if (result.sent) sent++;
    else skipped++;
  }
  res.json({ ok: true, sent, skipped, considered: users.length });
});

// ─── DISCORD OAUTH ────────────────────────────────────────────────────────────
// KROK 1: Redirect do Discord
function adminUserStatsSql(whereClause = '') {
  return `
    WITH bet_stats AS (
      SELECT
        user_id,
        COUNT(*)::int AS total_bets,
        (COUNT(*) FILTER (WHERE status='won'))::int AS won_bets,
        (COUNT(*) FILTER (WHERE status='lost'))::int AS lost_bets,
        (COUNT(*) FILTER (WHERE status='pending'))::int AS pending_bets,
        (COUNT(*) FILTER (WHERE status='void'))::int AS void_bets,
        COALESCE(SUM(stake), 0) AS total_stake,
        COALESCE(SUM(stake) FILTER (WHERE status IN ('won','lost')), 0) AS settled_stake,
        COALESCE(SUM(CASE
          WHEN status='won' THEN stake * (CASE WHEN tax_enabled THEN 1 - tax_rate ELSE 1 END) * odds - stake
          WHEN status='lost' THEN -stake
          ELSE 0
        END), 0) AS profit,
        MAX(created_at) AS last_bet_at
      FROM bets
      GROUP BY user_id
    ),
    billing_stats AS (
      SELECT
        user_id,
        (COUNT(*) FILTER (WHERE status='paid'))::int AS payment_count,
        COALESCE(SUM(amount_total) FILTER (WHERE status='paid'), 0)::bigint AS total_paid,
        MIN(occurred_at) FILTER (WHERE status='paid') AS first_payment_at,
        MAX(occurred_at) FILTER (WHERE status='paid') AS last_payment_at
      FROM billing_events
      WHERE user_id IS NOT NULL
      GROUP BY user_id
    )
    SELECT
      users.id,
      users.username,
      users.email,
      users.avatar,
      users.language,
      users.currency,
      users.league_tier,
      users.tax_enabled,
      users.created_at,
      users.last_seen_at,
      users.last_login_at,
      (users.password_hash <> '') AS has_password,
      (users.discord_id IS NOT NULL) AS has_discord,
      (users.google_id IS NOT NULL) AS has_google,
      (users.facebook_id IS NOT NULL) AS has_facebook,
      users.admin_premium,
      users.discord_premium,
      users.stripe_premium,
      users.stripe_subscription_status,
      users.stripe_customer_id,
      users.premium_until,
      ${effectivePremiumSql('users')} AS is_premium,
      ${trialActiveSql('users')} AS trial_active,
      ${trialAvailableSql('users')} AS trial_available,
      ${trialEndsSql('users')} AS trial_ends_at,
      COALESCE(bs.total_bets, 0)::int AS total_bets,
      COALESCE(bs.won_bets, 0)::int AS won_bets,
      COALESCE(bs.lost_bets, 0)::int AS lost_bets,
      COALESCE(bs.pending_bets, 0)::int AS pending_bets,
      COALESCE(bs.void_bets, 0)::int AS void_bets,
      COALESCE(bs.total_stake, 0) AS total_stake,
      COALESCE(bs.settled_stake, 0) AS settled_stake,
      COALESCE(bs.profit, 0) AS profit,
      CASE
        WHEN COALESCE(bs.settled_stake, 0) > 0
        THEN ROUND((COALESCE(bs.profit, 0) / bs.settled_stake * 100)::numeric, 2)
        ELSE 0
      END AS roi,
      bs.last_bet_at,
      COALESCE(bill.payment_count, 0)::int AS payment_count,
      COALESCE(bill.total_paid, 0)::bigint AS total_paid,
      bill.first_payment_at,
      bill.last_payment_at,
      latest_payment.purchase_type AS last_purchase_type,
      latest_payment.status AS last_purchase_status,
      latest_payment.amount_total AS last_purchase_amount,
      latest_payment.currency AS last_purchase_currency,
      latest_payment.occurred_at AS last_purchase_at
    FROM users
    LEFT JOIN bet_stats bs ON bs.user_id = users.id
    LEFT JOIN billing_stats bill ON bill.user_id = users.id
    LEFT JOIN LATERAL (
      SELECT purchase_type, status, amount_total, currency, occurred_at
      FROM billing_events
      WHERE billing_events.user_id = users.id
        AND billing_events.status = 'paid'
      ORDER BY occurred_at DESC, id DESC
      LIMIT 1
    ) latest_payment ON TRUE
    ${whereClause}
  `;
}

async function getAdminUserDetails(userId) {
  const { rows } = await pool.query(
    `${adminUserStatsSql('WHERE users.id=$1')} LIMIT 1`,
    [userId]
  );
  return rows[0] || null;
}

app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const safeLimit = Math.min(Math.max(parseInt(req.query.limit, 10) || 80, 1), 200);
    const safeOffset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
    const search = normalizeText(req.query.search, 100);
    const params = [];
    let where = '';

    if (search) {
      params.push(`%${search.toLowerCase()}%`);
      where = `WHERE LOWER(COALESCE(users.username, '')) LIKE $${params.length}
               OR LOWER(COALESCE(users.email, '')) LIKE $${params.length}
               OR CAST(users.id AS TEXT) LIKE $${params.length}`;
    }

    const listParams = [...params, safeLimit, safeOffset];
    const { rows } = await pool.query(
      `${adminUserStatsSql(where)}
       ORDER BY COALESCE(users.last_seen_at, users.last_login_at, users.created_at) DESC
       LIMIT $${listParams.length - 1} OFFSET $${listParams.length}`,
      listParams
    );

    const { rows: summaryRows } = await pool.query(`
      SELECT
        COUNT(*)::int AS total_users,
        (COUNT(*) FILTER (WHERE ${effectivePremiumSql('users')}))::int AS premium_users,
        (COUNT(*) FILTER (WHERE ${trialActiveSql('users')}))::int AS active_trials,
        (COUNT(*) FILTER (WHERE last_seen_at > NOW() - INTERVAL '24 hours'))::int AS active_today,
        (SELECT COUNT(*)::int FROM billing_events WHERE status='paid') AS paid_orders,
        (SELECT COALESCE(SUM(amount_total), 0)::bigint FROM billing_events WHERE status='paid') AS revenue_total,
        (COUNT(*) FILTER (WHERE COALESCE(league_tier, 'gold')='bronze'))::int AS league_bronze,
        (COUNT(*) FILTER (WHERE COALESCE(league_tier, 'gold')='silver'))::int AS league_silver,
        (COUNT(*) FILTER (WHERE COALESCE(league_tier, 'gold')='gold'))::int AS league_gold,
        (COUNT(*) FILTER (WHERE COALESCE(league_tier, 'gold')='platinum'))::int AS league_platinum,
        (COUNT(*) FILTER (WHERE COALESCE(league_tier, 'gold')='diamond'))::int AS league_diamond,
        (COUNT(*) FILTER (WHERE COALESCE(league_tier, 'gold')='elite'))::int AS league_elite
      FROM users
    `);

    const countParams = [...params];
    const { rows: countRows } = await pool.query(
      `SELECT COUNT(*)::int AS total FROM users ${where}`,
      countParams
    );

    res.json({
      users: rows,
      summary: summaryRows[0] || {},
      pagination: {
        total: countRows[0]?.total || 0,
        limit: safeLimit,
        offset: safeOffset,
      },
    });
  } catch (err) {
    console.error('Admin users error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/users/:id/details', authMiddleware, adminMiddleware, async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  if (!Number.isInteger(userId) || userId <= 0) return res.status(400).json({ error: 'Invalid user id' });

  try {
    const user = await getAdminUserDetails(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const { rows: payments } = await pool.query(
      `SELECT id, provider, purchase_type, status, amount_total, currency,
              external_id, occurred_at
       FROM billing_events
       WHERE user_id=$1
       ORDER BY occurred_at DESC, id DESC
       LIMIT 50`,
      [userId]
    );

    const { rows: audit } = await pool.query(
      `SELECT action, details, created_at
       FROM admin_audit_log
       WHERE target_user_id=$1
       ORDER BY created_at DESC, id DESC
       LIMIT 20`,
      [userId]
    );

    res.json({ user, payments, audit });
  } catch (err) {
    console.error('Admin user details error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/users/:id/sync-billing', authMiddleware, adminMiddleware, async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  if (!Number.isInteger(userId) || userId <= 0) return res.status(400).json({ error: 'Invalid user id' });
  if (!stripe) return res.status(503).json({ error: 'Stripe is not configured' });

  try {
    const result = await syncStripeHistoryForUser(userId);
    if (!result.found) return res.status(404).json({ error: 'User not found' });
    await recordAdminAction(req.admin?.id, userId, 'billing_sync', result);
    res.json({ ok: true, ...result });
  } catch (err) {
    console.error('Admin billing sync error:', err);
    res.status(500).json({ error: 'Could not sync Stripe billing history' });
  }
});

app.post('/api/admin/users/:id/premium', authMiddleware, adminMiddleware, async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  const action = String(req.body?.action || '').trim();
  if (!Number.isInteger(userId) || userId <= 0) return res.status(400).json({ error: 'Invalid user id' });

  try {
    if (action === 'grant') {
      await pool.query(
        `UPDATE users
         SET admin_premium=TRUE, is_premium=TRUE
         WHERE id=$1`,
        [userId]
      );
    } else if (action === 'grant_days') {
      const days = Math.min(Math.max(parseInt(req.body?.days, 10) || 30, 1), 3650);
      await pool.query(
        `UPDATE users
         SET admin_premium=FALSE,
             premium_until=GREATEST(COALESCE(premium_until, NOW()), NOW()) + ($2::int * INTERVAL '1 day'),
             is_premium=TRUE
         WHERE id=$1`,
        [userId, days]
      );
    } else if (action === 'revoke') {
      await pool.query(
        `UPDATE users
         SET admin_premium=FALSE,
             premium_until=NULL,
             is_premium=(COALESCE(discord_premium, FALSE) OR COALESCE(stripe_premium, FALSE))
         WHERE id=$1`,
        [userId]
      );
    } else {
      return res.status(400).json({ error: 'Invalid premium action' });
    }

    const user = await getAdminUserDetails(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    await recordAdminAction(req.admin?.id, userId, `premium_${action}`, {
      days: action === 'grant_days' ? Math.min(Math.max(parseInt(req.body?.days, 10) || 30, 1), 3650) : null,
    });
    res.json({ ok: true, user });
  } catch (err) {
    console.error('Admin premium error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/users/:id/league', authMiddleware, adminMiddleware, async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  const leagueTier = normalizeLeagueTier(req.body?.league_tier || req.body?.tier || req.body?.league);
  if (!Number.isInteger(userId) || userId <= 0) return res.status(400).json({ error: 'Invalid user id' });
  if (!leagueTier) return res.status(400).json({ error: 'Invalid league tier' });

  try {
    const { rows: beforeRows } = await pool.query('SELECT league_tier FROM users WHERE id=$1', [userId]);
    if (!beforeRows.length) return res.status(404).json({ error: 'User not found' });

    await pool.query(
      `UPDATE users
       SET league_tier=$2
       WHERE id=$1`,
      [userId, leagueTier]
    );

    const user = await getAdminUserDetails(userId);
    await recordAdminAction(req.admin?.id, userId, 'league_set', {
      from: beforeRows[0].league_tier || 'gold',
      to: leagueTier,
    });
    res.json({ ok: true, user });
  } catch (err) {
    console.error('Admin league error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/users/:id/trial', authMiddleware, adminMiddleware, async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  const action = String(req.body?.action || '').trim();
  if (!Number.isInteger(userId) || userId <= 0) return res.status(400).json({ error: 'Invalid user id' });

  try {
    if (action === 'reset') {
      await pool.query('UPDATE users SET trial_started_at=NULL WHERE id=$1', [userId]);
    } else if (action === 'start') {
      await pool.query('UPDATE users SET trial_started_at=NOW() WHERE id=$1', [userId]);
    } else if (action === 'expire') {
      await pool.query(
        `UPDATE users
         SET trial_started_at=NOW() - (($2::int + 1) * INTERVAL '1 day')
         WHERE id=$1`,
        [userId, TRIAL_DAYS]
      );
    } else {
      return res.status(400).json({ error: 'Invalid trial action' });
    }

    const user = await getAdminUserDetails(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    await recordAdminAction(req.admin?.id, userId, `trial_${action}`);
    res.json({ ok: true, user });
  } catch (err) {
    console.error('Admin trial error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/auth/discord', (req, res) => {
  const params = new URLSearchParams({
    client_id:     process.env.DISCORD_CLIENT_ID,
    redirect_uri:  process.env.DISCORD_REDIRECT_URI,
    response_type: 'code',
    scope:         'identify email',
  });
  res.redirect(`https://discord.com/api/oauth2/authorize?${params}`);
});

// KROK 2: Callback po autoryzacji
app.get('/api/auth/discord/callback', async (req, res) => {
  const { code, error } = req.query;
  const FRONTEND = FRONTEND_URL;

  if (error || !code) {
    return res.redirect(`${FRONTEND}?auth_error=cancelled`);
  }

  try {
    // 1. Wymień code na access_token
    const tokenRes = await axios.post(
      'https://discord.com/api/oauth2/token',
      new URLSearchParams({
        client_id:     process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type:    'authorization_code',
        code,
        redirect_uri:  process.env.DISCORD_REDIRECT_URI,
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    const { access_token } = tokenRes.data;

    // 2. Pobierz dane użytkownika z Discord
    const userRes = await axios.get('https://discord.com/api/v10/users/@me', {
      headers: { Authorization: `Bearer ${access_token}` }
    });
    const d = userRes.data; // { id, username, email, avatar }

    // 3. Sprawdź rolę premium
    const isPremium = await checkPremiumRole(d.id);

    // 4. Zbuduj URL avatara
    const avatar = d.avatar
      ? `https://cdn.discordapp.com/avatars/${d.id}/${d.avatar}.png?size=128`
      : `https://cdn.discordapp.com/embed/avatars/${Number(BigInt(d.id) % 5n)}.png`;

    // 5. Upsert użytkownika
    const user = await upsertOAuthUser({
      provider: 'discord',
      providerId: d.id,
      username: d.username,
      email: d.email || null,
      avatar,
      isPremium,
    });

    // 6. Wygeneruj JWT (używamy tego samego formatu co reszta: { id, username })
    const token = signUserToken(user);

    // 7. Przekieruj na frontend z tokenem
    const userParam = encodeURIComponent(JSON.stringify(publicUser(user)));

    res.redirect(`${FRONTEND}?token=${token}&user=${userParam}`);

  } catch (err) {
    console.error('Discord callback error:', err.response?.data || err.message);
    res.redirect(`${FRONTEND}?auth_error=server_error`);
  }
});

// ─── GOOGLE OAUTH ─────────────────────────────────────────────────────────────
// KROK 1: Redirect do Google
app.get('/api/auth/google', (req, res) => {
  const params = new URLSearchParams({
    client_id:     process.env.GOOGLE_CLIENT_ID,
    redirect_uri:  process.env.GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope:         'openid email profile',
    access_type:   'offline',
    prompt:        'select_account',
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

// KROK 2: Callback Google
app.get('/api/auth/google/callback', async (req, res) => {
  const { code, error } = req.query;
  const FRONTEND = FRONTEND_URL;

  if (error || !code) {
    return res.redirect(`${FRONTEND}?auth_error=google_cancelled`);
  }

  try {
    // 1. Wymień code na token
    const tokenRes = await axios.post(
      'https://oauth2.googleapis.com/token',
      new URLSearchParams({
        client_id:     process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        grant_type:    'authorization_code',
        code,
        redirect_uri:  process.env.GOOGLE_REDIRECT_URI,
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    const { access_token } = tokenRes.data;

    // 2. Pobierz dane użytkownika
    const userRes = await axios.get('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${access_token}` }
    });
    const g = userRes.data; // { sub, name, email, picture }

    const username = g.name || (g.email ? g.email.split('@')[0] : `google_${g.sub}`);
    const avatar   = g.picture || null;

    // 3. Upsert użytkownika po google_id albo emailu
    const user = await upsertOAuthUser({
      provider: 'google',
      providerId: g.sub,
      username,
      email: g.email || null,
      avatar,
    });
    const token = signUserToken(user);

    const userParam = encodeURIComponent(JSON.stringify(publicUser(user)));

    res.redirect(`${FRONTEND}?token=${token}&user=${userParam}`);

  } catch (err) {
    console.error('Google callback error:', err.response?.data || err.message);
    res.redirect(`${FRONTEND}?auth_error=google_server_error`);
  }
});

// ─── FACEBOOK OAUTH ────────────────────────────────────────────────────────────
// KROK 1: Redirect do Facebook
app.get('/api/auth/facebook', (req, res) => {
  const params = new URLSearchParams({
    client_id:     process.env.FACEBOOK_CLIENT_ID,
    redirect_uri:  process.env.FACEBOOK_REDIRECT_URI,
    response_type: 'code',
    scope:         'email,public_profile',
  });
  res.redirect(`https://www.facebook.com/v19.0/dialog/oauth?${params}`);
});

// KROK 2: Callback Facebook
app.get('/api/auth/facebook/callback', async (req, res) => {
  const { code, error } = req.query;
  const FRONTEND = FRONTEND_URL;

  if (error || !code) {
    return res.redirect(`${FRONTEND}?auth_error=facebook_cancelled`);
  }

  try {
    // 1. Wymień code na token
    const tokenRes = await axios.get('https://graph.facebook.com/v19.0/oauth/access_token', {
      params: {
        client_id:     process.env.FACEBOOK_CLIENT_ID,
        client_secret: process.env.FACEBOOK_CLIENT_SECRET,
        redirect_uri:  process.env.FACEBOOK_REDIRECT_URI,
        code,
      }
    });
    const { access_token } = tokenRes.data;

    // 2. Pobierz dane użytkownika
    const userRes = await axios.get('https://graph.facebook.com/me', {
      params: { fields: 'id,name,email,picture.type(large)', access_token }
    });
    const f = userRes.data; // { id, name, email, picture }

    const username = f.name || `fb_${f.id}`;
    const avatar   = f.picture?.data?.url || null;

    // 3. Upsert użytkownika po facebook_id albo emailu
    const user = await upsertOAuthUser({
      provider: 'facebook',
      providerId: f.id,
      username,
      email: f.email || null,
      avatar,
    });
    const token = signUserToken(user);

    const userParam = encodeURIComponent(JSON.stringify(publicUser(user)));

    res.redirect(`${FRONTEND}?token=${token}&user=${userParam}`);

  } catch (err) {
    console.error('Facebook callback error:', err.response?.data || err.message);
    res.redirect(`${FRONTEND}?auth_error=facebook_server_error`);
  }
});

// ─── BETS ROUTES ──────────────────────────────────────────────────────────────

// ─── STRIPE BILLING ───────────────────────────────────────────────────────────
app.get('/api/billing/prices', async (req, res) => {
  try {
    res.set('Cache-Control', 'public, max-age=300');
    const [subscription, oneTime] = await Promise.all([
      retrievePublicStripePrice(process.env.STRIPE_PREMIUM_PRICE_ID),
      retrievePublicStripePrice(process.env.STRIPE_ONETIME_PRICE_ID),
    ]);
    res.json({
      subscription,
      oneTime,
      premiumDays: oneTimePremiumDays(),
    });
  } catch (err) {
    console.error('Stripe public prices error:', err);
    res.status(500).json({ error: 'Could not load prices' });
  }
});

app.post('/api/billing/create-checkout-session', authMiddleware, async (req, res) => {
  if (!stripe || !process.env.STRIPE_PREMIUM_PRICE_ID) {
    return res.status(503).json({ error: 'Stripe is not configured' });
  }

  try {
    const { rows } = await pool.query(
      'SELECT id, email, username, stripe_customer_id FROM users WHERE id=$1',
      [req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    const user = rows[0];

    const sessionPayload = {
      mode: 'subscription',
      line_items: [{ price: process.env.STRIPE_PREMIUM_PRICE_ID, quantity: 1 }],
      allow_promotion_codes: true,
      success_url: `${FRONTEND_URL}?billing=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${FRONTEND_URL}?billing=cancel`,
      client_reference_id: String(user.id),
      metadata: { user_id: String(user.id) },
      subscription_data: { metadata: { user_id: String(user.id) } },
    };

    if (user.stripe_customer_id) {
      sessionPayload.customer = user.stripe_customer_id;
    } else if (user.email) {
      sessionPayload.customer_email = user.email;
    }

    const session = await stripe.checkout.sessions.create(sessionPayload);
    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe checkout error:', err);
    res.status(500).json({ error: 'Could not create checkout session' });
  }
});

app.post('/api/billing/create-onetime-checkout-session', authMiddleware, async (req, res) => {
  if (!stripe || !process.env.STRIPE_ONETIME_PRICE_ID) {
    return res.status(503).json({ error: 'Stripe one-time payment is not configured' });
  }

  try {
    const { rows } = await pool.query(
      'SELECT id, email, username, stripe_customer_id FROM users WHERE id=$1',
      [req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    const user = rows[0];
    const premiumDays = oneTimePremiumDays();

    const sessionPayload = {
      mode: 'payment',
      payment_method_types: ['card', 'blik'],
      line_items: [{ price: process.env.STRIPE_ONETIME_PRICE_ID, quantity: 1 }],
      allow_promotion_codes: true,
      success_url: `${FRONTEND_URL}?billing=onetime_success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${FRONTEND_URL}?billing=cancel`,
      client_reference_id: String(user.id),
      metadata: {
        user_id: String(user.id),
        premium_days: String(premiumDays),
        purchase_type: 'premium_onetime',
      },
      payment_intent_data: {
        metadata: {
          user_id: String(user.id),
          premium_days: String(premiumDays),
          purchase_type: 'premium_onetime',
        },
        description: `Typy z Piwnicy Premium ${premiumDays} dni`,
      },
    };

    if (user.stripe_customer_id) {
      sessionPayload.customer = user.stripe_customer_id;
    } else if (user.email) {
      sessionPayload.customer_email = user.email;
      sessionPayload.customer_creation = 'always';
    }

    const session = await stripe.checkout.sessions.create(sessionPayload);
    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe one-time checkout error:', err);
    res.status(500).json({ error: 'Could not create one-time checkout session' });
  }
});

app.post('/api/billing/verify-session', authMiddleware, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Stripe is not configured' });

  const sessionId = String(req.body?.session_id || '').trim();
  if (!sessionId.startsWith('cs_')) return res.status(400).json({ error: 'Invalid Stripe session' });

  try {
    const session = await stripe.checkout.sessions.retrieve(sessionId, {
      expand: ['subscription', 'payment_intent'],
    });

    const ownerId = session.client_reference_id || session.metadata?.user_id;
    if (String(ownerId) !== String(req.user.id)) {
      return res.status(403).json({ error: 'This payment belongs to a different account' });
    }

    if (session.mode === 'subscription') {
      const subscription = session.subscription;
      const subscriptionId = typeof subscription === 'string' ? subscription : subscription?.id;
      const status = typeof subscription === 'string'
        ? (await stripe.subscriptions.retrieve(subscription)).status
        : subscription?.status;

      await syncStripeSubscription({
        userId: req.user.id,
        customerId: session.customer,
        subscriptionId,
        status: status || 'active',
      });
      await recordBillingEvent({
        userId: req.user.id,
        customerId: session.customer,
        subscriptionId,
        purchaseType: 'subscription',
        status: status || 'active',
        amountTotal: session.amount_total,
        currency: session.currency,
        externalId: `checkout:${session.id}`,
        occurredAt: stripeOccurredAt(session.created),
        metadata: { verified_by_user: true },
      });
    } else if (session.mode === 'payment') {
      if (session.payment_status !== 'paid') {
        return res.status(409).json({ error: 'Payment is not completed yet' });
      }

      const paymentIntent = session.payment_intent;
      const paymentIntentId = typeof paymentIntent === 'string' ? paymentIntent : paymentIntent?.id;
      await grantOneTimePremium({
        userId: req.user.id,
        customerId: session.customer,
        days: session.metadata?.premium_days,
        idempotencyKey: paymentIntentId || session.id,
        amountTotal: session.amount_total,
        currency: session.currency,
        occurredAt: stripeOccurredAt(session.created),
      });
    }

    const user = await getUserAccess(req.user.id);
    res.json({ ok: true, user: publicUser(user), access: accessPayload(user) });
  } catch (err) {
    console.error('Stripe verify session error:', err);
    res.status(500).json({ error: 'Could not verify Stripe payment' });
  }
});

app.post('/api/billing/create-portal-session', authMiddleware, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Stripe is not configured' });

  try {
    const { rows } = await pool.query(
      'SELECT stripe_customer_id FROM users WHERE id=$1',
      [req.user.id]
    );
    const customerId = rows[0]?.stripe_customer_id;
    if (!customerId) return res.status(400).json({ error: 'No Stripe customer found' });

    const session = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: FRONTEND_URL,
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe portal error:', err);
    res.status(500).json({ error: 'Could not create billing portal session' });
  }
});

// GET /api/bets/daily-limit — legacy endpoint name, now returns trial/Premium access
app.get('/api/bets/daily-limit', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { rows: userRows } = await pool.query(
      `SELECT ${effectivePremiumSql('users')} AS is_premium,
              ${trialActiveSql('users')} AS trial_active,
              ${trialAvailableSql('users')} AS trial_available,
              ${trialEndsSql('users')} AS trial_ends_at,
              premium_until
       FROM users WHERE id=$1`,
      [userId]
    );
    const user = userRows[0];
    if (!user) return res.status(404).json({ error: 'User not found' });

    const isPremium = user.is_premium || false;

    res.json({
      trial_active: Boolean(user.trial_active),
      trial_available: Boolean(user.trial_available),
      trial_ends_at: user.trial_ends_at,
      trial_days: TRIAL_DAYS,
      premium_until: user.premium_until,
      is_premium: isPremium,
      can_add: isPremium || user.trial_active
    });
  } catch (err) {
    console.error('Access status error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/bets', authMiddleware, apiLimiter, async (req, res) => {
  const { status, limit = 200, offset = 0 } = req.query;
  if (status && status !== 'all' && !VALID_STATUSES.has(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 200, 1), 500);
  const safeOffset = Math.max(parseInt(offset, 10) || 0, 0);
  let q = 'SELECT * FROM bets WHERE user_id=$1';
  const params = [req.user.id];
  if (status && status !== 'all') { q += ` AND status=$${params.length + 1}`; params.push(status); }
  q += ` ORDER BY date DESC, created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
  params.push(safeLimit, safeOffset);
  const { rows } = await pool.query(q, params);
  res.json(rows);
});

// POST /api/bets — adding slips is available during trial or with Premium
app.post('/api/bets', authMiddleware, apiLimiter, checkBetAccess, async (req, res) => {
  const { date, bookmaker, category, stake, odds, tax_enabled, bet_type, notes, selections, status } = req.body;
  const parsedStake = parsePositiveNumber(stake);
  const parsedOdds = parsePositiveNumber(odds, 1);
  const cleanStatus = status || 'pending';
  const cleanBetType = bet_type || 'single';

  if (!date || !parsedStake || !parsedOdds) return res.status(400).json({ error: 'Missing required fields' });
  if (!isValidDateString(date)) return res.status(400).json({ error: 'Invalid date' });
  if (!VALID_STATUSES.has(cleanStatus)) return res.status(400).json({ error: 'Invalid status' });
  if (!VALID_BET_TYPES.has(cleanBetType)) return res.status(400).json({ error: 'Invalid bet type' });
  if (selections !== undefined && !Array.isArray(selections)) return res.status(400).json({ error: 'Invalid selections' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `INSERT INTO bets (user_id, date, bookmaker, category, stake, odds, tax_enabled, tax_rate, bet_type, notes, selections, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,0.12,$8,$9,$10,$11) RETURNING *`,
      [
        req.user.id,
        date,
        normalizeText(bookmaker, 100),
        normalizeText(category, 50),
        parsedStake,
        parsedOdds,
        parseBoolean(tax_enabled),
        cleanBetType,
        normalizeText(notes, 5000),
        JSON.stringify(selections || []),
        cleanStatus
      ]
    );
    await client.query('COMMIT');
    res.json(rows[0]);
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Create bet error:', err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    client.release();
  }
});

app.patch('/api/bets/:id', authMiddleware, apiLimiter, async (req, res) => {
  const { date, bookmaker, category, stake, odds, tax_enabled, bet_type, status, notes, selections } = req.body;
  const parsedStake = stake !== undefined ? parsePositiveNumber(stake) : undefined;
  const parsedOdds = odds !== undefined ? parsePositiveNumber(odds, 1) : undefined;

  if (date !== undefined && !isValidDateString(date)) return res.status(400).json({ error: 'Invalid date' });
  if (stake !== undefined && !parsedStake) return res.status(400).json({ error: 'Invalid stake' });
  if (odds !== undefined && !parsedOdds) return res.status(400).json({ error: 'Invalid odds' });
  if (bet_type !== undefined && !VALID_BET_TYPES.has(bet_type)) return res.status(400).json({ error: 'Invalid bet type' });
  if (status !== undefined && !VALID_STATUSES.has(status)) return res.status(400).json({ error: 'Invalid status' });
  if (selections !== undefined && !Array.isArray(selections)) return res.status(400).json({ error: 'Invalid selections' });

  const updates = [];
  const params = [];
  if (date !== undefined) {
    params.push(date);
    updates.push(`date=$${params.length}`);
  }
  if (bookmaker !== undefined) {
    params.push(normalizeText(bookmaker, 100));
    updates.push(`bookmaker=$${params.length}`);
  }
  if (category !== undefined) {
    params.push(normalizeText(category, 50));
    updates.push(`category=$${params.length}`);
  }
  if (stake !== undefined) {
    params.push(parsedStake);
    updates.push(`stake=$${params.length}`);
  }
  if (odds !== undefined) {
    params.push(parsedOdds);
    updates.push(`odds=$${params.length}`);
  }
  if (tax_enabled !== undefined) {
    params.push(parseBoolean(tax_enabled));
    updates.push(`tax_enabled=$${params.length}`);
    updates.push('tax_rate=0.12');
  }
  if (bet_type !== undefined) {
    params.push(bet_type);
    updates.push(`bet_type=$${params.length}`);
  }
  if (status !== undefined) {
    params.push(status);
    updates.push(`status=$${params.length}`);
  }
  if (notes !== undefined) {
    params.push(normalizeText(notes, 5000));
    updates.push(`notes=$${params.length}`);
  }
  if (selections !== undefined) {
    params.push(JSON.stringify(selections));
    updates.push(`selections=$${params.length}`);
  }
  if (!updates.length) return res.status(400).json({ error: 'No changes provided' });

  params.push(req.params.id, req.user.id);
  const { rows } = await pool.query(
    `UPDATE bets SET ${updates.join(', ')}, updated_at=NOW()
     WHERE id=$${params.length - 1} AND user_id=$${params.length} RETURNING *`,
    params
  );
  if (!rows.length) return res.status(404).json({ error: 'Not found' });
  res.json(rows[0]);
});

app.delete('/api/bets/:id', authMiddleware, apiLimiter, async (req, res) => {
  const { rowCount } = await pool.query('DELETE FROM bets WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  if (!rowCount) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

app.get('/api/bets/stats', authMiddleware, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT
      COUNT(*) as total,
      COUNT(*) FILTER (WHERE status='won') as won,
      COUNT(*) FILTER (WHERE status='lost') as lost,
      COUNT(*) FILTER (WHERE status='pending') as pending,
      COUNT(*) FILTER (WHERE status='void') as void,
      COALESCE(SUM(stake), 0) as total_stake,
      COALESCE(SUM(stake) FILTER (WHERE status='won'), 0) as won_stake,
      COALESCE(SUM(stake * (CASE WHEN tax_enabled THEN 1 - tax_rate ELSE 1 END) * odds) FILTER (WHERE status='won'), 0) as total_won_gross,
      COALESCE(AVG(odds), 0) as avg_odds
    FROM bets WHERE user_id=$1
  `, [req.user.id]);
  res.json(rows[0]);
});

// ─── AI SCAN ROUTE ────────────────────────────────────────────────────────────
app.post('/api/scan', authMiddleware, scanLimiter, checkBetAccess, upload.single('image'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No image provided' });
  const openai = getOpenAIClient();
  if (!openai) return res.status(503).json({ error: 'AI scanning not configured' });

  // Klient może przesłać aktualną datę — jeśli nie, bierzemy serwerową
  const today = req.body?.today || todayISO();

  try {
    const b64 = req.file.buffer.toString('base64');
    const mime = req.file.mimetype;

    const response = await openai.chat.completions.create({
      model: process.env.OPENAI_SCAN_MODEL || 'gpt-4o',
      response_format: { type: 'json_object' },
      max_tokens: 1200,
      messages: [{
        role: 'user',
        content: [
          {
            type: 'image_url',
            image_url: { url: `data:${mime};base64,${b64}`, detail: 'high' }
          },
          {
            type: 'text',
            text: `You are a precise betting slip (kupon bukmacherski) analyzer. Today's date is ${today}.

RULES:
1. DATE: Use the date visible on the slip. If no date is visible, use today: ${today}. NEVER guess or invent a date. Format: YYYY-MM-DD.
2. STATUS (CRITICAL): Default is ALWAYS "pending" unless you see EXPLICIT visual proof:
   - "won" ONLY IF: green background/text, checkmark ✓, text "trafiony"/"wygrany"/"won"/"wygrana"
   - "lost" ONLY IF: red background/text, ✗ cross, text "przegrany"/"lost"/"przegrana"
   - "pending" = anything else, including unclear or ambiguous cases
3. STAKE (CRITICAL): Return the FULL amount paid by the player — usually labelled "Stawka", "Łączna stawka", "Stake" or "Total stake".
   - If the slip shows "Stawka 20.00 zł" and "Stawka po podatku 17.60 zł", return stake "20.00", NOT "17.60".
   - The value after deducting tax is never the player's full stake.
   - Do not calculate or guess the full stake if it is not visible.
4. ODDS: Total combined odds of the slip (the big number, not individual selection odds). If only one selection exists, use that selection odds.
5. BOOKMAKER: Name of the bookmaker if visible, else null.
6. BET TYPE: "single" (1 selection), "accumulator" (2+ selections combined), "system".
7. TAX: Set "taxEnabled" to true ONLY when the slip explicitly shows a 12% stake tax, "podatek", "stawka po podatku", or both gross and after-tax stake. Otherwise false.
8. NUMBERS: Return numbers as strings with dot decimal separator, without currency symbols.
9. SELECTIONS: If a row contains two teams and one marked pick, put teams in "match" and the selected market/pick in "pick".
10. CATEGORY: Detect sport category from the whole slip. Use Polish names only:
   - "Piłka nożna" for football/soccer
   - "Koszykówka" for basketball
   - "Tenis" for tennis
   - if mixed, join detected categories with "/", e.g. "Piłka nożna/Tenis"
   - if unclear or another sport, use empty string

Return ONLY valid JSON, no markdown, no backticks, no explanation:
{"bookmaker":"name or null","stake":"full amount paid","odds":"number","taxEnabled":false,"betType":"single|accumulator|system","date":"YYYY-MM-DD","category":"Piłka nożna|Koszykówka|Tenis|mixed categories or empty string","selections":[{"match":"team A vs team B","pick":"selection description","odds":"number","status":"won|lost|pending"}],"betStatus":"won|lost|pending","notes":"extra info or empty string"}`
          }
        ]
      }]
    });

    const text = response.choices[0]?.message?.content?.replace(/```json|```/g, '').trim();

    let parsed;
    try {
      const jsonText = text?.startsWith('{') ? text : text?.match(/\{[\s\S]*\}/)?.[0];
      parsed = JSON.parse(jsonText);
    } catch (parseErr) {
      console.error('Scan JSON parse error:', text);
      return res.status(500).json({ error: 'AI zwróciło nieprawidłowy JSON. Spróbuj ponownie.' });
    }

    const cleanNumber = value => {
      if (value === undefined || value === null) return '';
      const raw = String(value).replace(/\s/g, '').replace(',', '.').match(/\d+(?:\.\d+)?/);
      return raw ? raw[0] : '';
    };
    const normalizeSportCategory = value => {
      const text = String(value || '')
        .normalize('NFKD')
        .replace(/[\u0300-\u036f]/g, '')
        .toLowerCase();
      const found = [];
      if (/(pilka|nozna|football|soccer)/.test(text)) found.push('Piłka nożna');
      if (/(koszyk|basket|nba|wnba|euroleague)/.test(text)) found.push('Koszykówka');
      if (/(tenis|tennis|atp|wta)/.test(text)) found.push('Tenis');
      return [...new Set(found)].join('/');
    };

    parsed.stake = cleanNumber(parsed.stake);
    parsed.odds = cleanNumber(parsed.odds);
    parsed.taxEnabled = parsed.taxEnabled === true || String(parsed.taxEnabled).toLowerCase() === 'true';
    parsed.betType = ['single', 'accumulator', 'system'].includes(parsed.betType) ? parsed.betType : 'single';
    const categoryText = [
      parsed.category,
      ...(Array.isArray(parsed.selections) ? parsed.selections.map(s => `${s.category || ''} ${s.sport || ''}`) : [])
    ].join(' ');
    parsed.category = normalizeSportCategory(categoryText);

    // Sanitize: jeśli date jest pusta lub nieprawidłowa, daj today
    if (!parsed.date || !/^\d{4}-\d{2}-\d{2}$/.test(parsed.date)) {
      parsed.date = today;
    }
    // Sanitize: jeśli betStatus nie jest jednym z dozwolonych, daj pending
    if (!['won', 'lost', 'pending', 'void'].includes(parsed.betStatus)) {
      parsed.betStatus = 'pending';
    }
    // Sanitize: każda selekcja też
    if (Array.isArray(parsed.selections)) {
      parsed.selections = parsed.selections.map(s => ({
        ...s,
        odds: cleanNumber(s.odds),
        status: ['won', 'lost', 'pending'].includes(s.status) ? s.status : 'pending'
      }));
    } else {
      parsed.selections = [];
    }

    if (parsed.selections.length) {
      const statuses = parsed.selections.map(s => s.status);
      if (statuses.includes('lost')) parsed.betStatus = 'lost';
      else if (statuses.every(s => s === 'won')) parsed.betStatus = 'won';
      else parsed.betStatus = 'pending';
    }

    res.json(parsed);
  } catch (e) {
    console.error('Scan error:', e);
    res.status(500).json({ error: 'Failed to analyze image' });
  }
});

// ─── HEALTH ───────────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

// ─── FRONTEND STATIC ─────────────────────────────────────────────────────────
// Serwuje gotowy frontend z folderu public, żeby można było odpalić całość jako jedną apkę.
const publicDir = path.join(__dirname, 'public');
const publicIndex = path.join(publicDir, 'index.html');
if (fs.existsSync(publicIndex)) {
  app.use(express.static(publicDir));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api/')) return next();
    res.sendFile(publicIndex);
  });
}

// ─── START ────────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`🚀 TzP API running on port ${PORT}`));
}).catch(e => { console.error('DB init failed:', e); process.exit(1); });
