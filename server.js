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
      tax_enabled BOOLEAN DEFAULT FALSE,
      discord_id TEXT UNIQUE,
      discord_name TEXT,
      avatar TEXT,
      is_premium BOOLEAN DEFAULT FALSE,
      trial_started_at TIMESTAMP DEFAULT NOW(),
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
  `);

  // Dodaj kolumny jeśli tabela users już istnieje (migracja)
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_id TEXT UNIQUE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_name TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS is_premium BOOLEAN DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS trial_started_at TIMESTAMP DEFAULT NOW();
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
    UPDATE users
    SET discord_premium = TRUE
    WHERE is_premium = TRUE
      AND COALESCE(discord_premium, FALSE) = FALSE
      AND COALESCE(stripe_premium, FALSE) = FALSE
      AND premium_until IS NULL;
  `).catch(() => {});

  await pool.query(`
    UPDATE users
    SET trial_started_at = NOW()
    WHERE trial_started_at IS NULL;
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

const VALID_STATUSES = new Set(['pending', 'won', 'lost', 'void']);
const VALID_BET_TYPES = new Set(['single', 'accumulator', 'system']);
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

function normalizeText(value, maxLength) {
  if (value === undefined || value === null) return null;
  const text = String(value).trim();
  if (!text) return null;
  return text.slice(0, maxLength);
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
  return {
    id: row.id,
    username: row.username,
    email: row.email,
    avatar: row.avatar,
    is_premium: row.is_premium,
    has_stripe_customer: Boolean(row.stripe_customer_id),
    trial_active: Boolean(row.trial_active),
    trial_ends_at: row.trial_ends_at,
    language: row.language,
    tax_enabled: row.tax_enabled,
  };
}

function effectivePremiumSql(alias = 'users') {
  const p = alias ? `${alias}.` : '';
  return `(COALESCE(${p}discord_premium, false) OR COALESCE(${p}stripe_premium, false) OR COALESCE(${p}premium_until, NOW()) > NOW())`;
}

function trialActiveSql(alias = 'users') {
  const p = alias ? `${alias}.` : '';
  return `(COALESCE(${p}trial_started_at, ${p}created_at, NOW()) + (${TRIAL_DAYS} * INTERVAL '1 day') > NOW())`;
}

function trialEndsSql(alias = 'users') {
  const p = alias ? `${alias}.` : '';
  return `(COALESCE(${p}trial_started_at, ${p}created_at, NOW()) + (${TRIAL_DAYS} * INTERVAL '1 day'))`;
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
    premiumSql = `, discord_premium=$${params.length}, is_premium=($${params.length} OR COALESCE(stripe_premium, false))`;
  }

  const { rows } = await pool.query(`
    UPDATE users
    SET ${providerColumn}=$1,
        email=COALESCE($2, email),
        avatar=COALESCE($3, avatar)
        ${premiumSql}
    WHERE id=$4
    RETURNING id, username, email, avatar, ${effectivePremiumSql('')} AS is_premium, ${trialActiveSql('')} AS trial_active, ${trialEndsSql('')} AS trial_ends_at, stripe_customer_id, language, tax_enabled
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
    INSERT INTO users (${providerColumn}, username, email, avatar, password_hash, is_premium, discord_premium)
    VALUES ($1, $2, $3, $4, '', $5, $6)
    RETURNING id, username, email, avatar, ${effectivePremiumSql('')} AS is_premium, ${trialActiveSql('')} AS trial_active, ${trialEndsSql('')} AS trial_ends_at, stripe_customer_id, language, tax_enabled
  `, [providerId, finalUsername, cleanEmail, avatar || null, discordPremium, discordPremium]);
  return rows[0];
}

function stripeActiveStatus(status) {
  return ['active', 'trialing'].includes(status);
}

function oneTimePremiumDays() {
  return Math.max(Number.parseInt(process.env.STRIPE_ONETIME_PREMIUM_DAYS || '30', 10) || 30, 1);
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
        is_premium=($4 OR COALESCE(discord_premium, false) OR COALESCE(premium_until, NOW()) > NOW())
    WHERE ${where}
    RETURNING id, username, email, avatar, is_premium, language, tax_enabled
  `, params);
  return rows[0] || null;
}

async function grantOneTimePremium({ userId, customerId, days }) {
  if (!userId && !customerId) return null;
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
    RETURNING id, username, email, avatar, is_premium, language, tax_enabled, premium_until
  `, params);
  return rows[0] || null;
}

async function handleStripeEvent(event) {
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    if (session.mode === 'subscription') {
      await syncStripeSubscription({
        userId: session.client_reference_id || session.metadata?.user_id,
        customerId: session.customer,
        subscriptionId: session.subscription,
        status: 'active',
      });
    }
    if (session.mode === 'payment') {
      await grantOneTimePremium({
        userId: session.client_reference_id || session.metadata?.user_id,
        customerId: session.customer,
        days: session.metadata?.premium_days,
      });
    }
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
              ${trialEndsSql('users')} AS trial_ends_at
       FROM users WHERE id=$1`,
      [req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    const user = rows[0];

    if (user.is_premium || user.trial_active) return next();

    return res.status(402).json({
      error: 'Trial expired',
      message: 'Twój 3-dniowy okres próbny minął. Kup Premium, żeby dalej dodawać kupony bez limitu.',
      trial_active: false,
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
  const { username, email, password, language = 'pl' } = req.body;
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
      `INSERT INTO users (username, email, password_hash, language)
       VALUES ($1, $2, $3, $4)
       RETURNING id, username, email, language, tax_enabled, ${effectivePremiumSql('')} AS is_premium, ${trialActiveSql('')} AS trial_active, ${trialEndsSql('')} AS trial_ends_at, stripe_customer_id, avatar`,
      [cleanUsername, cleanEmail, hash, language === 'en' ? 'en' : 'pl']
    );
    const token = signUserToken(rows[0]);
    res.json({ token, user: rows[0] });
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
              ${trialEndsSql('users')} AS trial_ends_at
       FROM users WHERE LOWER(email)=LOWER($1) OR LOWER(username)=LOWER($1)`,
      [login.toLowerCase().trim()]
    );
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = signUserToken(rows[0]);
    res.json({
      token,
      user: {
        id: rows[0].id,
        username: rows[0].username,
        email: rows[0].email,
        language: rows[0].language,
        tax_enabled: rows[0].tax_enabled,
        is_premium: rows[0].effective_is_premium,
        has_stripe_customer: Boolean(rows[0].stripe_customer_id),
        trial_active: rows[0].trial_active,
        trial_ends_at: rows[0].trial_ends_at,
        avatar: rows[0].avatar
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, username, email, language, tax_enabled,
            ${effectivePremiumSql('users')} AS is_premium,
            ${trialActiveSql('users')} AS trial_active,
            ${trialEndsSql('users')} AS trial_ends_at,
            stripe_customer_id, premium_until, avatar
     FROM users WHERE id=$1`,
    [req.user.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Not found' });

  const user = rows[0];
  res.json({
    ...user,
    stripe_customer_id: undefined,
    has_stripe_customer: Boolean(user.stripe_customer_id),
    premium_until: user.premium_until,
    trial_days: TRIAL_DAYS,
    can_add: Boolean(user.is_premium || user.trial_active)
  });
});

app.patch('/api/auth/settings', authMiddleware, async (req, res) => {
  const { language, tax_enabled } = req.body;
  const cleanLanguage = language === 'en' ? 'en' : 'pl';
  await pool.query('UPDATE users SET language=$1, tax_enabled=$2 WHERE id=$3', [cleanLanguage, Boolean(tax_enabled), req.user.id]);
  res.json({ ok: true });
});

// ─── DISCORD OAUTH ────────────────────────────────────────────────────────────
// KROK 1: Redirect do Discord
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
      success_url: `${FRONTEND_URL}?billing=success`,
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
      success_url: `${FRONTEND_URL}?billing=onetime_success`,
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
    }

    const session = await stripe.checkout.sessions.create(sessionPayload);
    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe one-time checkout error:', err);
    res.status(500).json({ error: 'Could not create one-time checkout session' });
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
  const { date, bookmaker, category, stake, odds, bet_type, notes, selections, status } = req.body;
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
      `INSERT INTO bets (user_id, date, bookmaker, category, stake, odds, bet_type, notes, selections, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [
        req.user.id,
        date,
        normalizeText(bookmaker, 100),
        normalizeText(category, 50),
        parsedStake,
        parsedOdds,
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
  const { date, bookmaker, category, stake, odds, bet_type, status, notes, selections } = req.body;
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
      COALESCE(SUM(stake * odds) FILTER (WHERE status='won'), 0) as total_won_gross,
      COALESCE(AVG(odds), 0) as avg_odds
    FROM bets WHERE user_id=$1
  `, [req.user.id]);
  res.json(rows[0]);
});

// ─── AI SCAN ROUTE ────────────────────────────────────────────────────────────
app.post('/api/scan', authMiddleware, scanLimiter, upload.single('image'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No image provided' });
  const openai = getOpenAIClient();
  if (!openai) return res.status(503).json({ error: 'AI scanning not configured' });

  // Klient może przesłać aktualną datę — jeśli nie, bierzemy serwerową
  const today = req.body?.today || todayISO();

  try {
    const b64 = req.file.buffer.toString('base64');
    const mime = req.file.mimetype;

    const response = await openai.chat.completions.create({
      model: 'gpt-4o',
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
3. STAKE: Extract the exact number. Remove currency symbols. Use dot as decimal separator.
4. ODDS: Total combined odds of the slip (the big number, not individual selection odds).
5. BOOKMAKER: Name of the bookmaker if visible, else null.
6. BET TYPE: "single" (1 selection), "accumulator" (2+ selections combined), "system".

Return ONLY valid JSON, no markdown, no backticks, no explanation:
{"bookmaker":"name or null","stake":"number","odds":"number","betType":"single|accumulator|system","date":"YYYY-MM-DD","selections":[{"match":"team A vs team B","pick":"selection description","odds":"number","status":"won|lost|pending"}],"betStatus":"won|lost|pending","notes":"extra info or empty string"}`
          }
        ]
      }]
    });

    const text = response.choices[0]?.message?.content?.replace(/```json|```/g, '').trim();

    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (parseErr) {
      console.error('Scan JSON parse error:', text);
      return res.status(500).json({ error: 'AI zwróciło nieprawidłowy JSON. Spróbuj ponownie.' });
    }

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
        status: ['won', 'lost', 'pending'].includes(s.status) ? s.status : 'pending'
      }));
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
