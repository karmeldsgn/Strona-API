require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const OpenAI = require('openai');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3001;

// ─── DB ───────────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// ─── OPENAI ───────────────────────────────────────────────────────────────────
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({
  origin: function(origin, callback) {
    const allowed = [
      'https://www.typyzpiwnicy.pl',
      'https://typyzpiwnicy.pl',
      'http://localhost:3000',
      'http://localhost:3001',
      'http://localhost:5500',
      'http://127.0.0.1:5500'
    ];
    // Pozwala na zapytania bez origin (np. mobilki) lub te z listy allowed
    if (!origin || allowed.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Błąd CORS: Ten adres nie ma uprawnień!'));
    }
  },
  credentials: true,
}));
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

  // Dodaj kolumny Discord jeśli tabela users już istnieje (migracja)
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_id TEXT UNIQUE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_name TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS is_premium BOOLEAN DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS daily_count INTEGER DEFAULT 0;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS daily_reset DATE DEFAULT CURRENT_DATE;
    ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
    ALTER TABLE users ALTER COLUMN password_hash SET DEFAULT '';
  `).catch(() => {}); // ignoruj błędy jeśli kolumny już istnieją

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

// ─── MIDDLEWARE: limit 2 kuponów dziennie dla zwykłych userów ─────────────────
async function checkDailyLimit(req, res, next) {
  try {
    const { rows } = await pool.query(
      'SELECT is_premium, daily_count, daily_reset FROM users WHERE id=$1',
      [req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    const user = rows[0];

    // Premium → bez limitu
    if (user.is_premium) return next();

    // Sprawdź czy dziś trzeba zresetować licznik
    const today = new Date().toISOString().split('T')[0];
    const lastReset = user.daily_reset
      ? new Date(user.daily_reset).toISOString().split('T')[0]
      : '1970-01-01';

    let currentCount = user.daily_count || 0;
    if (lastReset < today) {
      await pool.query(
        'UPDATE users SET daily_count=0, daily_reset=$1 WHERE id=$2',
        [today, req.user.id]
      );
      currentCount = 0;
    }

    if (currentCount >= 2) {
      return res.status(429).json({
        error: 'Dzienny limit kuponów wyczerpany',
        message: 'Darmowe konto pozwala na 2 kupony dziennie. Zdobądź rangę Premium na Discordzie!',
        limit: 2,
        used: currentCount,
        is_premium: false,
        reset_at: new Date(new Date().setHours(24, 0, 0, 0)).toISOString()
      });
    }

    // Inkrementuj licznik
    await pool.query(
      'UPDATE users SET daily_count=daily_count+1, daily_reset=$1 WHERE id=$2',
      [today, req.user.id]
    );
    next();
  } catch (err) {
    console.error('checkDailyLimit error:', err);
    res.status(500).json({ error: 'Server error' });
  }
}

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { username, email, password, language = 'pl' } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short' });
  if (username.length < 3 || username.length > 50) return res.status(400).json({ error: 'Invalid username length' });

  try {
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      'INSERT INTO users (username, email, password_hash, language) VALUES ($1, $2, $3, $4) RETURNING id, username, email, language',
      [username.trim(), email.toLowerCase().trim(), hash, language]
    );
    const token = jwt.sign({ id: rows[0].id, username: rows[0].username }, process.env.JWT_SECRET, { expiresIn: '30d' });
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
      'SELECT * FROM users WHERE email=$1 OR username=$1',
      [login.toLowerCase().trim()]
    );
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: rows[0].id, username: rows[0].username }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({
      token,
      user: {
        id: rows[0].id,
        username: rows[0].username,
        email: rows[0].email,
        language: rows[0].language,
        tax_enabled: rows[0].tax_enabled,
        is_premium: rows[0].is_premium,
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
    'SELECT id, username, email, language, tax_enabled, is_premium, avatar, daily_count, daily_reset FROM users WHERE id=$1',
    [req.user.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Not found' });

  const user = rows[0];
  const today = new Date().toISOString().split('T')[0];
  const lastReset = user.daily_reset
    ? new Date(user.daily_reset).toISOString().split('T')[0]
    : '1970-01-01';
  const dailyUsed = lastReset < today ? 0 : (user.daily_count || 0);

  res.json({
    ...user,
    daily_used:      dailyUsed,
    daily_limit:     user.is_premium ? null : 2,
    daily_remaining: user.is_premium ? null : Math.max(0, 2 - dailyUsed)
  });
});

app.patch('/api/auth/settings', authMiddleware, async (req, res) => {
  const { language, tax_enabled } = req.body;
  await pool.query('UPDATE users SET language=$1, tax_enabled=$2 WHERE id=$3', [language, tax_enabled, req.user.id]);
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
  const FRONTEND = process.env.FRONTEND_URL || 'https://www.typyzpiwnicy.pl';

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
    const { rows } = await pool.query(`
      INSERT INTO users (discord_id, username, email, avatar, is_premium, password_hash)
      VALUES ($1, $2, $3, $4, $5, '')
      ON CONFLICT (discord_id) DO UPDATE SET
        username   = EXCLUDED.username,
        email      = COALESCE(EXCLUDED.email, users.email),
        avatar     = EXCLUDED.avatar,
        is_premium = EXCLUDED.is_premium
      RETURNING id, username, email, avatar, is_premium, language, tax_enabled
    `, [d.id, d.username, d.email || null, avatar, isPremium]);

    const user = rows[0];

    // 6. Wygeneruj JWT (używamy tego samego formatu co reszta: { id, username })
    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    // 7. Przekieruj na frontend z tokenem
    const userParam = encodeURIComponent(JSON.stringify({
      id:         user.id,
      username:   user.username,
      email:      user.email,
      avatar:     user.avatar,
      is_premium: user.is_premium,
      language:   user.language,
      tax_enabled: user.tax_enabled
    }));

    res.redirect(`${FRONTEND}?discord_token=${token}&discord_user=${userParam}`);

  } catch (err) {
    console.error('Discord callback error:', err.response?.data || err.message);
    res.redirect(`${FRONTEND}?auth_error=server_error`);
  }
});

// ─── BETS ROUTES ──────────────────────────────────────────────────────────────
app.get('/api/bets', authMiddleware, apiLimiter, async (req, res) => {
  const { status, limit = 200, offset = 0 } = req.query;
  let q = 'SELECT * FROM bets WHERE user_id=$1';
  const params = [req.user.id];
  if (status && status !== 'all') { q += ` AND status=$${params.length + 1}`; params.push(status); }
  q += ` ORDER BY date DESC, created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
  params.push(parseInt(limit), parseInt(offset));
  const { rows } = await pool.query(q, params);
  res.json(rows);
});

// POST /api/bets — z limitem dziennym dla zwykłych userów
app.post('/api/bets', authMiddleware, apiLimiter, checkDailyLimit, async (req, res) => {
  const { date, bookmaker, category, stake, odds, bet_type, notes, selections, status } = req.body;
  if (!date || !stake || !odds) return res.status(400).json({ error: 'Missing required fields' });

  const { rows } = await pool.query(
    `INSERT INTO bets (user_id, date, bookmaker, category, stake, odds, bet_type, notes, selections, status)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
    [req.user.id, date, bookmaker || null, category || null, parseFloat(stake), parseFloat(odds),
     bet_type || 'single', notes || null, JSON.stringify(selections || []), status || 'pending']
  );
  res.json(rows[0]);
});

app.patch('/api/bets/:id', authMiddleware, apiLimiter, async (req, res) => {
  const { status, notes, selections } = req.body;
  const { rows } = await pool.query(
    `UPDATE bets SET status=COALESCE($1,status), notes=COALESCE($2,notes),
     selections=COALESCE($3,selections), updated_at=NOW()
     WHERE id=$4 AND user_id=$5 RETURNING *`,
    [status, notes, selections ? JSON.stringify(selections) : null, req.params.id, req.user.id]
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
  if (!process.env.OPENAI_API_KEY) return res.status(503).json({ error: 'AI scanning not configured' });

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
            text: `You are a betting slip analyzer. Analyze this betting slip image carefully.
Determine status of each selection based on visual markers:
- "won" = green color, checkmark ✓, "trafiony", "wygrany", "won"
- "lost" = red, ✗ cross, "przegrany", "lost"
- "pending" = no markers, not played yet

Return ONLY valid JSON (no markdown, no backticks):
{"bookmaker":"name","stake":"amount","odds":"total odds","betType":"single or accumulator or system","date":"YYYY-MM-DD","selections":[{"match":"match name","pick":"selection","odds":"odds","status":"won/lost/pending"}],"betStatus":"won/lost/pending","notes":"any notes"}`
          }
        ]
      }]
    });

    const text = response.choices[0]?.message?.content?.replace(/```json|```/g, '').trim();
    const parsed = JSON.parse(text);
    res.json(parsed);
  } catch (e) {
    console.error('Scan error:', e);
    res.status(500).json({ error: 'Failed to analyze image' });
  }
});

// ─── HEALTH ───────────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

// ─── START ────────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`🚀 TzP API running on port ${PORT}`));
}).catch(e => { console.error('DB init failed:', e); process.exit(1); });
