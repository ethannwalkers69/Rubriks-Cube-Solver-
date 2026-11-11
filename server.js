'use strict';
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const { DATABASE_URL, ADMIN_PASSWORD } = process.env;
const PORT = process.env.PORT || 3000;
if (!DATABASE_URL || !ADMIN_PASSWORD) {
  console.error('Kulang ang environment variables: DATABASE_URL at ADMIN_PASSWORD');
  process.exit(1);
}

const pool = new Pool({ connectionString: DATABASE_URL, max: 5 });
const app = express();
app.set('trust proxy', 1); // Render proxy, para tamang IP ang makuha
app.disable('x-powered-by');
app.use(express.json({ limit: '2kb' }));

// ---- helpers ----
const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const samePw = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));

// simpleng rate limit (naka-memory)
const buckets = new Map();
function hit(key, max, windowMs) {
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || b.reset < now) { b = { n: 0, reset: now + windowMs }; buckets.set(key, b); }
  b.n++;
  return b.n <= max;
}
function blocked(key, max) {
  const b = buckets.get(key);
  return !!b && b.reset > Date.now() && b.n >= max;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, b] of buckets) if (b.reset < now) buckets.delete(k);
}, 60000).unref();

const NAME_RE = /^[\p{L}\p{N} _.\-]{2,20}$/u;

// ---- API ----
app.post('/api/visit', async (req, res) => {
  try {
    if (!hit('v:' + req.ip, 30, 3600e3)) return res.status(429).json({ error: 'too many requests' });
    const name = String((req.body && req.body.username) || '').trim().replace(/\s+/g, ' ');
    if (!NAME_RE.test(name) || name.toLowerCase() === 'admin') {
      return res.status(400).json({ error: 'invalid username' });
    }
    await pool.query('insert into visitors (username) values ($1)', [name]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/admin/users', async (req, res) => {
  try {
    const key = 'a:' + req.ip;
    if (blocked(key, 5)) return res.status(429).json({ error: 'too many attempts' });
    const pw = (req.body && req.body.password) || '';
    if (!samePw(pw, ADMIN_PASSWORD)) {
      hit(key, 5, 15 * 60e3);
      return res.status(401).json({ error: 'wrong password' });
    }
    buckets.delete(key);
    const { rows } = await pool.query(
      'select id, username, created_at from visitors order by created_at desc limit 500'
    );
    res.json({ users: rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

app.get('/healthz', (req, res) => res.send('ok'));

// ---- static website ----
app.use(express.static(path.join(__dirname, 'public')));

// JSON error handler (hal. maling JSON body)
app.use((err, req, res, next) => res.status(400).json({ error: 'bad request' }));

(async () => {
  await pool.query(`create table if not exists visitors (
    id         bigserial primary key,
    username   text not null,
    created_at timestamptz not null default now()
  )`);
  app.listen(PORT, '0.0.0.0', () => console.log('Running on port ' + PORT));
})().catch(e => { console.error(e); process.exit(1); });
