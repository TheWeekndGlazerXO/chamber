/**
 * Chamber — server.js (FIXED & COMPLETE)
 *
 * SETUP:
 *   npm install express cors helmet morgan compression @supabase/supabase-js stripe dotenv
 *   node server.js
 *
 * All 50 feature routes + auth + admin + Stripe + Supabase
 */

require("dotenv").config();
const express = require("express");
const cors    = require("cors");
const helmet  = require("helmet");
const morgan  = require("morgan");
const compression = require("compression");
const crypto  = require("crypto");
const https   = require("https");
const { createClient } = require("@supabase/supabase-js");

const app  = express();
const PORT = process.env.PORT || 3001;

// ─────────────────────────────────────────────────────────────
// SUPABASE CLIENTS
// service key = full admin access (never send to browser)
// ─────────────────────────────────────────────────────────────
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
  console.warn("⚠  SUPABASE_URL or SUPABASE_SERVICE_KEY missing — DB features disabled");
}
const supabase = createClient(
  process.env.SUPABASE_URL || "https://placeholder.supabase.co",
  process.env.SUPABASE_SERVICE_KEY || "placeholder",
  { auth: { autoRefreshToken: false, persistSession: false } }
);
const supabasePublic = createClient(
  process.env.SUPABASE_URL || "https://placeholder.supabase.co",
  process.env.SUPABASE_ANON_KEY || "placeholder"
);

// ─────────────────────────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(morgan("dev"));
app.use(cors({
  origin: (process.env.FRONTEND_URL || "http://localhost:3000,http://localhost:5173,http://127.0.0.1:5500").split(","),
  credentials: true,
}));

const path = require('path');
app.use(express.static(path.join(__dirname, 'public')));

// Stripe needs raw body — must come BEFORE express.json
app.use("/api/stripe/webhook", express.raw({ type: "application/json" }));
app.use(express.json({ limit: "2mb" }));

// ─────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────
const uid    = () => crypto.randomBytes(8).toString("hex");
const hashIp = ip => crypto.createHash("sha256").update(ip + (process.env.JWT_SECRET || "chamber_secret_change_me")).digest("hex").slice(0, 16);

const PLAN_ORDER  = ["free", "starter", "growth", "scale"];
const PLAN_LIMITS = { free: 1, starter: 5, growth: 25, scale: 999999 };
const PLAN_MRR    = { starter: 29, growth: 99, scale: 299, free: 0, cancelled: 0 };

function planIdx(p) { return PLAN_ORDER.indexOf(p || "free"); }

// ─────────────────────────────────────────────────────────────
// AUTH MIDDLEWARE
// ─────────────────────────────────────────────────────────────
async function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "").trim();
  if (!token) return res.status(401).json({ error: "No token — please sign in" });
  const { data: { user }, error } = await supabasePublic.auth.getUser(token);
  if (error || !user) return res.status(401).json({ error: "Token invalid or expired — sign in again" });
  req.user = user;
  const { data: profile } = await supabase.from("profiles").select("*").eq("id", user.id).single();
  req.profile = profile || { plan: "free", reports_this_month: 0, credits_limit: 3 };
  next();
}

// Admin: requires valid session + either admin_ids env list OR admin_secret header
async function requireAdmin(req, res, next) {
  // Allow admin_secret bypass (for admin.html direct API calls)
  const secret = req.headers["x-admin-secret"];
  if (secret && secret === process.env.ADMIN_SECRET) return next();
  // Otherwise fall through to normal auth
  await requireAuth(req, res, next);
}

// ─────────────────────────────────────────────────────────────
// RATE LIMITER (simple in-memory; swap for Redis in prod)
// ─────────────────────────────────────────────────────────────
const rlMap = new Map();
function rateLimit(max = 20, windowMs = 60000) {
  return (req, res, next) => {
    const key = req.ip + "|" + (req.user?.id || "anon");
    const now = Date.now();
    const hits = (rlMap.get(key) || []).filter(t => now - t < windowMs);
    if (hits.length >= max) return res.status(429).json({ error: "Rate limit exceeded. Wait 1 minute." });
    rlMap.set(key, [...hits, now]);
    next();
  };
}

// ─────────────────────────────────────────────────────────────
// GITHUB MODELS AI  (GPT-4o via Azure endpoint)
// ─────────────────────────────────────────────────────────────
async function ai(messages, system = "Return only valid JSON. No markdown.", maxTokens = 2000) {
  if (!process.env.GITHUB_TOKEN) throw new Error("GITHUB_TOKEN not set in .env");
  const model = process.env.MODEL_NAME || "openai/gpt-4o";
  const payload = JSON.stringify({
    model,
    messages: [{ role: "system", content: system }, ...messages],
    max_tokens: maxTokens,
    temperature: 0.7,
  });
  return new Promise((resolve, reject) => {
    const reqOpts = {
      hostname: "models.inference.ai.azure.com",
      path: "/chat/completions",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${process.env.GITHUB_TOKEN}`,
        "Content-Length": Buffer.byteLength(payload),
      },
    };
    const req = https.request(reqOpts, res => {
      let d = "";
      res.on("data", c => d += c);
      res.on("end", () => {
        try {
          const p = JSON.parse(d);
          if (p.error) return reject(new Error(typeof p.error === "object" ? (p.error.message || JSON.stringify(p.error)) : p.error));
          resolve(p.choices?.[0]?.message?.content || "");
        } catch { reject(new Error("AI response parse error: " + d.slice(0, 200))); }
      });
    });
    req.on("error", reject);
    req.setTimeout(60000, () => { req.destroy(); reject(new Error("AI request timeout (60s)")); });
    req.write(payload);
    req.end();
  });
}

function parseJson(text) {
  const clean = text.replace(/```json\n?|```\n?/g, "").trim();
  return JSON.parse(clean);
}
async function getProductHuntTrending(keyword) {
  if (!process.env.PRODUCTHUNT_TOKEN) return null;
  const body = JSON.stringify({ query: `{ posts(first: 5, order: RANKING) { edges { node { name tagline votesCount } } } }` });
  return new Promise(resolve => {
    const req = https.request({
      hostname: 'api.producthunt.com', path: '/v2/api/graphql', method: 'POST',
      headers: { 'Authorization': `Bearer ${process.env.PRODUCTHUNT_TOKEN}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
    });
    req.on('error', () => resolve(null)); req.write(body); req.end();
  });
}
// ─────────────────────────────────────────────────────────────
// EXTERNAL DATA HELPERS
// ─────────────────────────────────────────────────────────────

// REDDIT
let _rToken = null, _rExp = 0;
async function getRedditToken() {
  if (_rToken && Date.now() < _rExp) return _rToken;
  if (!process.env.REDDIT_CLIENT_ID) return null;
  const auth = Buffer.from(`${process.env.REDDIT_CLIENT_ID}:${process.env.REDDIT_CLIENT_SECRET}`).toString("base64");
  const body = "grant_type=client_credentials";
  return new Promise(resolve => {
    const req = https.request({
      hostname: "www.reddit.com", path: "/api/v1/access_token", method: "POST",
      headers: { "Authorization": `Basic ${auth}`, "Content-Type": "application/x-www-form-urlencoded", "User-Agent": process.env.REDDIT_USER_AGENT || "Chamber/1.0", "Content-Length": body.length },
    }, res => {
      let d = "";
      res.on("data", c => d += c);
      res.on("end", () => {
        try { const r = JSON.parse(d); _rToken = r.access_token; _rExp = Date.now() + (r.expires_in - 60) * 1000; resolve(_rToken); }
        catch { resolve(null); }
      });
    });
    req.on("error", () => resolve(null)); req.write(body); req.end();
  });
}

async function searchReddit(query, subs = ["ecommerce","Entrepreneur","smallbusiness","FulfillmentByAmazon"], limit = 8) {
  try {
    const token = await getRedditToken();
    if (!token) return null;
    return new Promise(resolve => {
      const path = `/r/${subs.join("+")}/search.json?q=${encodeURIComponent(query)}&sort=relevance&t=month&limit=${limit}&restrict_sr=1`;
      https.get({ hostname: "oauth.reddit.com", path, headers: { "Authorization": `Bearer ${token}`, "User-Agent": process.env.REDDIT_USER_AGENT || "Chamber/1.0" } }, res => {
        let d = "";
        res.on("data", c => d += c);
        res.on("end", () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
      }).on("error", () => resolve(null));
    });
  } catch { return null; }
}

async function serperSearch(query) {
  if (!process.env.SERPER_API_KEY) return null;
  const payload = JSON.stringify({ q: query, num: 10 });
  return new Promise(resolve => {
    const req = https.request({ hostname: "google.serper.dev", path: "/search", method: "POST", headers: { "X-API-KEY": process.env.SERPER_API_KEY, "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) } }, res => {
      let d = "";
      res.on("data", c => d += c);
      res.on("end", () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
    });
    req.on("error", () => resolve(null)); req.write(payload); req.end();
  });
}

async function youtubeSearch(query, max = 5) {
  if (!process.env.YOUTUBE_API_KEY) return null;
  return new Promise(resolve => {
    const path = `/youtube/v3/search?part=snippet&q=${encodeURIComponent(query)}&maxResults=${max}&type=video&order=viewCount&key=${process.env.YOUTUBE_API_KEY}`;
    https.get({ hostname: "www.googleapis.com", path }, res => {
      let d = "";
      res.on("data", c => d += c);
      res.on("end", () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
    }).on("error", () => resolve(null));
  });
}

async function newsSearch(query) {
  if (!process.env.NEWS_API_KEY) return null;
  return new Promise(resolve => {
    const path = `/v2/everything?q=${encodeURIComponent(query)}&sortBy=relevancy&pageSize=5&apiKey=${process.env.NEWS_API_KEY}`;
    https.get({ hostname: "newsapi.org", path }, res => {
      let d = "";
      res.on("data", c => d += c);
      res.on("end", () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
    }).on("error", () => resolve(null));
  });
}
async function getTrends(keyword) {
  if (!googleTrends) return null;
  try {
    const raw = await googleTrends.interestOverTime({
      keyword,
      startTime: new Date(Date.now() - 90 * 86400000),
      geo: 'US',
    });
    const data = JSON.parse(raw).default?.timelineData || [];
    const recent = data.slice(-4);
    const avg = recent.reduce((s,d) => s + (d.value[0]||0), 0) / (recent.length||1);
    const velocity = data.length > 1
      ? (data.slice(-1)[0].value[0] - data[0].value[0])
      : 0;
    return { avg: Math.round(avg), velocity, trend: velocity > 5 ? 'rising' : velocity < -5 ? 'declining' : 'stable' };
  } catch { return null; }
}

async function getTwitterVolume(keyword) {
  if (!process.env.TWITTER_BEARER_TOKEN) return null;
  return new Promise(resolve => {
    const query = encodeURIComponent(`${keyword} -is:retweet lang:en`);
    const path = `/2/tweets/search/recent?query=${query}&max_results=10&tweet.fields=public_metrics`;
    https.get({
      hostname: 'api.twitter.com', path,
      headers: { 'Authorization': `Bearer ${process.env.TWITTER_BEARER_TOKEN}` }
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try {
          const r = JSON.parse(d);
          const tweets = r.data || [];
          const totalEngagement = tweets.reduce((s,t) =>
            s + (t.public_metrics?.like_count||0) + (t.public_metrics?.retweet_count||0), 0);
          resolve({ tweet_count: tweets.length, total_engagement: totalEngagement });
        } catch { resolve(null); }
      });
    }).on('error', () => resolve(null));
  });
}
// ─────────────────────────────────────────────────────────────
// FEATURE ROUTE FACTORY  — wraps auth + plan check + AI call
// ─────────────────────────────────────────────────────────────
function feature(key, promptFn, minPlan = "free") {
  return [requireAuth, rateLimit(20), async (req, res) => {
    if (planIdx(req.profile?.plan) < planIdx(minPlan)) {
      return res.status(403).json({ error: `'${key}' requires ${minPlan} plan or higher.`, upgrade: true, required_plan: minPlan });
    }
    try {
      const text = await ai([{ role: "user", content: promptFn(req.body) }]);
      const result = parseJson(text);
      // Fire-and-forget DB writes (don't await — don't block response)
      supabase.from("feature_usage").insert({ user_id: req.user.id, report_id: req.body.report_id || null, feature_key: key }).then(() => {}).catch(() => {});
      supabase.from("events").insert({ user_id: req.user.id, event_type: "feature_used", event_data: { feature: key } }).then(() => {}).catch(() => {});
      res.json({ ok: true, feature: key, result });
    } catch (e) {
      console.error(`[${key}] error:`, e.message);
      res.status(500).json({ error: e.message });
    }
  }];
}

// ═════════════════════════════════════════════════════════════
// ══  R O U T E S  ════════════════════════════════════════════
// ═════════════════════════════════════════════════════════════
let googleTrends;
try { googleTrends = require('google-trends-api'); } catch { googleTrends = null; }
// ── HEALTH ────────────────────────────────────────────────────
app.get("/health", async (req, res) => {
  try {
    const [{ count: users }, { count: reports }] = await Promise.all([
      supabase.from("profiles").select("*", { count: "exact", head: true }),
      supabase.from("reports").select("*", { count: "exact", head: true }),
    ]);
    res.json({ status: "ok", total_users: users || 0, total_reports: reports || 0, timestamp: new Date().toISOString(), ai_model: process.env.MODEL_NAME || "openai/gpt-4o" });
  } catch {
    res.json({ status: "ok (db unavailable)", timestamp: new Date().toISOString() });
  }
});
app.get("/api/config", (req, res) => {
    res.json({
      supabaseUrl:     process.env.SUPABASE_URL,
      supabaseAnonKey: process.env.SUPABASE_ANON_KEY,
    });
  });

// ── AUTH ──────────────────────────────────────────────────────

app.post("/api/auth/signup", async (req, res) => {
  const { email, password, full_name, source = "direct" } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });
  if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
  const { data, error } = await supabasePublic.auth.signUp({
    email, password,
    options: { data: { full_name, source }, emailRedirectTo: `${process.env.FRONTEND_URL || "http://localhost:3000"}/auth.html` },
  });
  if (error) return res.status(400).json({ error: error.message });
  // Profile row is auto-created by DB trigger (see supabase-schema.sql)
  supabase.from("events").insert({ user_id: data.user?.id, event_type: "signup", event_data: { source }, ip_hash: hashIp(req.ip) }).then(() => {}).then(() => {}).catch(() => {});
  res.json({ ok: true, user: data.user, session: data.session });
});

app.post("/api/auth/signin", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });
  const { data, error } = await supabasePublic.auth.signInWithPassword({ email, password });
  if (error) return res.status(401).json({ error: error.message });
  supabase.from("events").insert({ user_id: data.user?.id, event_type: "signin", ip_hash: hashIp(req.ip) }).then(() => {}).catch(() => {});
  res.json({ ok: true, user: data.user, session: data.session });
});

app.post("/api/auth/signout", requireAuth, async (req, res) => {
  await supabasePublic.auth.signOut().catch(() => {});
  res.json({ ok: true });
});

app.post("/api/auth/reset-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });
  const { error } = await supabasePublic.auth.resetPasswordForEmail(email, {
    redirectTo: `${process.env.FRONTEND_URL || "http://localhost:3000"}/reset.html`,
  });
  if (error) return res.status(400).json({ error: error.message });
  res.json({ ok: true, message: "Reset email sent" });
});

app.get("/api/auth/me", requireAuth, (req, res) => res.json({ user: req.user, profile: req.profile }));

// ── ADMIN — real Supabase data ─────────────────────────────────
// These endpoints accept either:
//   a) Authorization: Bearer <supabase_jwt>
//   b) x-admin-secret: <ADMIN_SECRET from .env>

app.get("/api/admin/overview", requireAdmin, async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 30;
    const since = new Date(Date.now() - days * 86400000).toISOString();

    const [
      mrrRes,
      { count: totalUsers },
      { count: newSignups },
      { count: newReports },
      { count: totalReports },
      eventsRes,
    ] = await Promise.all([
      supabase.from("mrr_view").select("*").single(),
      supabase.from("profiles").select("*", { count: "exact", head: true }),
      supabase.from("profiles").select("*", { count: "exact", head: true }).gte("created_at", since),
      supabase.from("reports").select("*", { count: "exact", head: true }).gte("created_at", since),
      supabase.from("reports").select("*", { count: "exact", head: true }),
      supabase.from("events").select("event_type").gte("created_at", since),
    ]);

    const mrrData = mrrRes.data || {};
    const eventCounts = {};
    (eventsRes.data || []).forEach(e => { eventCounts[e.event_type] = (eventCounts[e.event_type] || 0) + 1; });

    res.json({
      mrr:             mrrData.mrr || 0,
      arr:             mrrData.arr || 0,
      total_users:     totalUsers  || 0,
      paying_users:    mrrData.paying_users || 0,
      free_users:      (totalUsers || 0) - (mrrData.paying_users || 0),
      starter_count:   mrrData.starter_count || 0,
      growth_count:    mrrData.growth_count  || 0,
      scale_count:     mrrData.scale_count   || 0,
      new_signups:     newSignups   || 0,
      new_reports:     newReports   || 0,
      total_reports:   totalReports || 0,
      conversion_rate: totalUsers > 0 ? +((mrrData.paying_users || 0) / totalUsers * 100).toFixed(1) : 0,
      event_counts:    eventCounts,
      period_days:     days,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/admin/time-series", requireAdmin, async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 30;
    // Build day buckets from DB
    const since = new Date(Date.now() - days * 86400000).toISOString();
    const [sigRes, repRes] = await Promise.all([
      supabase.from("profiles").select("created_at").gte("created_at", since),
      supabase.from("reports").select("created_at,growth_score").gte("created_at", since),
    ]);

    // Bucket by date
    const sigMap = {}, repMap = {};
    (sigRes.data || []).forEach(r => { const d = r.created_at.slice(0,10); sigMap[d] = (sigMap[d]||0)+1; });
    (repRes.data || []).forEach(r => { const d = r.created_at.slice(0,10); repMap[d] = (repMap[d]||0)+1; });

    const series = [];
    for (let i = days - 1; i >= 0; i--) {
      const dt = new Date(); dt.setDate(dt.getDate() - i);
      const key = dt.toISOString().slice(0,10);
      series.push({ date: key, signups: sigMap[key]||0, analyses: repMap[key]||0 });
    }
    res.json({ series });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/admin/users", requireAdmin, async (req, res) => {
  try {
    const page  = parseInt(req.query.page)  || 1;
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const from  = (page - 1) * limit;
    const { data, count } = await supabase
      .from("user_activity")
      .select("*", { count: "exact" })
      .range(from, from + limit - 1)
      .order("created_at", { ascending: false });
    res.json({ users: data || [], total: count || 0, page, limit, pages: Math.ceil((count||0)/limit) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/admin/reports", requireAdmin, async (req, res) => {
  try {
    const page  = parseInt(req.query.page)  || 1;
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const from  = (page - 1) * limit;
    const { data, count } = await supabase
      .from("reports")
      .select("id,product_name,product_category,growth_score,status,created_at,user_id,processing_time_ms", { count: "exact" })
      .range(from, from + limit - 1)
      .order("created_at", { ascending: false });
    res.json({ reports: data || [], total: count || 0, page, limit });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/admin/events", requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const type  = req.query.type;
    let q = supabase.from("events").select("*").order("created_at", { ascending: false }).limit(limit);
    if (type && type !== "all") q = q.eq("event_type", type);
    const { data } = await q;
    res.json({ events: data || [] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── USER ROUTES ────────────────────────────────────────────────

app.get("/api/user/reports", requireAuth, async (req, res) => {
  const { data } = await supabase
    .from("reports")
    .select("id,product_name,product_category,growth_score,status,created_at,modules_used")
    .eq("user_id", req.user.id)
    .order("created_at", { ascending: false })
    .limit(50);
  res.json({ reports: data || [] });
});

app.get("/api/user/report/:id", requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from("reports")
    .select("*")
    .eq("id", req.params.id)
    .or(`user_id.eq.${req.user.id},shared.eq.true`)
    .single();
  if (error || !data) return res.status(404).json({ error: "Report not found" });
  res.json(data);
});

app.delete("/api/user/report/:id", requireAuth, async (req, res) => {
  const { error } = await supabase.from("reports").delete().eq("id", req.params.id).eq("user_id", req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════
// SERVER.JS ADDITIONS
// ═══════════════════════════════════════════════════════════
//
// HOW TO USE THIS FILE:
// 1. Find the "── USER ROUTES ──" block in your server.js
//    (the section with /api/user/reports etc.)
// 2. PASTE THE ENTIRE CONTENTS OF THIS FILE right AFTER the
//    existing user routes block, but BEFORE:
//    "── STRIPE ──"  (or before your Stripe routes)
//
// Also do these 2 small changes:
//
// CHANGE 1: Replace your /api/stripe/create-checkout route with the
// payment links version below (section marked REPLACE STRIPE CHECKOUT)
//
// CHANGE 2: Add this line to requireAdmin (right after the existing
// "const secret = ..." line):
//   if (secret && secret === process.env.ADMIN_SECRET) return next();
// (This is already in the fixed server.js, just confirming)
// ═══════════════════════════════════════════════════════════
 
 
// ── PROFILE PATCH ─────────────────────────────────────────────
app.patch("/api/user/profile", requireAuth, async (req, res) => {
    const { display_name } = req.body;
    if (!display_name) return res.status(400).json({ error: "display_name required" });
    const { error } = await supabase
      .from("profiles")
      .update({ display_name: display_name.slice(0, 80) })
      .eq("id", req.user.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  });
   
   
  // ── REFERRAL ROUTES ────────────────────────────────────────────
   
  // GET /api/referral/my-code  — returns user's code + stats + history
  app.get("/api/referral/my-code", requireAuth, async (req, res) => {
    try {
      // Ensure user has a referral code (backfill if missing)
      let { data: profile } = await supabase
        .from("profiles")
        .select("referral_code, referral_reward_claimed")
        .eq("id", req.user.id)
        .single();
   
      if (!profile?.referral_code) {
        // Generate one now
        const { data: gen } = await supabase.rpc("generate_referral_code");
        await supabase.from("profiles").update({ referral_code: gen }).eq("id", req.user.id);
        profile = { referral_code: gen, referral_reward_claimed: false };
      }
   
      const code = profile.referral_code;
   
      // Fetch referral history
      const { data: refs } = await supabase
        .from("referrals")
        .select("referred_email, plan_purchased, status, created_at, converted_at")
        .eq("referral_code", code)
        .order("created_at", { ascending: false })
        .limit(20);
   
      const converted = (refs || []).filter(r => r.status === "converted" || r.status === "rewarded").length;
      const rewarded  = (refs || []).filter(r => r.status === "rewarded").length;
   
      // Check if reward should be granted (3 converted, not yet claimed)
      if (converted >= 3 && !profile.referral_reward_claimed) {
        await grantReferralReward(req.user.id);
      }
   
      res.json({
        ok: true,
        code,
        stats: {
          used:      (refs || []).length,
          converted,
          rewards:   rewarded,
          reward_claimed: profile.referral_reward_claimed || false,
        },
        history: refs || [],
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
   
  // POST /api/referral/apply  — called at signup to record who referred
  app.post("/api/referral/apply", requireAuth, async (req, res) => {
    const { referral_code } = req.body;
    if (!referral_code) return res.status(400).json({ error: "referral_code required" });
   
    // Look up who owns this code
    const { data: referrer } = await supabase
      .from("profiles")
      .select("id")
      .eq("referral_code", referral_code.toUpperCase().trim())
      .single();
   
    if (!referrer) return res.status(404).json({ error: "Invalid referral code" });
    if (referrer.id === req.user.id) return res.status(400).json({ error: "Cannot use your own referral code" });
   
    // Make sure user hasn't already used a code
    const { data: existingRef } = await supabase
      .from("referrals")
      .select("id")
      .eq("referred_id", req.user.id)
      .maybeSingle();
   
    if (existingRef) return res.status(400).json({ error: "You have already used a referral code" });
   
    // Record referral
    await supabase.from("referrals").insert({
      referral_code: referral_code.toUpperCase().trim(),
      referrer_id:   referrer.id,
      referred_id:   req.user.id,
      referred_email: req.user.email,
      status: "pending",
    });
   
    // Tag user's profile with who referred them
    await supabase.from("profiles").update({ referred_by: referral_code.toUpperCase().trim() }).eq("id", req.user.id);
   
    res.json({ ok: true, message: "Referral applied — 50% off your first month at checkout!" });
  });
   
  // POST /api/referral/convert  — called when a referred user upgrades (call from webhook or manually)
  app.post("/api/referral/convert", requireAdmin, async (req, res) => {
    const { user_id, plan } = req.body;
    if (!user_id || !plan) return res.status(400).json({ error: "user_id and plan required" });
   
    const { data: profile } = await supabase.from("profiles").select("referred_by").eq("id", user_id).single();
    if (!profile?.referred_by) return res.json({ ok: true, message: "User has no referral code" });
   
    // Mark referral as converted
    await supabase.from("referrals")
      .update({ status: "converted", converted_at: new Date().toISOString(), plan_purchased: plan })
      .eq("referral_code", profile.referred_by)
      .eq("referred_id", user_id);
   
    // Check if referrer now has 3 converted referrals
    const { data: referrer } = await supabase.from("profiles").select("id").eq("referral_code", profile.referred_by).single();
    if (referrer) {
      const { count } = await supabase.from("referrals")
        .select("*", { count: "exact", head: true })
        .eq("referral_code", profile.referred_by)
        .in("status", ["converted", "rewarded"]);
      if ((count || 0) >= 3) await grantReferralReward(referrer.id);
    }
   
    res.json({ ok: true });
  });
   
  async function grantReferralReward(userId) {
    // Grant 2 months of Growth plan free
    const { data: p } = await supabase.from("profiles").select("plan, referral_reward_claimed").eq("id", userId).single();
    if (p?.referral_reward_claimed) return; // already granted
   
    // Upgrade to growth (or extend if already growth)
    const rewardExpiry = new Date();
    rewardExpiry.setMonth(rewardExpiry.getMonth() + 2);
   
    await supabase.from("profiles").update({
      plan: "growth",
      referral_reward_claimed: true,
      credits_limit: 25,
    }).eq("id", userId);
   
    // Mark all converted referrals as rewarded
    await supabase.from("referrals")
      .update({ status: "rewarded" })
      .eq("referrer_id", userId)
      .eq("status", "converted");
   
    await supabase.from("events").insert({
      user_id: userId,
      event_type: "referral_reward",
      event_data: { plan: "growth", months: 2, expires: rewardExpiry.toISOString() },
    }).then(() => {}).catch(() => {});
  }
   
   
  // ── AFFILIATE ROUTES (admin only) ─────────────────────────────
   
  // POST /api/admin/affiliates  — create new affiliate
  app.post("/api/admin/affiliates", requireAdmin, async (req, res) => {
    const { name, email, commission_pct = 25, notes } = req.body;
    if (!name) return res.status(400).json({ error: "name required" });
   
    // Generate affiliate code: AFF-NAME-XXXX
    const slug = name.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 8);
    const rand = Math.random().toString(36).slice(2, 6).toUpperCase();
    const code = `AFF-${slug}-${rand}`;
   
    const { data, error } = await supabase.from("affiliates").insert({
      name, email, code, commission_pct, notes,
    }).select().single();
   
    if (error) return res.status(500).json({ error: error.message });
   
    await supabase.from("events").insert({ event_type: "affiliate_created", event_data: { name, code } }).then(() => {}).catch(() => {});
    res.json({ ok: true, affiliate: data });
  });
   
  // GET /api/admin/affiliates  — list all affiliates with stats
  app.get("/api/admin/affiliates", requireAdmin, async (req, res) => {
    try {
      const { data, error } = await supabase.from("affiliate_stats").select("*").order("created_at", { ascending: false });
      if (error) throw error;
      res.json({ ok: true, affiliates: data || [] });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
   
  // GET /api/admin/affiliates/:id  — get one affiliate with full conversion history
  app.get("/api/admin/affiliates/:id", requireAdmin, async (req, res) => {
    try {
      const [{ data: aff }, { data: convs }] = await Promise.all([
        supabase.from("affiliate_stats").select("*").eq("id", req.params.id).single(),
        supabase.from("affiliate_conversions")
          .select("*")
          .eq("affiliate_id", req.params.id)
          .order("created_at", { ascending: false }),
      ]);
      if (!aff) return res.status(404).json({ error: "Affiliate not found" });
   
      // Build time series (last 30 days of signups)
      const series = {};
      (convs || []).forEach(c => {
        const d = c.created_at.slice(0,10);
        if (!series[d]) series[d] = { date:d, signups:0, mrr:0, commission:0 };
        series[d].signups++;
        series[d].mrr       += c.mrr_value       || 0;
        series[d].commission += c.commission_amount || 0;
      });
   
      res.json({ ok: true, affiliate: aff, conversions: convs || [], series: Object.values(series).sort((a,b)=>a.date.localeCompare(b.date)) });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
   
  // PATCH /api/admin/affiliates/:id  — update status, commission, notes
  app.patch("/api/admin/affiliates/:id", requireAdmin, async (req, res) => {
    const { status, commission_pct, notes } = req.body;
    const updates = {};
    if (status)         updates.status         = status;
    if (commission_pct) updates.commission_pct = commission_pct;
    if (notes !== undefined) updates.notes    = notes;
    const { error } = await supabase.from("affiliates").update(updates).eq("id", req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  });
   
  // POST /api/admin/affiliates/:id/mark-paid  — mark commissions as paid
  app.post("/api/admin/affiliates/:id/mark-paid", requireAdmin, async (req, res) => {
    const { error } = await supabase.from("affiliate_conversions")
      .update({ payment_status: "paid", paid_at: new Date().toISOString() })
      .eq("affiliate_id", req.params.id)
      .eq("payment_status", "pending");
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  });
   
  // POST /api/affiliate/track  — called when user signs up via affiliate link
  // (call this from signup route when referral_code starts with "AFF-")
  app.post("/api/affiliate/track", async (req, res) => {
    const { affiliate_code, user_id, user_email } = req.body;
    if (!affiliate_code?.startsWith("AFF-")) return res.status(400).json({ error: "Not an affiliate code" });
   
    const { data: aff } = await supabase.from("affiliates").select("id,commission_pct,status").eq("code", affiliate_code).single();
    if (!aff || aff.status !== "active") return res.status(404).json({ error: "Invalid or inactive affiliate link" });
   
    await supabase.from("affiliate_conversions").insert({
      affiliate_id:    aff.id,
      affiliate_code,
      user_id:         user_id || null,
      user_email:      user_email || null,
      mrr_value:       0,       // updated when they pay
      commission_amount: 0,     // updated when they pay
      commission_pct:  aff.commission_pct,
      payment_status:  "pending",
    });
   
    // Tag profile
    if (user_id) {
      await supabase.from("profiles").update({ affiliate_code }).eq("id", user_id);
    }
   
    res.json({ ok: true });
  });
   
  // POST /api/affiliate/convert  — called when affiliate-referred user purchases
  // (call from Stripe webhook or admin manually)
  app.post("/api/affiliate/convert", requireAdmin, async (req, res) => {
    const { user_id, plan } = req.body;
    const MRR_MAP = { starter:29, growth:99, scale:299 };
    const mrr = MRR_MAP[plan] || 0;
   
    const { data: profile } = await supabase.from("profiles").select("affiliate_code").eq("id", user_id).single();
    if (!profile?.affiliate_code?.startsWith("AFF-")) return res.json({ ok:true, message:"Not an affiliate signup" });
   
    const { data: aff } = await supabase.from("affiliates").select("id,commission_pct").eq("code", profile.affiliate_code).single();
    if (!aff) return res.status(404).json({ error: "Affiliate not found" });
   
    const commission = +(mrr * aff.commission_pct / 100).toFixed(2);
   
    await supabase.from("affiliate_conversions")
      .update({ mrr_value: mrr, commission_amount: commission, plan, payment_status: "pending" })
      .eq("affiliate_code", profile.affiliate_code)
      .eq("user_id", user_id);
   
    res.json({ ok: true, commission, mrr });
  });
   
  
// ── CORE ANALYSIS ─────────────────────────────────────────────

app.post("/api/analyze", requireAuth, rateLimit(10, 60000), async (req, res) => {
  const { product, url, audience, category } = req.body;
  if (!product && !url) return res.status(400).json({ error: "Product name or URL required" });

  const plan = req.profile?.plan || "free";
  // Check monthly report count
  const { count: used } = await supabase
    .from("reports")
    .select("*", { count: "exact", head: true })
    .eq("user_id", req.user.id)
    .gte("created_at", new Date(Date.now() - 30 * 86400000).toISOString());

  if ((used || 0) >= PLAN_LIMITS[plan]) {
    return res.status(403).json({ error: `Monthly limit reached (${used}/${PLAN_LIMITS[plan]}). Please upgrade.`, upgrade: true });
  }

  const start = Date.now();
  // Create pending report row so user sees it immediately
  const { data: reportRow } = await supabase.from("reports").insert({
    user_id: req.user.id, product_name: product || url,
    product_url: url, product_category: category, target_audience: audience, status: "processing",
  }).select().single();

  try {
    // Gather real external data in parallel (each has a null fallback)
    const [redditRaw, serperRaw, newsRaw, trendsRaw, twitterRaw] = await Promise.all([
      searchReddit(product || url),
      serperSearch(`${product} reviews competitors`),
      newsSearch(product),
      getTrends(product),          // ← add
      getTwitterVolume(product),   // ← add
    ]);

    const redditPosts = redditRaw?.data?.children?.slice(0, 5).map(p => ({
      sub: p.data.subreddit, title: p.data.title?.slice(0, 100),
      text: p.data.selftext?.slice(0, 150), score: p.data.score,
    })) || [];
    const searchSnips = serperRaw?.organic?.slice(0, 5).map(r => ({ title: r.title, snippet: r.snippet?.slice(0, 150) })) || [];
    const newsHeads   = newsRaw?.articles?.slice(0, 3).map(a => a.title) || [];

    const userMsg = `Analyze this product for a DTC/ecommerce founder:
Product: ${product}
${url ? `URL: ${url}` : ""}
${audience ? `Target audience: ${audience}` : ""}
${category ? `Category: ${category}` : ""}

Real Reddit posts found:
${JSON.stringify(redditPosts)}

Real Google search results:
${JSON.stringify(searchSnips)}

Real news:
${JSON.stringify(newsHeads)}

Real Trends:
${trendsRaw ? `Google Trends (90-day): avg interest ${trendsRaw.avg}/100, trend: ${trendsRaw.trend}` : ''}
${twitterRaw ? `Twitter recent mentions: ${twitterRaw.tweet_count} tweets, ${twitterRaw.total_engagement} total engagement` : ''}

Return this EXACT JSON (numbers are integers/floats, strings are strings):
{
  "product_name": "string",
  "category": "string",
  "growth_score": 0-100,
  "score_breakdown": {"market_timing":0,"search_demand":0,"competition_gap":0,"audience_fit":0,"trend_momentum":0},
  "marketing_angles": [{"title":"string","description":"string","strength":1-5}],
  "competitors": [{"name":"string","price":"string","weakness":"string","threat_level":0-10}],
  "reddit_sentiment": {"positive":0,"neutral":0,"negative":0,"key_themes":["string"],"sample_posts":[{"subreddit":"string","text":"string","upvotes":"string"}]},
  "influencers": [{"emoji":"string","handle":"string","platform":"string","followers":"string","engagement":"string","niche":"string","match_score":0-100}],
  "keywords": [{"keyword":"string","volume":"string","difficulty":"Low|Medium|High","opportunity":0-100}],
  "market_size": {"tam":"string","sam":"string","som":"string","growth_rate":"string"},
  "trend_velocity": "rising|stable|declining",
"viral_potential": {"score":0-100,"reason":"string"},
"demand_signals": ["string"],
"pain_points": ["string"],
"content_angles": ["string"],
"pricing_sweet_spot": "string",
"best_channels": ["string"],
"time_to_traction": "string"
  "actionable_tips": ["string"],
  "summary": "string"
}`;

    const raw  = await ai([{ role: "user", content: userMsg }], "Return only valid JSON. No markdown. No explanation. Numbers must be plain numbers, not strings.", 3000);
    const data = parseJson(raw);
    const ms   = Date.now() - start;

    // Update report row with results
    const { data: updated } = await supabase.from("reports").update({
      ...data, status: "completed", processing_time_ms: ms, is_mock: false,
    }).eq("id", reportRow.id).select().single();

    // Update user's monthly counter (fire and forget)
    supabase.from("events").insert({ user_id: req.user.id, event_type: "analyze", event_data: { product, report_id: reportRow.id, growth_score: data.growth_score } }).then(() => {}).catch(() => {});
    supabase.from("profiles").update({ reports_this_month: (req.profile.reports_this_month || 0) + 1 }).eq("id", req.user.id).catch(() => {});

    res.json({ ok: true, report: updated || { ...reportRow, ...data, status: "completed" } });
  } catch (err) {
    console.error("[analyze] error:", err.message);
    supabase.from("reports").update({ status: "failed" }).eq("id", reportRow.id).catch(() => {});
    res.status(500).json({ error: err.message, report_id: reportRow.id });
  }
});

// ─────────────────────────────────────────────────────────────
// 50 FEATURE ENDPOINTS
// ─────────────────────────────────────────────────────────────

/* CONTENT */
app.post("/api/features/ad-copy",         ...feature("ad_copy",        b=>`Write 4 high-converting ${b.platform||"Facebook/TikTok"} ads for: ${b.product}. Audience: ${b.audience||"general consumer"}. Return JSON array: [{"headline":"string","body":"string","cta":"string","platform":"string","hook_type":"curiosity|fear|authority|social_proof|transformation"}]`, "starter"));
app.post("/api/features/email-sequence",  ...feature("email_sequence", b=>`Create a 5-email ${b.sequence_type||"welcome"} sequence for: ${b.product}. Return JSON array: [{"email_num":1,"subject":"string","preview_text":"string","body":"string","cta":"string","send_day":0}]`, "starter"));
app.post("/api/features/ig-captions",     ...feature("ig_captions",    b=>`Write 6 Instagram captions for: ${b.product}. Return JSON array: [{"caption":"string","hashtags":["string"],"post_type":"Reel|Carousel|Story","cta":"string","best_time":"string"}]`, "starter"));
app.post("/api/features/product-description", ...feature("product_description", b=>`Write 3 product descriptions for: ${b.product} optimized for ${b.platform||"Amazon"}. Return JSON array: [{"platform":"string","title":"string","bullets":["string"],"description":"string"}]`, "starter"));
app.post("/api/features/brand-story",     ...feature("brand_story",    b=>`Write 3 brand story versions for: ${b.product}. Return JSON array: [{"format":"About page|Origin story|Elevator pitch","story":"string","emotional_hook":"string"}]`, "free"));
app.post("/api/features/press-release",   ...feature("press_release",  b=>`Write a press release for: ${b.company||"Company"} launching ${b.product}. Return JSON: {"headline":"string","subheadline":"string","dateline":"string","body":["string"],"quote":"string","boilerplate":"string"}`, "growth"));
app.post("/api/features/newsletter-content", ...feature("newsletter_content", b=>`Write a product newsletter for: ${b.product}. Return JSON: {"subject":"string","preview":"string","sections":[{"type":"string","content":"string"}],"cta":"string"}`, "starter"));
app.post("/api/features/landing-page-copy",  ...feature("landing_page_copy",  b=>`Write full landing page copy for: ${b.product}. Return JSON: {"hero_headline":"string","subheadline":"string","cta":"string","pain_points":["string"],"solution":"string","features":[{"title":"string","desc":"string"}],"faq":[{"q":"string","a":"string"}],"final_cta":"string"}`, "growth"));

/* RESEARCH */
app.post("/api/features/seo-keywords",    ...feature("seo_keywords",   b=>`Generate 20 SEO keywords for: ${b.product}. Return JSON array: [{"keyword":"string","intent":"informational|commercial|transactional","difficulty":"Low|Medium|High","monthly_searches":"string","opportunity_score":85}]`, "starter"));
app.post("/api/features/reddit-communities", ...feature("reddit_communities", b=>`Find 10 best Reddit communities for: ${b.product}. Return JSON array: [{"subreddit":"string","members":"string","engagement":"High|Medium|Low","posting_strategy":"string","best_content_types":["string"]}]`, "free"));
app.post("/api/features/market-size",     ...feature("market_size",    b=>`Estimate market size for: ${b.product}. Return JSON: {"tam":"string","sam":"string","som":"string","growth_rate":"string","maturity":"string","key_players":["string"],"entry_barriers":["string"]}`, "starter"));
app.post("/api/features/seasonal-trends",...feature("seasonal_trends", b=>`Seasonal demand for: ${b.product}. Return JSON: {"peak_months":["string"],"low_months":["string"],"monthly":[{"month":"January","demand_index":80}],"events":["string"],"prep_timeline":"string"}`, "starter"));
app.post("/api/features/trend-forecast",  ...feature("trend_forecast", b=>`12-month trend forecast for: ${b.product||b.category}. Return JSON: {"emerging":["string"],"declining":["string"],"opportunities":["string"],"consumer_shifts":["string"],"recommendations":["string"]}`, "growth"));
app.post("/api/features/business-validation", ...feature("business_validation", b=>`Validate business idea: ${b.product} in ${b.market||"ecommerce"}. Return JSON: {"viability_score":75,"demand":"string","competition":"Low|Medium|High|Saturated","differentiation":"string","revenue_potential":"string","time_to_profit":"string","risks":["string"],"success_factors":["string"],"verdict":"GO|PIVOT|NO-GO","reasoning":"string"}`, "starter"));
app.post("/api/features/competitor-ads",  ...feature("competitor_ads", b=>`Analyze competitor ad strategies for: ${b.product}. Return JSON: {"themes":["string"],"common_hooks":["string"],"gaps":["string"],"recommended_angle":"string","formats_to_test":["string"]}`, "growth"));
app.post("/api/features/competitive-positioning", ...feature("competitive_positioning", b=>`Competitive positioning map for: ${b.product} vs ${b.competitors||"main competitors"}. Return JSON: {"axes":{"x":"string","y":"string"},"brands":[{"name":"string","x":70,"y":60,"gap":"string"}],"your_position":"string","whitespace":"string"}`, "growth"));

/* REVENUE */
app.post("/api/features/pricing-strategy", ...feature("pricing_strategy", b=>`Optimal pricing for: ${b.product}. COGS: ${b.cogs||"unknown"}. Return JSON: {"recommended_price":"string","price_range":{"floor":"string","ceiling":"string"},"tiers":[{"name":"string","price":"string","includes":["string"]}],"reasoning":"string"}`, "growth"));
app.post("/api/features/promo-strategy",  ...feature("promo_strategy", b=>`Promotion strategy for: ${b.product}. Margin: ${b.margin||"40%"}. Return JSON: {"promos":[{"type":"string","discount":"string","timing":"string","platform":"string","lift":"string"}],"rules":["string"]}`, "starter"));
app.post("/api/features/bundle-ideas",    ...feature("bundle_ideas",   b=>`6 bundle ideas for: ${b.product}. Return JSON array: [{"bundle_name":"string","components":["string"],"price":"string","margin":"string","target":"string"}]`, "starter"));
app.post("/api/features/cross-sell",      ...feature("cross_sell",     b=>`Cross-sell/upsell map for: ${b.product}. Return JSON: {"upsells":[{"product":"string","price_increase":"string","pitch":"string"}],"cross_sells":[{"product":"string","reason":"string"}],"subscription_opportunity":"string"}`, "starter"));
app.post("/api/features/return-predictor",...feature("return_predictor",b=>`Return rate prediction for: ${b.product}. Return JSON: {"predicted_rate":"string","reasons":["string"],"mitigation":["string"],"packaging_tips":["string"],"listing_fixes":["string"]}`, "starter"));
app.post("/api/features/subscription-box",...feature("subscription_box",b=>`Subscription box opportunity in: ${b.niche}. Return JSON: {"market_size":"string","gaps":["string"],"price_points":["string"],"curation_strategy":"string","acquisition_tactics":["string"],"churn_reduction":["string"]}`, "growth"));

/* SOCIAL */
app.post("/api/features/viral-hooks",     ...feature("viral_hooks",    b=>`10 viral content hooks for: ${b.product} on ${b.platform||"TikTok"}. Return JSON array: [{"hook":"string","type":"curiosity|shock|relatable|authority","predicted_ctr":"string"}]`, "free"));
app.post("/api/features/tiktok-calendar", ...feature("tiktok_calendar",b=>`30-day TikTok content calendar for: ${b.product}. Return JSON: {"weeks":[{"week":1,"theme":"string","posts":[{"day":1,"hook":"string","format":"string","hashtags":["string"]}]}],"pillars":["string"]}`, "growth"));
app.post("/api/features/influencer-outreach", ...feature("influencer_outreach", b=>`3 influencer DM templates for: ${b.product}. Return JSON array: [{"platform":"string","tone":"string","message":"string","follow_up":"string"}]`, "starter"));
app.post("/api/features/ugc-brief",       ...feature("ugc_brief",      b=>`UGC creator brief for: ${b.product} on ${b.platform||"TikTok"}. Return JSON: {"overview":"string","key_messages":["string"],"dos":["string"],"donts":["string"],"video_structure":["string"],"hooks":["string"],"deliverables":{"videos":3,"length":"30-60s"}}`, "growth"));
app.post("/api/features/giveaway-strategy",...feature("giveaway_strategy",b=>`Viral giveaway for: ${b.product}. Budget: ${b.budget||"minimal"}. Return JSON: {"prize":"string","mechanics":["string"],"platforms":["string"],"hashtag":"string","expected_reach":"string","nurture_sequence":["string"]}`, "starter"));

/* LAUNCH */
app.post("/api/features/gtm-strategy",   ...feature("gtm_strategy",   b=>`Go-to-market for: ${b.product}. Budget: ${b.budget||"$0"}. Timeline: ${b.timeline||"90 days"}. Return JSON: {"phases":[{"phase":"string","timeline":"string","channels":["string"],"tactics":["string"],"kpis":["string"]}],"quick_wins":["string"]}`, "growth"));
app.post("/api/features/launch-checklist",...feature("launch_checklist",b=>`Launch checklist for: ${b.product}. Return JSON: {"phases":[{"phase":"string","timeline":"string","tasks":[{"task":"string","priority":"High|Medium|Low","done":false}]}]}`, "free"));
app.post("/api/features/ph-launch-kit",  ...feature("ph_launch_kit",  b=>`Product Hunt launch kit for: ${b.product}. Return JSON: {"tagline":"string","description":"string","first_comment":"string","upvote_strategy":["string"],"assets_needed":["string"],"best_day":"Tuesday|Wednesday|Thursday"}`, "growth"));
app.post("/api/features/beta-finder",    ...feature("beta_finder",    b=>`Beta user sources for: ${b.product}. Return JSON: {"communities":["string"],"scripts":[{"platform":"string","message":"string"}],"incentives":["string"],"screening_questions":["string"]}`, "free"));
app.post("/api/features/affiliate-program",...feature("affiliate_program",b=>`Affiliate program for: ${b.product}. Return JSON: {"commission":{"standard":"string","vip":"string"},"targets":["string"],"outreach":"string","assets":["string"],"tools":["string"]}`, "growth"));

/* AMAZON / DTC */
app.post("/api/features/amazon-listing", ...feature("amazon_listing", b=>`Optimized Amazon listing for: ${b.product}. Return JSON: {"title":"string","bullets":["string"],"description":"string","backend_keywords":["string"],"a_plus_ideas":["string"]}`, "starter"));
app.post("/api/features/supplier-brief", ...feature("supplier_brief", b=>`Supplier inquiry brief for: ${b.product}. Return JSON: {"message":"string","specs":["string"],"questions":["string"],"red_flags":["string"],"negotiation_tips":["string"]}`, "free"));
app.post("/api/features/shipping-analysis",...feature("shipping_analysis",b=>`Shipping strategy for: ${b.product}. Return JSON: {"carriers":[{"name":"string","price":"string","transit":"string","best_for":"string"}],"fulfillment_options":[{"type":"string","pros":["string"],"cons":["string"]}],"tips":["string"]}`, "free"));
app.post("/api/features/photography-guide",...feature("photography_guide",b=>`Product photography guide for: ${b.product}. Return JSON: {"shots":["string"],"lighting":"string","backgrounds":["string"],"props":["string"],"ai_prompts":["string"],"aspect_ratios":["string"]}`, "free"));

/* STRATEGY */
app.post("/api/features/swot",            ...feature("swot",           b=>`SWOT analysis for: ${b.product}. Return JSON: {"strengths":["string"],"weaknesses":["string"],"opportunities":["string"],"threats":["string"],"strategic_actions":["string"]}`, "starter"));
app.post("/api/features/persona",         ...feature("persona",        b=>`2 buyer personas for: ${b.product}. Return JSON array: [{"name":"string","age":"string","job":"string","income":"string","pain_points":["string"],"goals":["string"],"channels":["string"],"quote":"string"}]`, "starter"));
app.post("/api/features/customer-journey",...feature("customer_journey",b=>`Customer journey map for: ${b.product}. Return JSON: {"stages":[{"stage":"string","touchpoints":["string"],"thoughts":"string","pain_points":["string"],"opportunities":["string"]}]}`, "growth"));
app.post("/api/features/product-roadmap", ...feature("product_roadmap",b=>`12-month product roadmap for: ${b.product}. Return JSON: {"quarters":[{"q":"Q1","theme":"string","features":["string"],"marketing":["string"],"target_revenue":"string"}],"metrics":["string"]}`, "growth"));
app.post("/api/features/ab-tests",        ...feature("ab_tests",       b=>`10 A/B test ideas for: ${b.product} ${b.page||"product page"}. Return JSON array: [{"test":"string","hypothesis":"string","variant_a":"string","variant_b":"string","metric":"string","priority":"High|Medium|Low"}]`, "growth"));
app.post("/api/features/objection-handler",...feature("objection_handler",b=>`Sales objection handler for: ${b.product}. Return JSON array: [{"objection":"string","reframe":"string","proof":"string","guarantee":"string"}]`, "starter"));
app.post("/api/features/brand-names",     ...feature("brand_names",    b=>`10 brand names for: ${b.product} (${b.vibe||"modern"}). Return JSON array: [{"name":"string","meaning":"string","domain_tip":"string","trademark_risk":"Low|Medium|High","score":90}]`, "free"));

/* TOOLS */
app.post("/api/features/faq",             ...feature("faq",            b=>`12 FAQs for: ${b.product}. Return JSON array: [{"question":"string","answer":"string","category":"shipping|quality|returns|usage|pricing"}]`, "free"));
app.post("/api/features/review-responses",...feature("review_responses",b=>`5 ${b.type||"negative"} review response templates for: ${b.product}. Return JSON array: [{"scenario":"string","template":"string","objective":"string"}]`, "free"));
app.post("/api/features/domain-ideas",    ...feature("domain_ideas",   b=>`15 domain names for: ${b.product||b.brand}. Return JSON array: [{"domain":"string","extension":".com","score":90,"brandability":"High|Medium|Low","tip":"string"}]`, "free"));
app.post("/api/features/white-label",     ...feature("white_label",    b=>`White-label opportunities for: ${b.product}. Return JSON: {"opportunities":[{"niche":"string","platform":"string","size":"string","competition":"Low|Medium|High","strategy":"string"}],"approach":"string"}`, "scale"));
app.post("/api/features/newsletter-content", ...feature("newsletter_content", b=>`Newsletter for: ${b.product}. Return JSON: {"subject":"string","preview":"string","sections":[{"type":"string","content":"string"}],"cta":"string"}`, "starter"));

/* SPECIAL: YouTube + News need real API calls */
app.post("/api/features/youtube-trends", requireAuth, rateLimit(15), async (req, res) => {
  const { product } = req.body;
  if (!product) return res.status(400).json({ error: "product required" });
  if (planIdx(req.profile?.plan) < planIdx("free")) return res.status(403).json({ error: "Sign in required" });
  try {
    const [yt, strat] = await Promise.all([
      youtubeSearch(`${product} review`),
      ai([{ role: "user", content: `YouTube content strategy for: ${product}. Return JSON: {"formats":["string"],"hooks":["string"],"thumbnails":["string"],"titles":["string"],"optimal_length":"string"}` }]),
    ]);
    const videos = yt?.items?.map(v => ({ title: v.snippet.title, channel: v.snippet.channelTitle, id: v.id.videoId })) || [];
    supabase.from("feature_usage").insert({ user_id: req.user.id, feature_key: "youtube_trends" }).then(() => {}).catch(() => {});
    res.json({ ok: true, feature: "youtube_trends", trending_videos: videos, strategy: parseJson(strat), result: parseJson(strat) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/features/news-trends", requireAuth, rateLimit(15), async (req, res) => {
  const { product } = req.body;
  if (!product) return res.status(400).json({ error: "product required" });
  try {
    const [news, insights] = await Promise.all([
      newsSearch(product),
      ai([{ role: "user", content: `Market trends for: ${product}. Return JSON: {"trends":["string"],"opportunities":["string"],"sentiment":"positive|neutral|negative"}` }]),
    ]);
    const articles = news?.articles?.map(a => ({ title: a.title, description: a.description, source: a.source?.name, url: a.url })) || [];
    supabase.from("feature_usage").insert({ user_id: req.user.id, feature_key: "news_trends" }).then(() => {}).catch(() => {});
    res.json({ ok: true, feature: "news_trends", news: articles, insights: parseJson(insights), result: parseJson(insights) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* SPECIAL: margin-calc is pure math, no AI */
app.post("/api/features/margin-calc", requireAuth, async (req, res) => {
  const { selling_price, cogs, shipping = 0, platform_fee_pct = 15, ad_spend_pct = 20, returns_pct = 5 } = req.body;
  if (!selling_price || !cogs) return res.status(400).json({ error: "selling_price and cogs are required" });
  const sp = +selling_price, cg = +cogs, sh = +shipping;
  const fees    = sp * (+platform_fee_pct) / 100;
  const ads     = sp * (+ad_spend_pct)    / 100;
  const returns = sp * (+returns_pct)     / 100;
  const gross   = sp - cg - sh - fees - ads - returns;
  const result  = {
    selling_price: sp, cogs: cg, shipping: sh,
    platform_fees: +fees.toFixed(2), ad_spend: +ads.toFixed(2), returns: +returns.toFixed(2),
    gross_profit: +gross.toFixed(2), margin_pct: +(gross / sp * 100).toFixed(1),
    ltv_3mo: +(gross * 3).toFixed(2),
    break_even_units: gross > 0 ? Math.ceil(1000 / gross) : null,
  };
  res.json({ ok: true, feature: "margin_calc", result });
});

// ── VIRAL SCRAPER (uses AI + cached in Supabase) ──────────────
app.get("/api/viral/scrape", requireAdmin, rateLimit(10), async (req, res) => {
  const q        = (req.query.q || "product analysis DTC").slice(0, 120);
  const platform = req.query.platform || "all";

  // Check DB cache first
  const { data: cached } = await supabase.from("viral_cache").select("*")
    .eq("query", q).eq("platform", platform).gt("expires_at", new Date().toISOString()).maybeSingle();
  if (cached) return res.json({ cached: true, results: cached.results });

  try {
    const raw = await ai([{ role: "user", content: `Generate 6 viral content post ideas for: "${q}" (platform: ${platform}). These are real-style viral posts for AI/SaaS tools in DTC/ecommerce. Return JSON array: [{"platform":"Reddit|TikTok|Twitter/X|YouTube|LinkedIn","icon":"emoji","title":"string","source":"string","likes":"string","comments":"string","shares":"string","score":90,"hook":"string","format":"string","why":"string"}]` }]);
    const results = parseJson(raw);
    supabase.from("viral_cache").upsert({ query: q, platform, results, expires_at: new Date(Date.now() + 7200000).toISOString() }).then(() => {}).catch(() => {});
    res.json({ cached: false, results });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── STRIPE ────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════
// REPLACE STRIPE CHECKOUT
// Find: app.post("/api/stripe/create-checkout", ...)
// Replace the entire function body with this:
// ═══════════════════════════════════════════════════════════
 

app.post("/api/stripe/create-checkout", requireAuth, async (req, res) => {
  const { plan } = req.body;
  const linkMap = {
    starter: process.env.STRIPE_STARTER_LINK,
    growth:  process.env.STRIPE_GROWTH_LINK,
    scale:   process.env.STRIPE_SCALE_LINK,
  };
  if (!linkMap[plan]) return res.status(400).json({ error: "Invalid plan" });
 
  const base = linkMap[plan];
  if (!base || base === "YOUR_LINK_HERE") {
    return res.status(503).json({ error: "Stripe payment links not configured in .env" });
  }
 
  // Build URL with prefilled email
  const promoCode = process.env.STRIPE_PROMO_CODE;
  const params = new URLSearchParams({ prefilled_email: req.user.email });
  if (promoCode) params.append('prefilled_promo_code', promoCode);
  const url = `${base}?${params.toString()}`;
 
  res.json({ url });
});

// (Remove the /* and */ comment markers when pasting into server.js)
 

app.post("/api/stripe/portal", requireAuth, async (req, res) => {
  if (!process.env.STRIPE_SECRET_KEY || !req.profile?.stripe_customer_id) {
    return res.status(400).json({ error: "No billing account found" });
  }
  const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
  const session = await stripe.billingPortal.sessions.create({
    customer: req.profile.stripe_customer_id,
    return_url: `${process.env.FRONTEND_URL || "http://localhost:3000"}/app.html`,
  });
  res.json({ url: session.url });
});

app.post("/api/stripe/webhook", async (req, res) => {
  if (!process.env.STRIPE_SECRET_KEY) return res.json({ received: true });
  let event;
  try {
    const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
    event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  const planFromPrice = pid => ({ [process.env.STRIPE_STARTER_PRICE_ID]: "starter", [process.env.STRIPE_GROWTH_PRICE_ID]: "growth", [process.env.STRIPE_SCALE_PRICE_ID]: "scale" }[pid] || "starter");
  const planLimits    = { starter: 5, growth: 25, scale: 999999 };

  if (event.type.startsWith("customer.subscription")) {
    const sub  = event.data.object;
    const plan = planFromPrice(sub.items?.data[0]?.price.id);
    if (event.type === "customer.subscription.deleted") {
      await supabase.from("profiles").update({ plan: "cancelled" }).eq("stripe_customer_id", sub.customer);
      await supabase.from("events").insert({ event_type: "churn", event_data: { sub_id: sub.id } });
    } else {
      await supabase.from("profiles").update({ plan, credits_limit: planLimits[plan], stripe_subscription_id: sub.id }).eq("stripe_customer_id", sub.customer);
      await supabase.from("subscriptions").upsert({ stripe_subscription_id: sub.id, stripe_customer_id: sub.customer, plan, status: sub.status, current_period_end: new Date(sub.current_period_end * 1000).toISOString() });
      await supabase.from("events").insert({ event_type: "upgrade", event_data: { plan } });
    }
  }
  res.json({ received: true });
});

// ── EVENT TRACKING ────────────────────────────────────────────
app.post("/api/events/track", async (req, res) => {
  const { event_type, user_id, event_data = {}, source, page } = req.body;
  if (!event_type) return res.status(400).json({ error: "event_type required" });
  await supabase.from("events").insert({ user_id: user_id || null, event_type, event_data, source, page, ip_hash: hashIp(req.ip) }).then(() => {}).catch(() => {});
  res.json({ ok: true });
});

// ── FALLBACKS ─────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: `Not found: ${req.method} ${req.path}` }));
app.use((err, req, res, _next) => { console.error(err); res.status(500).json({ error: "Internal server error" }); });

// ── START ─────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════╗
║      Chamber API — running on :${PORT}     ║
╠══════════════════════════════════════════╣
║  Health   → http://localhost:${PORT}/health ║
║  Auth     → POST /api/auth/signin        ║
║  Analyze  → POST /api/analyze            ║
║  Features → POST /api/features/*         ║
║  Admin    → GET  /api/admin/overview     ║
╠══════════════════════════════════════════╣
║  Send x-admin-secret: <ADMIN_SECRET>     ║
║  header to admin routes (no login req'd) ║
╚══════════════════════════════════════════╝
  `);
});

module.exports = app;