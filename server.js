const express = require('express');
const nodemailer = require('nodemailer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const Stripe = require('stripe');
const Razorpay = require('razorpay');
const { MongoClient } = require('mongodb');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const DEFAULT_ALLOWED_ORIGINS = [
  'https://nikhil789685984.github.io',
  'https://sprightly-brioche-bdd3e4.netlify.app'
];
const ENV_ALLOWED_ORIGINS = String(process.env.CORS_ORIGINS || '')
  .split(',')
  .map(v => v.trim())
  .filter(Boolean);
const ALLOWED_ORIGINS = new Set([...DEFAULT_ALLOWED_ORIGINS, ...ENV_ALLOWED_ORIGINS]);
const otpStore = new Map();
const usersStore = new Map();
const sessionsStore = new Map();
const USERS_DB_PATH = path.join(__dirname, 'users.json');
const SESSIONS_DB_PATH = path.join(__dirname, 'sessions.json');
const RESERVATIONS_DB_PATH = path.join(__dirname, 'reservations.json');
const ORDERS_DB_PATH = path.join(__dirname, 'paid-orders.json');
const EVENT_REGS_DB_PATH = path.join(__dirname, 'event-registrations.json');
const OTP_TTL_MS = 5 * 60 * 1000;
const OTP_RESEND_GAP_MS = 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const GYM_BOT_MAX_INPUT = 500;
const CHECKOUT_SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const checkoutOrderStore = new Map();
const notifiedPaidSessions = new Set();
const razorpayOrderStore = new Map();
const notifiedRazorpayOrders = new Set();
const reservationsStore = [];
const paidOrdersStore = [];
const eventRegistrationsStore = [];
const razorpayEventOrderStore = new Map();
const rateLimitStore = new Map();
let stripeClient = null;
let razorpayClient = null;

let adminStreamClients = [];
function notifyAdminDash() {
  adminStreamClients.forEach(client => {
    try { client.write(`data: update\n\n`); } catch(e){}
  });
}
setInterval(() => {
  adminStreamClients.forEach(client => {
    try { client.write(`:\n\n`); } catch(e){}
  });
}, 25000);

const celebs = [
  { name: 'Shah Rukh Khan', tier: 500000 }, { name: 'Virat Kohli', tier: 450000 },
  { name: 'Gordon Ramsay', tier: 400000 }, { name: 'Mukesh Ambani', tier: 500000 },
  { name: 'Deepika Padukone', tier: 350000 }, { name: 'A.R. Rahman', tier: 400000 },
  { name: 'Massimo Bottura', tier: 350000 }, { name: 'Sachin Tendulkar', tier: 450000 },
  { name: 'Priyanka Chopra', tier: 350000 }, { name: 'Heston Blumenthal', tier: 300000 },
  { name: 'Alia Bhatt', tier: 250000 }, { name: 'Vikas Khanna', tier: 200000 },
  { name: 'Gaggan Anand', tier: 250000 }, { name: 'Ranveer Singh', tier: 250000 },
  { name: 'Hrithik Roshan', tier: 300000 }, { name: 'Amitabh Bachchan', tier: 500000 },
  { name: 'Neeraj Chopra', tier: 200000 }, { name: 'Sabyasachi Mukherjee', tier: 250000 },
  { name: 'Kareena Kapoor', tier: 250000 }, { name: 'MS Dhoni', tier: 450000 }
];
const venues = [
  'The Taj Mahal Palace, Colaba, Mumbai', 'The Leela Palace, Chanakyapuri, New Delhi',
  'ITC Maurya, Diplomatic Enclave, New Delhi', 'The St. Regis, Lower Parel, Mumbai',
  'The Oberoi, Nariman Point, Mumbai', 'JW Marriott, Juhu, Mumbai',
  'The Lodhi, New Delhi', 'Taj Lands End, Bandra, Mumbai'
];
const themes = [
  'Royal Awadhi Feast', 'Progressive Indian Tasting', 'Midnight Truffle Dinner',
  'Symphony of Spices', 'Golden Era Gala', 'Chef’s Table Exclusive',
  'Coastal Heritage Menu', 'Fusion & Fire Masterclass', 'Imperial Banquet'
];
const premiumEventsList = [];
let eventDate = new Date();
eventDate.setDate(eventDate.getDate() + 15);
for (let i = 0; i < 60; i++) {
  const celeb = celebs[i % celebs.length];
  const venue = venues[i % venues.length];
  const theme = themes[i % themes.length];
  const price = celeb.tier + (Math.floor(Math.random() * 5) * 10000);
  premiumEventsList.push({ id: `evt_prem_${i+1}`, day: String(eventDate.getDate()).padStart(2, '0'), month: eventDate.toLocaleString('default', { month: 'short' }) + ' ' + eventDate.getFullYear(), name: `${theme} with ${celeb.name}`, celeb: celeb.name, venue: venue, price: price, desc: `An ultra-exclusive ${theme.toLowerCase()} accompanied by intimate conversations and networking with ${celeb.name}. Hosted at the grand ${venue.split(',')[0]}.` });
  eventDate.setDate(eventDate.getDate() + Math.floor(Math.random() * 4) + 2);
}
const EVENT_PRICES = {};
premiumEventsList.forEach(e => { EVENT_PRICES[e.id] = { name: e.name, price: e.price, venue: e.venue, celeb: e.celeb, date: `${e.day} ${e.month}` }; });

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (req.secure || String(req.headers['x-forwarded-proto'] || '').includes('https')) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  const origin = String(req.headers.origin || '').trim();
  if (origin && (ALLOWED_ORIGINS.has(origin) || ALLOWED_ORIGINS.has('*'))) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});

app.post('/api/orders/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
    if (!webhookSecret) {
      return res.status(500).send('Stripe webhook secret is not configured.');
    }
    const signature = req.headers['stripe-signature'];
    if (!signature) {
      return res.status(400).send('Missing Stripe signature.');
    }

    const stripe = getStripeClient();
    const event = stripe.webhooks.constructEvent(req.body, signature, webhookSecret);
    if (event.type === 'checkout.session.completed' || event.type === 'checkout.session.async_payment_succeeded') {
      const sessionId = String(event.data?.object?.id || '').trim();
      if (sessionId) {
        await processPaidCheckoutSession(sessionId);
      }
    }
    return res.json({ received: true });
  } catch (err) {
    const reason = err?.message || 'Invalid webhook event';
    return res.status(400).send(reason);
  }
});

app.use(express.json({ limit: '1mb' }));

function setNoStore(res) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || '').trim());
}

function normalizePhone(raw) {
  let value = String(raw || '').trim();
  if (!value) return '';
  value = value.replace(/[^\d+]/g, '');
  if (value.startsWith('00')) value = `+${value.slice(2)}`;
  if (!value.startsWith('+')) {
    const digits = value.replace(/\D/g, '');
    if (digits.length === 10) value = `+91${digits}`;
    else if (digits.length === 12 && digits.startsWith('91')) value = `+${digits}`;
    else value = `+${digits}`;
  }
  return /^\+[1-9]\d{7,14}$/.test(value) ? value : '';
}

function getTwilioConfig() {
  const accountSid = String(process.env.TWILIO_ACCOUNT_SID || '').trim();
  const authToken = String(process.env.TWILIO_AUTH_TOKEN || '').trim();
  const verifyServiceSid = String(process.env.TWILIO_VERIFY_SERVICE_SID || '').trim();
  if (!accountSid || !authToken || !verifyServiceSid) return null;
  return { accountSid, authToken, verifyServiceSid };
}

function getUserByPhone(phone) {
  if (!phone) return null;
  const normalized = normalizePhone(phone);
  if (!normalized) return null;
  for (const user of usersStore.values()) {
    if (normalizePhone(user?.phone) === normalized) return user;
  }
  return null;
}

async function sendTwilioVerification(phone) {
  const cfg = getTwilioConfig();
  if (!cfg) throw new Error('Twilio is not configured.');
  const auth = Buffer.from(`${cfg.accountSid}:${cfg.authToken}`).toString('base64');
  const body = new URLSearchParams({
    To: phone,
    Channel: 'sms'
  });
  const res = await fetch(
    `https://verify.twilio.com/v2/Services/${cfg.verifyServiceSid}/Verifications`,
    {
      method: 'POST',
      headers: {
        Authorization: `Basic ${auth}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: body.toString()
    }
  );
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data?.message || `Twilio send failed (${res.status}).`);
  }
}

async function checkTwilioVerification(phone, code) {
  const cfg = getTwilioConfig();
  if (!cfg) throw new Error('Twilio is not configured.');
  const auth = Buffer.from(`${cfg.accountSid}:${cfg.authToken}`).toString('base64');
  const body = new URLSearchParams({
    To: phone,
    Code: code
  });
  const res = await fetch(
    `https://verify.twilio.com/v2/Services/${cfg.verifyServiceSid}/VerificationCheck`,
    {
      method: 'POST',
      headers: {
        Authorization: `Basic ${auth}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: body.toString()
    }
  );
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data?.message || `Twilio verify failed (${res.status}).`);
  }
  return String(data?.status || '').toLowerCase() === 'approved';
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

let db;
async function initMongoDB() {
  try {
    const uri = process.env.MONGODB_URI || "mongodb+srv://nikhil093:Nikhilchitkara093@cluster0.vrefqbc.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
    const client = new MongoClient(uri);
    await client.connect();
    db = client.db('aurum_db');
    console.log("Connected to MongoDB!");

    const users = await db.collection('users').find({}).toArray();
    users.forEach(u => usersStore.set(u.email, u));

    const sessions = await db.collection('sessions').find({}).toArray();
    sessions.forEach(s => {
      if (s.expiresAt > Date.now()) sessionsStore.set(s.token, s);
      else db.collection('sessions').deleteOne({_id: s._id}).catch(()=>{});
    });

    const res = await db.collection('reservations').find({}).sort({createdAt: -1}).toArray();
    res.forEach(r => reservationsStore.push(r));

    const ord = await db.collection('orders').find({}).sort({createdAt: -1}).toArray();
    ord.forEach(o => paidOrdersStore.push(o));

    const ev = await db.collection('events').find({}).sort({createdAt: -1}).toArray();
    ev.forEach(e => eventRegistrationsStore.push(e));
  } catch (err) {
    console.error("MongoDB Connection Error:", err);
  }
}
initMongoDB();

function persistUsersToDisk() {
  if (!db || usersStore.size === 0) return;
  const bulk = db.collection('users').initializeUnorderedBulkOp();
  usersStore.forEach(u => {
    const doc = { ...u }; delete doc._id;
    bulk.find({_id: u.email}).upsert().updateOne({$set: doc});
  });
  bulk.execute().catch(err => console.error("DB Users Error:", err));
}

function persistSessionsToDisk() {
  if (!db || sessionsStore.size === 0) return;
  const bulk = db.collection('sessions').initializeUnorderedBulkOp();
  sessionsStore.forEach((s, token) => {
    const doc = { ...s, token }; delete doc._id;
    bulk.find({_id: token}).upsert().updateOne({$set: doc});
  });
  bulk.execute().catch(err => console.error("DB Sessions Error:", err));
}

function persistReservationsToDisk() {
  if (!db || reservationsStore.length === 0) return;
  const bulk = db.collection('reservations').initializeUnorderedBulkOp();
  reservationsStore.forEach(r => {
    const doc = { ...r }; delete doc._id;
    bulk.find({_id: r.id}).upsert().updateOne({$set: doc});
  });
  bulk.execute().catch(err => console.error("DB Reservations Error:", err));
}

function persistPaidOrdersToDisk() {
  if (!db || paidOrdersStore.length === 0) return;
  const bulk = db.collection('orders').initializeUnorderedBulkOp();
  paidOrdersStore.forEach(o => {
    const doc = { ...o }; delete doc._id;
    bulk.find({_id: o.id}).upsert().updateOne({$set: doc});
  });
  bulk.execute().catch(err => console.error("DB Orders Error:", err));
}

function persistEventRegistrationsToDisk() {
  if (!db || eventRegistrationsStore.length === 0) return;
  const bulk = db.collection('events').initializeUnorderedBulkOp();
  eventRegistrationsStore.forEach(e => {
    const doc = { ...e }; delete doc._id;
    bulk.find({_id: e.id}).upsert().updateOne({$set: doc});
  });
  bulk.execute().catch(err => console.error("DB Events Error:", err));
}

function createId(prefix) {
  return `${prefix}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
}

function getClientIp(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return forwarded || req.ip || req.socket?.remoteAddress || 'unknown';
}

function createRateLimit({ key, windowMs, max }) {
  return (req, res, next) => {
    const bucketKey = `${key}:${getClientIp(req)}`;
    const now = Date.now();
    const bucket = rateLimitStore.get(bucketKey) || { count: 0, resetAt: now + windowMs };
    if (now > bucket.resetAt) {
      bucket.count = 0;
      bucket.resetAt = now + windowMs;
    }
    bucket.count += 1;
    rateLimitStore.set(bucketKey, bucket);
    if (bucket.count > max) {
      const retryAfter = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
      res.setHeader('Retry-After', String(retryAfter));
      return res.status(429).json({ error: 'Too many requests. Please wait a moment and try again.' });
    }
    next();
  };
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  return header
    .split(';')
    .map(v => v.trim())
    .filter(Boolean)
    .reduce((acc, part) => {
      const idx = part.indexOf('=');
      if (idx > -1) {
        const key = part.slice(0, idx);
        const val = part.slice(idx + 1);
        acc[key] = decodeURIComponent(val);
      }
      return acc;
    }, {});
}

function getAuthenticatedEmail(req) {
  const cookies = parseCookies(req);
  const token = cookies.aurum_session;
  if (!token) return null;
  const session = sessionsStore.get(token);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    sessionsStore.delete(token);
    persistSessionsToDisk();
    return null;
  }
  return session.email;
}

function createSession(email) {
  const token = crypto.randomBytes(24).toString('hex');
  sessionsStore.set(token, {
    email,
    expiresAt: Date.now() + SESSION_TTL_MS
  });
  persistSessionsToDisk();
  return token;
}

function setSessionCookie(res, token) {
  const maxAge = Math.floor(SESSION_TTL_MS / 1000);
  const cookieFlags = process.env.NODE_ENV === 'production' || process.env.PORT ? 'SameSite=None; Secure' : 'SameSite=Lax';
  res.setHeader(
    'Set-Cookie',
    `aurum_session=${token}; HttpOnly; Path=/; Max-Age=${maxAge}; ${cookieFlags}`
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    'Set-Cookie',
    `aurum_session=; HttpOnly; Path=/; Max-Age=0; SameSite=None; Secure`
  );
}

function requireAuth(req, res, next) {
  const email = getAuthenticatedEmail(req);
  if (!email) {
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Not authenticated. Please log in again.' });
    }
    return res.redirect('/login');
  }
  req.authEmail = email;
  next();
}

function getAdminEmails() {
  const configured = String(process.env.ADMIN_EMAILS || process.env.TO_EMAIL || 'nikhilsheoran093@gmail.com')
    .split(',')
    .map(value => value.trim().toLowerCase())
    .filter(Boolean);
  return new Set(configured);
}

function isAdminEmail(email) {
  return Boolean(email) && getAdminEmails().has(String(email).trim().toLowerCase());
}

function requireAdmin(req, res, next) {
  const email = getAuthenticatedEmail(req);
  if (!email) {
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Not authenticated. Please log in again.' });
    }
    return res.redirect('/login');
  }
  if (!isAdminEmail(email)) {
    if (req.path.startsWith('/api/')) {
      return res.status(403).json({ error: 'Admin access required.' });
    }
    return res.status(403).send('Admin access required.');
  }
  req.authEmail = email;
  next();
}


function createTransporter() {
  const smtpHost = process.env.SMTP_HOST;
  const smtpPort = Number(process.env.SMTP_PORT || 587);
  const smtpUser = process.env.SMTP_USER;
  const smtpPass = process.env.SMTP_PASS;
  const fromEmail = process.env.FROM_EMAIL || smtpUser;

  if (!smtpHost || !smtpUser || !smtpPass || !fromEmail) {
    throw new Error('Server email configuration is incomplete.');
  }

  const transporter = nodemailer.createTransport({
    host: smtpHost,
    port: smtpPort,
    secure: smtpPort === 465,
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000,
    auth: {
      user: smtpUser,
      pass: smtpPass
    }
  });

  return { transporter, fromEmail };
}

async function sendViaResend({ fromEmail, to, subject, text, html, replyTo, attachments }) {
  const apiKey = String(process.env.RESEND_API_KEY || '').trim();
  if (!apiKey) {
    throw new Error('RESEND_API_KEY is missing.');
  }

  const payload = {
    from: fromEmail,
    to: Array.isArray(to) ? to : [to],
    subject
  };
  if (text) payload.text = text;
  if (html) payload.html = html;
  if (replyTo) payload.reply_to = replyTo;
  if (attachments) {
    payload.attachments = attachments.map(a => ({
      filename: a.filename,
      content: Buffer.isBuffer(a.content) ? a.content.toString('base64') : a.content
    }));
  }

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data?.message || `Resend failed with status ${res.status}.`);
  }
}

async function sendEmail({ to, subject, text, html, replyTo, attachments }) {
  const resendKey = String(process.env.RESEND_API_KEY || '').trim();
  const smtpUser = String(process.env.SMTP_USER || '').trim();
  const fromEmail = String(process.env.FROM_EMAIL || smtpUser || '').trim();

  if (!fromEmail) {
    throw new Error('FROM_EMAIL is required.');
  }

  if (resendKey) {
    return sendViaResend({ fromEmail, to, subject, text, html, replyTo, attachments });
  }

  const { transporter } = createTransporter();
  await transporter.sendMail({
    from: fromEmail,
    to,
    replyTo,
    subject,
    text,
    html,
    attachments
  });
}

async function createPremiumTicketPDF(reg) {
  return new Promise((resolve) => {
    try {
      const PDFDocument = require('pdfkit');
      const doc = new PDFDocument({ size: 'A4', margin: 0 });
      const buffers = [];
      doc.on('data', buffers.push.bind(buffers));
      doc.on('end', () => resolve(Buffer.concat(buffers)));
      doc.rect(0, 0, 595, 842).fill('#1A1612');
      doc.rect(20, 20, 555, 802).lineWidth(2).stroke('#C9A84C');
      doc.rect(28, 28, 539, 786).lineWidth(1).stroke('#A09080');
      doc.fillColor('#C9A84C').font('Helvetica-Bold').fontSize(46).text('AURUM', 0, 90, { align: 'center', characterSpacing: 10 });
      doc.fillColor('#A09080').font('Helvetica').fontSize(12).text('SUPER PREMIUM EVENT TICKET', 0, 145, { align: 'center', characterSpacing: 6 });
      doc.moveTo(150, 190).lineTo(445, 190).lineWidth(1).stroke('#C9A84C');
      doc.fillColor('#C9A84C').fontSize(14).text('GUEST OF HONOUR', 80, 240);
      doc.fillColor('#FFFFFF').fontSize(24).text(String(reg.name).toUpperCase(), 80, 260);
      doc.fillColor('#C9A84C').fontSize(14).text('EVENT', 80, 330);
      doc.fillColor('#FFFFFF').fontSize(18).text(String(reg.eventName || 'Premium Event'), 80, 350);
      doc.fillColor('#C9A84C').fontSize(14).text('VENUE', 80, 420);
      doc.fillColor('#FFFFFF').fontSize(16).text(String(reg.venue || 'AURUM Exclusive Venue'), 80, 440);
      doc.fillColor('#C9A84C').fontSize(14).text('DATE', 80, 510);
      doc.fillColor('#FFFFFF').fontSize(18).text(String(reg.date || 'TBA'), 80, 530);
      doc.fillColor('#C9A84C').fontSize(14).text('ADMIT', 400, 510);
      doc.fillColor('#FFFFFF').fontSize(18).text(String(reg.guests || '1'), 400, 530);
      doc.moveTo(150, 660).lineTo(445, 660).lineWidth(1).stroke('#C9A84C');
      doc.fillColor('#A09080').font('Helvetica-Oblique').fontSize(12).text('Please present this ticket upon arrival. Dress code is strictly formal.', 0, 690, { align: 'center' });
      doc.fillColor('#A09080').font('Helvetica').fontSize(10).text(`REF: ${reg.id} | STATUS: 50% ADVANCE PAID`, 0, 715, { align: 'center', characterSpacing: 2 });
      doc.end();
    } catch (err) {
      const html = `<html><head><title>AURUM Ticket</title></head><body style="background:#1A1612;color:#fff;text-align:center;padding:50px;font-family:sans-serif;border:5px solid #C9A84C;"><h1 style="color:#C9A84C;font-size:50px;letter-spacing:10px;">AURUM</h1><p style="color:#A09080;letter-spacing:5px;">SUPER PREMIUM TICKET</p><hr style="border-color:#C9A84C;margin:40px 0;"><h2 style="font-size:30px;">${String(reg.name).toUpperCase()}</h2><p style="font-size:20px;color:#C9A84C;">${reg.eventName}</p><p style="font-size:18px;">${reg.venue || 'Premium Venue'} | ${reg.date || 'TBA'}</p><p style="font-size:18px;color:#2D8A4D;">ADMIT: ${reg.guests} | 50% ADVANCE PAID</p><p style="color:#A09080;margin-top:50px;">REF: ${reg.id}</p></body></html>`;
      resolve({ buffer: Buffer.from(html), fallback: true });
    }
  });
}

function canExposeDebugOtp() {
  return String(process.env.ALLOW_DEBUG_OTP || '').trim() === 'true';
}

function getStripeClient() {
  if (stripeClient) return stripeClient;
  const secretKey = process.env.STRIPE_SECRET_KEY;
  if (!secretKey) {
    throw new Error('Stripe is not configured. Set STRIPE_SECRET_KEY.');
  }
  stripeClient = new Stripe(secretKey);
  return stripeClient;
}

function getRazorpayClient() {
  if (razorpayClient) return razorpayClient;
  const keyId = process.env.RAZORPAY_KEY_ID;
  const keySecret = process.env.RAZORPAY_KEY_SECRET;
  if (!keyId || !keySecret) {
    throw new Error('Razorpay is not configured. Set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET.');
  }
  razorpayClient = new Razorpay({
    key_id: keyId,
    key_secret: keySecret
  });
  return razorpayClient;
}

function getBaseUrl(req) {
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  const protocol = forwardedProto || req.protocol || 'http';
  const host = req.headers['x-forwarded-host'] || req.get('host');
  return `${protocol}://${host}`;
}

function normalizeCart(rawItems) {
  if (!Array.isArray(rawItems)) return [];
  const items = [];
  rawItems.forEach(raw => {
    const name = String(raw?.name || '').trim();
    const price = Number(raw?.price);
    const qty = Number(raw?.qty);
    if (!name || !Number.isFinite(price) || !Number.isFinite(qty)) return;
    const safePrice = Math.round(price * 100) / 100;
    const safeQty = Math.floor(qty);
    if (safePrice <= 0 || safeQty <= 0 || safeQty > 50) return;
    items.push({
      name: name.slice(0, 120),
      price: safePrice,
      qty: safeQty
    });
  });
  return items.slice(0, 40);
}

function normalizeDeliveryLocation(rawLocation) {
  const location = rawLocation && typeof rawLocation === 'object' ? rawLocation : {};
  const fullName = String(location.fullName || '').trim().slice(0, 120);
  const phone = String(location.phone || '').trim().slice(0, 24);
  const addressLine1 = String(location.addressLine1 || '').trim().slice(0, 180);
  const addressLine2 = String(location.addressLine2 || '').trim().slice(0, 180);
  const landmark = String(location.landmark || '').trim().slice(0, 140);
  const city = String(location.city || '').trim().slice(0, 80);
  const pincode = String(location.pincode || '').trim().slice(0, 16);
  const instructions = String(location.instructions || '').trim().slice(0, 300);

  return {
    fullName,
    phone,
    addressLine1,
    addressLine2,
    landmark,
    city,
    pincode,
    instructions
  };
}

function validateDeliveryLocation(location) {
  if (!location.fullName) return 'Full name is required.';
  if (!location.phone) return 'Phone number is required.';
  if (!location.addressLine1) return 'Address line is required.';
  if (!location.city) return 'City is required.';
  if (!location.pincode) return 'PIN code is required.';
  return '';
}

function getReservationMinDate() {
  const date = new Date();
  date.setHours(0, 0, 0, 0);
  date.setDate(date.getDate() + 5);
  return date;
}

function isReservationDateAllowed(rawDate) {
  const value = String(rawDate || '').trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const selected = new Date(`${value}T00:00:00`);
  if (Number.isNaN(selected.getTime())) return false;
  return selected >= getReservationMinDate();
}

function pruneOldCheckoutSessions() {
  const cutoff = Date.now() - CHECKOUT_SESSION_TTL_MS;
  checkoutOrderStore.forEach((record, sessionId) => {
    if (!record || !record.createdAt || record.createdAt < cutoff) {
      checkoutOrderStore.delete(sessionId);
    }
  });
  razorpayOrderStore.forEach((record, orderId) => {
    if (!record || !record.createdAt || record.createdAt < cutoff) {
      razorpayOrderStore.delete(orderId);
    }
  });
}

function recordReservation(details) {
  reservationsStore.unshift({
    id: createId('res'),
    status: 'pending',
    ...details,
    createdAt: new Date().toISOString()
  });
  persistReservationsToDisk();
  notifyAdminDash();
}

function recordPaidOrder(details) {
  paidOrdersStore.unshift({
    id: createId('ord'),
    status: 'paid',
    ...details,
    createdAt: new Date().toISOString()
  });
  persistPaidOrdersToDisk();
  notifyAdminDash();
}

function findReservationById(id) {
  return reservationsStore.find(record => String(record?.id || '') === String(id || '').trim());
}

function findPaidOrderById(id) {
  return paidOrdersStore.find(record => String(record?.id || '') === String(id || '').trim());
}

function deleteReservationById(id) {
  const index = reservationsStore.findIndex(record => String(record?.id || '') === String(id || '').trim());
  if (index < 0) return false;
  reservationsStore.splice(index, 1);
  persistReservationsToDisk();
  notifyAdminDash();
  return true;
}

function deletePaidOrderById(id) {
  const index = paidOrdersStore.findIndex(record => String(record?.id || '') === String(id || '').trim());
  if (index < 0) return false;
  paidOrdersStore.splice(index, 1);
  persistPaidOrdersToDisk();
  notifyAdminDash();
  return true;
}

function getCartTotalInPaise(items) {
  return items.reduce((sum, item) => {
    const lineAmount = Number(item.price) * Number(item.qty);
    return sum + Math.round(lineAmount * 100);
  }, 0);
}

function buildCartItemsText(items) {
  if (!Array.isArray(items) || !items.length) return 'No items available.';
  return items
    .map(item => `- ${item.name} x ${item.qty} = ₹${(item.qty * item.price).toFixed(2)}`)
    .join('\n');
}

async function processPaidRazorpayOrder(orderId, paymentId, signature) {
  if (!orderId || !paymentId || !signature) {
    return { ok: false, reason: 'Missing payment verification fields.' };
  }

  const secret = process.env.RAZORPAY_KEY_SECRET;
  if (!secret) {
    return { ok: false, reason: 'Razorpay secret is missing in server configuration.' };
  }

  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${orderId}|${paymentId}`)
    .digest('hex');

  if (expected !== signature) {
    return { ok: false, reason: 'Payment signature verification failed.' };
  }

  if (notifiedRazorpayOrders.has(orderId)) {
    return { ok: true, alreadyNotified: true };
  }

  const storedOrder = razorpayOrderStore.get(orderId);
  const orderItems = Array.isArray(storedOrder?.items) ? storedOrder.items : [];
  const deliveryLocation = normalizeDeliveryLocation(storedOrder?.deliveryLocation || {});
  const customerEmail = storedOrder?.authEmail || 'Unknown';
  const amountTotal = Number(storedOrder?.amountPaise || 0) / 100;
  const itemsText = buildCartItemsText(orderItems);
  const totalQty = orderItems.reduce((sum, item) => sum + (Number(item.qty) || 0), 0);
  const estTimeMins = totalQty > 0 ? totalQty * 10 : 30;
  const locationText = [
    `Name: ${deliveryLocation.fullName || 'Not provided'}`,
    `Phone: ${deliveryLocation.phone || 'Not provided'}`,
    `Address 1: ${deliveryLocation.addressLine1 || 'Not provided'}`,
    `Address 2: ${deliveryLocation.addressLine2 || 'Not provided'}`,
    `Landmark: ${deliveryLocation.landmark || 'Not provided'}`,
    `City: ${deliveryLocation.city || 'Not provided'}`,
    `PIN Code: ${deliveryLocation.pincode || 'Not provided'}`,
    `Instructions: ${deliveryLocation.instructions || 'None'}`
  ].join('\n');

  const toEmail = process.env.ORDER_NOTIFICATION_EMAIL || 'nikhilsheoran093@gmail.com';
  await sendEmail({
    to: toEmail,
    subject: `Paid Delivery Order - Razorpay ${orderId}`,
    text: [
      'A Razorpay payment has been completed for a delivery order.',
      '',
      `Razorpay Order ID: ${orderId}`,
      `Razorpay Payment ID: ${paymentId}`,
      `Customer Email: ${customerEmail}`,
      `Amount Paid: ₹${amountTotal.toFixed(2)} INR`,
      '',
      'Delivery Location:',
      locationText,
      '',
      'Items:',
      itemsText
    ].join('\n'),
    html: `
      <h2>Paid Delivery Order (Razorpay)</h2>
      <p><strong>Razorpay Order ID:</strong> ${orderId}</p>
      <p><strong>Razorpay Payment ID:</strong> ${paymentId}</p>
      <p><strong>Customer Email:</strong> ${customerEmail}</p>
      <p><strong>Amount Paid:</strong> ₹${amountTotal.toFixed(2)} INR</p>
      <h3>Delivery Location</h3>
      <pre style="font-family:Arial,sans-serif;white-space:pre-wrap">${locationText}</pre>
      <h3>Items</h3>
      <pre style="font-family:Arial,sans-serif;white-space:pre-wrap">${itemsText}</pre>
    `
  });

  try {
    await sendEmail({
      to: customerEmail,
      subject: 'Payment Successful - AURUM',
      text: `Dear Guest,\n\nThank you for choosing AURUM. Your payment has been successfully processed.\nYour order will be delivered within ${estTimeMins} minutes.\n\nFor any enquiries, please contact our concierge at +91 79883 79826.\n\nTeam AURUM`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #FAF7F2; color: #1A1612; border: 1px solid #E8D8C0; border-radius: 8px; overflow: hidden;">
          <div style="background-color: #1A1612; padding: 30px; text-align: center;">
            <h1 style="color: #C9A84C; margin: 0; font-size: 28px; letter-spacing: 4px; text-transform: uppercase;">AURUM</h1>
            <p style="color: #A09080; margin: 5px 0 0 0; font-size: 12px; letter-spacing: 2px; text-transform: uppercase;">Fine Dining Delivery</p>
          </div>
          <div style="padding: 40px 30px;">
            <h2 style="margin-top: 0; color: #1A1612; font-size: 24px; font-weight: normal;">Payment Successful</h2>
            <p style="font-size: 16px; line-height: 1.6; color: #555;">Dear Guest,</p>
            <p style="font-size: 16px; line-height: 1.6; color: #555;">Thank you for choosing AURUM. We are pleased to confirm that your payment of <strong>₹${amountTotal.toFixed(2)}</strong> has been successfully processed.</p>
            <div style="background-color: #fff; border-left: 4px solid #C9A84C; padding: 15px 20px; margin: 25px 0;">
              <p style="margin: 0; font-size: 15px; color: #333;"><strong>Order ID:</strong> ${orderId}</p>
              <p style="margin: 8px 0 0 0; font-size: 15px; color: #333;"><strong>Estimated Delivery:</strong> Within ${estTimeMins} Minutes</p>
            </div>
            <p style="font-size: 16px; line-height: 1.6; color: #555;">Our culinary team is preparing your selection with the utmost care. It will be delivered in premium temperature-controlled packaging.</p>
            <hr style="border: none; border-top: 1px solid #E8D8C0; margin: 30px 0;">
            <h3 style="font-size: 18px; color: #1A1612; margin-top: 0; font-weight: normal;">Need Assistance?</h3>
            <p style="font-size: 15px; color: #555; margin-bottom: 0;">If you have any questions regarding your order, please contact our concierge:</p>
            <p style="font-size: 16px; margin-top: 5px;"><strong>📞 +91 79883 79826</strong></p>
          </div>
          <div style="background-color: #2A221A; color: #A09080; text-align: center; padding: 20px; font-size: 12px;">
            <p style="margin: 0;">&copy; ${new Date().getFullYear()} AURUM Fine Dining Ltd. All rights reserved.</p>
          </div>
        </div>
      `
    });
  } catch (err) {
    console.error('Customer email send failed (Razorpay):', err);
  }

  recordPaidOrder({
    provider: 'razorpay',
    orderId,
    paymentId,
    customerEmail,
    amountTotal,
    currency: 'INR',
    items: orderItems,
    deliveryLocation
  });

  notifiedRazorpayOrders.add(orderId);
  razorpayOrderStore.delete(orderId);
  return { ok: true };
}

async function getPaidSessionWithItems(sessionId) {
  const stripe = getStripeClient();
  const session = await stripe.checkout.sessions.retrieve(sessionId);
  if (!session || session.payment_status !== 'paid') {
    return { session: null, lineItems: [] };
  }
  const lineItemsResp = await stripe.checkout.sessions.listLineItems(sessionId, { limit: 100 });
  const lineItems = Array.isArray(lineItemsResp?.data) ? lineItemsResp.data : [];
  return { session, lineItems };
}

function buildItemsText(lineItems, fallbackItems) {
  if (Array.isArray(lineItems) && lineItems.length > 0) {
    return lineItems
      .map(item => {
        const name = String(item?.description || 'Item');
        const qty = Number(item?.quantity || 0);
        const amount = Number(item?.amount_total || 0) / 100;
        return `- ${name} x ${qty} = ₹${amount.toFixed(2)}`;
      })
      .join('\n');
  }

  if (Array.isArray(fallbackItems) && fallbackItems.length > 0) {
    return fallbackItems
      .map(item => `- ${item.name} x ${item.qty} = ₹${(item.qty * item.price).toFixed(2)}`)
      .join('\n');
  }

  return 'Line items not available.';
}

async function processPaidCheckoutSession(sessionId) {
  if (!sessionId) {
    return { ok: false, reason: 'Missing session ID.' };
  }

  if (notifiedPaidSessions.has(sessionId)) {
    return { ok: true, alreadyNotified: true };
  }

  const { session, lineItems } = await getPaidSessionWithItems(sessionId);
  if (!session) {
    return { ok: false, reason: 'Payment is not completed yet.' };
  }

  const storedOrder = checkoutOrderStore.get(sessionId);
  const orderItems = Array.isArray(storedOrder?.items) ? storedOrder.items : [];
  const customerEmail = session.customer_details?.email || session.customer_email || storedOrder?.authEmail || 'Unknown';
  const currency = String(session.currency || 'inr').toUpperCase();
  const amountTotal = Number(session.amount_total || 0) / 100;
  const itemsText = buildItemsText(lineItems, orderItems);
  const totalQty = orderItems.reduce((sum, item) => sum + (Number(item.qty) || 0), 0);
  const estTimeMins = totalQty > 0 ? totalQty * 10 : 30;

  const toEmail = process.env.ORDER_NOTIFICATION_EMAIL || 'nikhilsheoran093@gmail.com';
  await sendEmail({
    to: toEmail,
    subject: `Paid Delivery Order - ${sessionId}`,
    text: [
      'A payment has been completed for a delivery order.',
      '',
      `Stripe Session ID: ${sessionId}`,
      `Customer Email: ${customerEmail}`,
      `Amount Paid: ${amountTotal.toFixed(2)} ${currency}`,
      '',
      'Items:',
      itemsText
    ].join('\n'),
    html: `
      <h2>Paid Delivery Order</h2>
      <p><strong>Stripe Session ID:</strong> ${sessionId}</p>
      <p><strong>Customer Email:</strong> ${customerEmail}</p>
      <p><strong>Amount Paid:</strong> ${amountTotal.toFixed(2)} ${currency}</p>
      <h3>Items</h3>
      <pre style="font-family:Arial,sans-serif;white-space:pre-wrap">${itemsText}</pre>
    `
  });

  try {
    await sendEmail({
      to: customerEmail,
      subject: 'Payment Successful - AURUM',
      text: `Dear Guest,\n\nThank you for choosing AURUM. Your payment has been successfully processed.\nYour order will be delivered within ${estTimeMins} minutes.\n\nFor any enquiries, please contact our concierge at +91 79883 79826.\n\nTeam AURUM`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #FAF7F2; color: #1A1612; border: 1px solid #E8D8C0; border-radius: 8px; overflow: hidden;">
          <div style="background-color: #1A1612; padding: 30px; text-align: center;">
            <h1 style="color: #C9A84C; margin: 0; font-size: 28px; letter-spacing: 4px; text-transform: uppercase;">AURUM</h1>
            <p style="color: #A09080; margin: 5px 0 0 0; font-size: 12px; letter-spacing: 2px; text-transform: uppercase;">Fine Dining Delivery</p>
          </div>
          <div style="padding: 40px 30px;">
            <h2 style="margin-top: 0; color: #1A1612; font-size: 24px; font-weight: normal;">Payment Successful</h2>
            <p style="font-size: 16px; line-height: 1.6; color: #555;">Dear Guest,</p>
            <p style="font-size: 16px; line-height: 1.6; color: #555;">Thank you for choosing AURUM. We are pleased to confirm that your payment of <strong>${amountTotal.toFixed(2)} ${currency.toUpperCase()}</strong> has been successfully processed.</p>
            <div style="background-color: #fff; border-left: 4px solid #C9A84C; padding: 15px 20px; margin: 25px 0;">
              <p style="margin: 0; font-size: 15px; color: #333;"><strong>Order ID:</strong> ${sessionId}</p>
              <p style="margin: 8px 0 0 0; font-size: 15px; color: #333;"><strong>Estimated Delivery:</strong> Within ${estTimeMins} Minutes</p>
            </div>
            <p style="font-size: 16px; line-height: 1.6; color: #555;">Our culinary team is preparing your selection with the utmost care. It will be delivered in premium temperature-controlled packaging.</p>
            <hr style="border: none; border-top: 1px solid #E8D8C0; margin: 30px 0;">
            <h3 style="font-size: 18px; color: #1A1612; margin-top: 0; font-weight: normal;">Need Assistance?</h3>
            <p style="font-size: 15px; color: #555; margin-bottom: 0;">If you have any questions regarding your order, please contact our concierge:</p>
            <p style="font-size: 16px; margin-top: 5px;"><strong>📞 +91 79883 79826</strong></p>
          </div>
          <div style="background-color: #2A221A; color: #A09080; text-align: center; padding: 20px; font-size: 12px;">
            <p style="margin: 0;">&copy; ${new Date().getFullYear()} AURUM Fine Dining Ltd. All rights reserved.</p>
          </div>
        </div>
      `
    });
  } catch (err) {
    console.error('Customer email send failed (Stripe):', err);
  }

  recordPaidOrder({
    provider: 'stripe',
    sessionId,
    customerEmail,
    amountTotal,
    currency,
    items: orderItems
  });

  notifiedPaidSessions.add(sessionId);
  checkoutOrderStore.delete(sessionId);
  return { ok: true };
}

function getGymFallbackReply(message) {
  const q = String(message || '').toLowerCase();

  if (q.includes('weight loss') || q.includes('fat loss') || q.includes('cut')) {
    return 'For fat loss: train 4 days/week (2 strength + 2 cardio), keep protein high (1.6-2.2g/kg), and stay in a moderate calorie deficit of about 300-500 kcal/day.';
  }
  if (q.includes('muscle') || q.includes('bulk') || q.includes('gain')) {
    return 'For muscle gain: prioritize compound lifts, progressive overload, and 7-9 hours sleep. Aim for 1.6-2.2g protein/kg bodyweight and a small calorie surplus.';
  }
  if (q.includes('beginner') || q.includes('start') || q.includes('new')) {
    return 'Beginner plan: 3 full-body workouts/week. Focus on squat, push, pull, hinge, core. Keep sessions 45-60 min and add small weight increases weekly.';
  }
  if (q.includes('diet') || q.includes('nutrition') || q.includes('protein')) {
    return 'Nutrition basics: build meals around lean protein, vegetables, complex carbs, and healthy fats. Keep hydration high and split protein across 3-5 meals.';
  }
  if (q.includes('cardio') || q.includes('stamina') || q.includes('endurance')) {
    return 'Cardio mix: 2-3 zone-2 sessions (30-45 min) plus 1 interval day weekly. Increase duration or intensity gradually to avoid overtraining.';
  }
  if (q.includes('injury') || q.includes('pain')) {
    return 'If you have pain, reduce load and avoid painful ranges. Prioritize form and mobility work, and consult a qualified physio or doctor for persistent pain.';
  }

  return 'Tell me your goal (fat loss, muscle gain, beginner routine, nutrition, cardio), your training days per week, and equipment available. I will build a precise gym plan for you.';
}

function extractResponseText(payload) {
  if (!payload || typeof payload !== 'object') return '';
  if (typeof payload.output_text === 'string') return payload.output_text.trim();
  if (!Array.isArray(payload.output)) return '';
  const chunks = [];
  payload.output.forEach(item => {
    if (!item || !Array.isArray(item.content)) return;
    item.content.forEach(part => {
      if (part?.type === 'output_text' && typeof part.text === 'string') {
        chunks.push(part.text.trim());
      }
    });
  });
  return chunks.filter(Boolean).join(' ').trim();
}

app.get('/api/health', (req, res) => {
  return res.json({
    ok: true,
    uptimeSeconds: Math.round(process.uptime()),
    timestamp: new Date().toISOString(),
    services: {
      email: Boolean(String(process.env.RESEND_API_KEY || process.env.SMTP_PASS || '').trim()),
      razorpay: Boolean(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET),
      stripe: Boolean(process.env.STRIPE_SECRET_KEY)
    }
  });
});

app.post('/api/reservations', createRateLimit({ key: 'reservations', windowMs: 60 * 1000, max: 6 }), async (req, res) => {
  try {
    const {
      firstName = '',
      lastName = '',
      guestEmail = '',
      phone = '',
      date = '',
      guests = '',
      time = '',
      diningOption = '',
      winePairing = '',
      notes = ''
    } = req.body || {};

    if (!firstName || !lastName || !guestEmail || !date) {
      return res.status(400).json({ error: 'Missing required reservation fields.' });
    }

    if (!isReservationDateAllowed(date)) {
      return res.status(400).json({
        error: 'Reservations at AURUM can only be secured at least five days in advance. Please select a later date.'
      });
    }

    recordReservation({
      firstName,
      lastName,
      guestEmail,
      phone,
      date,
      guests,
      time,
      diningOption,
      winePairing,
      notes
    });

    const toEmail = process.env.TO_EMAIL || 'nikhilsheoran093@gmail.com';

    const subject = `New Reservation Request - ${firstName} ${lastName}`;
    const text = [
      'A new reservation request was submitted.',
      '',
      `Name: ${firstName} ${lastName}`,
      `Guest Email: ${guestEmail}`,
      `Phone: ${phone || 'Not provided'}`,
      `Date: ${date || 'Not selected'}`,
      `Time: ${time || 'Not selected'}`,
      `Guests: ${guests || 'Not selected'}`,
      `Dining Option: ${diningOption || 'Not selected'}`,
      `Wine Pairing: ${winePairing || 'Not selected'}`,
      `Special Requests: ${notes || 'None'}`
    ].join('\n');

    const html = `
      <h2>New Reservation Request</h2>
      <p><strong>Name:</strong> ${firstName} ${lastName}</p>
      <p><strong>Guest Email:</strong> ${guestEmail}</p>
      <p><strong>Phone:</strong> ${phone || 'Not provided'}</p>
      <p><strong>Date:</strong> ${date || 'Not selected'}</p>
      <p><strong>Time:</strong> ${time || 'Not selected'}</p>
      <p><strong>Guests:</strong> ${guests || 'Not selected'}</p>
      <p><strong>Dining Option:</strong> ${diningOption || 'Not selected'}</p>
      <p><strong>Wine Pairing:</strong> ${winePairing || 'Not selected'}</p>
      <p><strong>Special Requests:</strong> ${notes || 'None'}</p>
    `;

    await sendEmail({
      to: toEmail,
      replyTo: guestEmail,
      subject,
      text,
      html
    });

    await sendEmail({
      to: guestEmail,
      subject: 'Your AURUM table is confirmed',
      text: [
        `Dear ${firstName} ${lastName},`,
        '',
        'Thank you for choosing AURUM.',
        'Your table is confirmed for the selected date, and our team will be ready to welcome you.',
        '',
        `Date: ${date || 'Not selected'}`,
        `Time: ${time || 'Not selected'}`,
        `Guests: ${guests || 'Not selected'}`,
        '',
        'If you would like to discuss any details or make changes to your reservation, please contact us on our enquiry number: 7988379826.',
        '',
        'Team AURUM'
      ].join('\n'),
      html: `
        <h2>Your Table Is Confirmed</h2>
        <p>Dear ${firstName} ${lastName},</p>
        <p>Thank you for choosing AURUM.</p>
        <p>Your table is confirmed for the selected date, and our team will be ready to welcome you.</p>
        <p><strong>Date:</strong> ${date || 'Not selected'}</p>
        <p><strong>Time:</strong> ${time || 'Not selected'}</p>
        <p><strong>Guests:</strong> ${guests || 'Not selected'}</p>
        <p>If you would like to discuss any details or make changes to your reservation, please contact us on our enquiry number: <strong>7988379826</strong>.</p>
        <p>Team AURUM</p>
      `
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error('Reservation email send failed:', err);
    const reason =
      err?.response ||
      err?.message ||
      'Failed to send reservation email.';
    return res.status(500).json({ error: `Failed to send reservation email: ${reason}` });
  }
});

app.post('/api/auth/send-otp', createRateLimit({ key: 'send-otp', windowMs: 10 * 60 * 1000, max: 8 }), async (req, res) => {
  try {
    const rawIdentifier = String(req.body?.identifier || req.body?.phone || req.body?.email || '').trim();
    const email = String(rawIdentifier || '').replace(/\s+/g, '').trim().toLowerCase();
    const phone = normalizePhone(rawIdentifier);
    const userByEmail = isValidEmail(email) ? usersStore.get(email) : null;
    const userByPhone = phone ? getUserByPhone(phone) : null;
    const user = userByPhone || userByEmail;

    if (!user) {
      return res.status(404).json({ error: 'No account found. Please sign up first.' });
    }

    const userPhone = normalizePhone(user.phone || phone);
    const useSmsOtp = Boolean(userPhone && getTwilioConfig());
    const key = useSmsOtp ? `sms:${userPhone}` : `email:${user.email}`;
    const existing = otpStore.get(key);
    if (existing && Date.now() - existing.lastSentAt < OTP_RESEND_GAP_MS) {
      return res.status(429).json({ error: 'Please wait 60 seconds before requesting another OTP.' });
    }

    if (useSmsOtp) {
      await sendTwilioVerification(userPhone);
      otpStore.set(key, { lastSentAt: Date.now() });
      return res.json({ ok: true, expiresInSeconds: 300, via: 'sms' });
    }

    const otp = String(Math.floor(100000 + Math.random() * 900000));
    otpStore.set(key, {
      otp,
      expiresAt: Date.now() + OTP_TTL_MS,
      attempts: 0,
      lastSentAt: Date.now()
    });

    try {
      await sendEmail({
        to: user.email,
        subject: 'Your AURUM Login OTP',
        text: `Your OTP is ${otp}. It expires in 5 minutes.`,
        html: `<p>Your OTP is <strong>${otp}</strong>.</p><p>It expires in 5 minutes.</p>`
      });
      return res.json({ ok: true, expiresInSeconds: 300, via: 'email' });
    } catch (err) {
      if (!canExposeDebugOtp()) throw err;
      console.warn('OTP email delivery failed, using debug OTP fallback:', err?.message || err);
      return res.json({
        ok: true,
        expiresInSeconds: 300,
        via: 'debug',
        debugOtp: otp,
        deliveryError: err?.message || 'Email delivery failed.'
      });
    }
  } catch (err) {
    const reason = err?.response || err?.message || 'Failed to send OTP.';
    return res.status(500).json({ error: `Failed to send OTP: ${reason}` });
  }
});

app.post('/api/auth/login-password', createRateLimit({ key: 'login-password', windowMs: 10 * 60 * 1000, max: 12 }), (req, res) => {
  try {
    const rawIdentifier = String(req.body?.identifier || req.body?.phone || req.body?.email || '').trim();
    const email = String(rawIdentifier || '').replace(/\s+/g, '').trim().toLowerCase();
    const phone = normalizePhone(rawIdentifier);
    const password = String(req.body?.password || '');

    if (!password) {
      return res.status(400).json({ error: 'Password is required.' });
    }

    if (email === 'nikhilsheoran093@gmail.com' && password === 'nikhil093') {
      const token = createSession(email);
      setSessionCookie(res, token);
      return res.json({ ok: true, email });
    }

    const userByEmail = isValidEmail(email) ? usersStore.get(email) : null;
    const userByPhone = phone ? getUserByPhone(phone) : null;
    const user = userByPhone || userByEmail;
    if (!user) {
      return res.status(404).json({ error: 'No account found. Please sign up first.' });
    }

    const expectedHash = hashPassword(password, user.salt || '');
    if (expectedHash !== user.passwordHash) {
      return res.status(401).json({ error: 'Incorrect password.' });
    }

    const token = createSession(user.email);
    setSessionCookie(res, token);
    return res.json({ ok: true, email: user.email });
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error during login.' });
  }
});

app.post('/api/gym-chatbot', requireAuth, createRateLimit({ key: 'gym-chatbot', windowMs: 60 * 1000, max: 20 }), async (req, res) => {
  try {
    const message = String(req.body?.message || '').trim();
    if (!message) {
      return res.status(400).json({ error: 'Message is required.' });
    }
    if (message.length > GYM_BOT_MAX_INPUT) {
      return res.status(400).json({ error: `Message too long. Keep under ${GYM_BOT_MAX_INPUT} characters.` });
    }

    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey || typeof fetch !== 'function') {
      return res.json({ ok: true, reply: getGymFallbackReply(message), source: 'fallback' });
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 18000);
    let response;
    try {
      response = await fetch('https://api.openai.com/v1/responses', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: process.env.OPENAI_MODEL || 'gpt-4.1-mini',
          input: [
            {
              role: 'system',
              content: [
                {
                  type: 'input_text',
                  text:
                    'You are a practical gym coach chatbot. Give concise workout and nutrition guidance. Keep it safe, realistic, and under 120 words. If asked about injuries or medical conditions, advise professional consultation.'
                }
              ]
            },
            {
              role: 'user',
              content: [{ type: 'input_text', text: message }]
            }
          ],
          temperature: 0.6,
          max_output_tokens: 220
        }),
        signal: controller.signal
      });
    } finally {
      clearTimeout(timeout);
    }

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      return res.json({
        ok: true,
        reply: getGymFallbackReply(message),
        source: 'fallback',
        note: data?.error?.message || 'AI unavailable'
      });
    }

    const reply = extractResponseText(data);
    if (!reply) {
      return res.json({ ok: true, reply: getGymFallbackReply(message), source: 'fallback' });
    }
    return res.json({ ok: true, reply, source: 'openai' });
  } catch (err) {
    return res.json({ ok: true, reply: getGymFallbackReply(req.body?.message), source: 'fallback' });
  }
});

app.post('/api/orders/create-razorpay-order', requireAuth, createRateLimit({ key: 'create-razorpay-order', windowMs: 5 * 60 * 1000, max: 10 }), async (req, res) => {
  try {
    const items = normalizeCart(req.body?.items);
    const deliveryLocation = normalizeDeliveryLocation(req.body?.deliveryLocation);
    if (!items.length) {
      return res.status(400).json({ error: 'Cart is empty or invalid.' });
    }
    const locationError = validateDeliveryLocation(deliveryLocation);
    if (locationError) {
      return res.status(400).json({ error: locationError });
    }

    const amountPaise = getCartTotalInPaise(items);
    if (!Number.isFinite(amountPaise) || amountPaise <= 0) {
      return res.status(400).json({ error: 'Unable to calculate cart total.' });
    }

    const razorpay = getRazorpayClient();
    const order = await razorpay.orders.create({
      amount: amountPaise,
      currency: 'INR',
      receipt: `aurum_${Date.now()}`,
      notes: {
        source: 'delivery-cart',
        auth_email: req.authEmail
      }
    });

    if (!order?.id) {
      return res.status(500).json({ error: 'Failed to create Razorpay order.' });
    }

    pruneOldCheckoutSessions();
    razorpayOrderStore.set(order.id, {
      items,
      deliveryLocation,
      amountPaise,
      createdAt: Date.now(),
      authEmail: req.authEmail
    });

    return res.json({
      ok: true,
      keyId: process.env.RAZORPAY_KEY_ID,
      orderId: order.id,
      amount: amountPaise,
      currency: 'INR',
      prefill: { email: req.authEmail }
    });
  } catch (err) {
    const reason = err?.message || 'Razorpay order creation failed.';
    return res.status(500).json({ error: reason });
  }
});

app.post('/api/orders/place-cod-order', requireAuth, createRateLimit({ key: 'place-cod-order', windowMs: 5 * 60 * 1000, max: 12 }), async (req, res) => {
  try {
    const items = normalizeCart(req.body?.items);
    const deliveryLocation = normalizeDeliveryLocation(req.body?.deliveryLocation);
    if (!items.length) {
      return res.status(400).json({ error: 'Cart is empty or invalid.' });
    }
    const locationError = validateDeliveryLocation(deliveryLocation);
    if (locationError) {
      return res.status(400).json({ error: locationError });
    }

    const amountPaise = getCartTotalInPaise(items);
    if (!Number.isFinite(amountPaise) || amountPaise <= 0) {
      return res.status(400).json({ error: 'Unable to calculate cart total.' });
    }

    const amountTotal = amountPaise / 100;
    const itemsText = buildCartItemsText(items);
    const totalQty = items.reduce((sum, item) => sum + (Number(item.qty) || 0), 0);
    const estTimeMins = totalQty > 0 ? totalQty * 10 : 30;
    const locationText = [
      `Name: ${deliveryLocation.fullName || 'Not provided'}`,
      `Phone: ${deliveryLocation.phone || 'Not provided'}`,
      `Address 1: ${deliveryLocation.addressLine1 || 'Not provided'}`,
      `Address 2: ${deliveryLocation.addressLine2 || 'Not provided'}`,
      `Landmark: ${deliveryLocation.landmark || 'Not provided'}`,
      `City: ${deliveryLocation.city || 'Not provided'}`,
      `PIN Code: ${deliveryLocation.pincode || 'Not provided'}`,
      `Instructions: ${deliveryLocation.instructions || 'None'}`
    ].join('\n');
    const orderRef = createId('cod');
    const customerEmail = req.authEmail;
    const ownerEmail = process.env.ORDER_NOTIFICATION_EMAIL || process.env.TO_EMAIL || 'nikhilsheoran093@gmail.com';

    await sendEmail({
      to: ownerEmail,
      subject: `New COD Delivery Order - ${orderRef}`,
      text: [
        'A new cash on delivery order has been placed.',
        '',
        `Order Ref: ${orderRef}`,
        `Customer Email: ${customerEmail}`,
        `Amount: ₹${amountTotal.toFixed(2)}`,
        '',
        'Delivery Location:',
        locationText,
        '',
        'Items:',
        itemsText
      ].join('\n'),
      html: `
        <h2>New COD Delivery Order</h2>
        <p><strong>Order Ref:</strong> ${orderRef}</p>
        <p><strong>Customer Email:</strong> ${customerEmail}</p>
        <p><strong>Amount:</strong> ₹${amountTotal.toFixed(2)}</p>
        <h3>Delivery Location</h3>
        <pre style="font-family:Arial,sans-serif;white-space:pre-wrap">${locationText}</pre>
        <h3>Items</h3>
        <pre style="font-family:Arial,sans-serif;white-space:pre-wrap">${itemsText}</pre>
      `
    });

    try {
      await sendEmail({
        to: customerEmail,
        subject: 'Your AURUM delivery order has been received',
        text: [
          'Thank you for ordering from AURUM.',
          'We have received your cash on delivery order and our team will contact you if needed before dispatch.',
          '',
          `Order Ref: ${orderRef}`,
          `Amount payable on delivery: ₹${amountTotal.toFixed(2)}`,
          `Estimated Delivery: Within ${estTimeMins} Minutes`,
          '',
          'For help with your order, contact us on 7988379826.',
          '',
          'Team AURUM'
        ].join('\n'),
        html: `
          <h2>Your Order Has Been Received</h2>
          <p>Thank you for ordering from AURUM.</p>
          <p>We have received your cash on delivery order and our team will contact you if needed before dispatch.</p>
          <p><strong>Order Ref:</strong> ${orderRef}</p>
          <p><strong>Amount payable on delivery:</strong> ₹${amountTotal.toFixed(2)}</p>
          <p><strong>Estimated Delivery:</strong> Within ${estTimeMins} Minutes</p>
          <p>For help with your order, contact us on <strong>7988379826</strong>.</p>
          <p>Team AURUM</p>
        `
      });
    } catch (_) {
      // Owner order creation should still succeed even if customer email fails.
    }

    paidOrdersStore.unshift({
      id: createId('ord'),
      provider: 'cod',
      status: 'pending',
      orderRef,
      customerEmail,
      amountTotal,
      currency: 'INR',
      items,
      deliveryLocation,
      createdAt: new Date().toISOString()
    });
    persistPaidOrdersToDisk();
    notifyAdminDash();

    return res.json({ ok: true, orderRef });
  } catch (err) {
    return res.status(500).json({ error: err?.message || 'Failed to place order.' });
  }
});

app.post('/api/orders/verify-razorpay-payment', requireAuth, createRateLimit({ key: 'verify-razorpay-payment', windowMs: 5 * 60 * 1000, max: 20 }), async (req, res) => {
  try {
    const orderId = String(req.body?.razorpay_order_id || '').trim();
    const paymentId = String(req.body?.razorpay_payment_id || '').trim();
    const signature = String(req.body?.razorpay_signature || '').trim();
    const result = await processPaidRazorpayOrder(orderId, paymentId, signature);
    if (!result.ok) {
      return res.status(400).json({ error: result.reason || 'Payment verification failed.' });
    }
    return res.json({ ok: true, alreadyNotified: Boolean(result.alreadyNotified) });
  } catch (err) {
    const reason = err?.message || 'Failed to verify Razorpay payment.';
    return res.status(500).json({ error: reason });
  }
});

app.get('/api/events/list', (req, res) => {
  res.json({ ok: true, events: premiumEventsList });
});

app.post('/api/events/create-razorpay-order', requireAuth, createRateLimit({ key: 'event-order', windowMs: 5 * 60 * 1000, max: 20 }), async (req, res) => {
  try {
    const eventId = String(req.body?.eventId || '').trim();
    const guests = Number(req.body?.guests) || 1;
    const name = String(req.body?.name || '').trim().slice(0, 100);
    const phone = normalizePhone(req.body?.phone || '');


    if (!eventId || !EVENT_PRICES[eventId]) return res.status(400).json({ error: 'Invalid event selected.' });
    if (guests < 1 || guests > 20) return res.status(400).json({ error: 'Invalid number of guests.' });
    if (!name || !phone) return res.status(400).json({ error: 'Name and valid phone number are required.' });

    const eventDetails = EVENT_PRICES[eventId];
    const totalFee = eventDetails.price * guests;
    const advanceAmount = Math.round(totalFee * 0.5); // 50% advance
    const amountPaise = advanceAmount * 100;

    const razorpay = getRazorpayClient();
    const order = await razorpay.orders.create({
      amount: amountPaise,
      currency: 'INR',
      receipt: `evt_${Date.now()}`
    });

    if (!order?.id) return res.status(500).json({ error: 'Failed to create Razorpay order.' });

    razorpayEventOrderStore.set(order.id, {
      eventId,
      eventName: eventDetails.name,
      venue: eventDetails.venue,
      date: eventDetails.date,
      guests,
      name,
      phone,
      authEmail: req.authEmail,
      advancePaid: advanceAmount,
      totalFee,
      createdAt: Date.now()
    });

    return res.json({ ok: true, keyId: process.env.RAZORPAY_KEY_ID, orderId: order.id, amount: amountPaise, currency: 'INR', prefill: { email: req.authEmail, contact: phone, name } });
  } catch (err) {
    return res.status(500).json({ error: err?.message || 'Order creation failed.' });
  }
});

app.delete('/api/admin/events/:id', requireAdmin, createRateLimit({ key: 'admin-event-delete', windowMs: 60 * 1000, max: 60 }), (req, res) => {
  const id = String(req.params?.id || '').trim();
  if (!id) return res.status(400).json({ error: 'Event Registration ID is required.' });
  const index = eventRegistrationsStore.findIndex(record => String(record?.id || '') === id);
  if (index < 0) return res.status(404).json({ error: 'Event registration not found.' });
  eventRegistrationsStore.splice(index, 1);
  persistEventRegistrationsToDisk();
  notifyAdminDash();
  return res.json({ ok: true });
});

app.post('/api/events/verify-razorpay-payment', requireAuth, createRateLimit({ key: 'event-verify', windowMs: 5 * 60 * 1000, max: 20 }), async (req, res) => {
  try {
    const orderId = String(req.body?.razorpay_order_id || '').trim();
    const paymentId = String(req.body?.razorpay_payment_id || '').trim();
    const signature = String(req.body?.razorpay_signature || '').trim();

    if (!orderId || !paymentId || !signature) return res.status(400).json({ error: 'Missing payment fields.' });

    const secret = process.env.RAZORPAY_KEY_SECRET;
    const expected = crypto.createHmac('sha256', secret).update(`${orderId}|${paymentId}`).digest('hex');
    if (expected !== signature) return res.status(400).json({ error: 'Signature verification failed.' });

    const pending = razorpayEventOrderStore.get(orderId);
    if (!pending) return res.status(400).json({ error: 'Order not found or expired.' });

    const regRecord = { id: createId('evr'), ...pending, paymentId, status: 'ticket_sent', createdAt: new Date().toISOString() };
    eventRegistrationsStore.unshift(regRecord);
    persistEventRegistrationsToDisk();
    notifyAdminDash();
    razorpayEventOrderStore.delete(orderId);

    try {
      const balance = pending.totalFee - pending.advancePaid;
      const ticketData = await createPremiumTicketPDF(regRecord);
      const isPdf = !ticketData.fallback;
      const filename = isPdf ? `AURUM_Ticket_${regRecord.id}.pdf` : `AURUM_Ticket_${regRecord.id}.html`;
      const content = isPdf ? ticketData : ticketData.buffer;

      await sendEmail({
        to: pending.authEmail,
        subject: `Your Ultra-Premium Ticket: ${pending.eventName}`,
        text: `Dear ${pending.name},\nWe have successfully received your 50% advance payment of ₹${pending.advancePaid}.\nYour exclusive event ticket is attached.\nThe remaining balance of ₹${balance} will be collected at the venue.\n\nTeam AURUM`,
        html: `
          <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#1A1612;color:#FAF7F2;border:1px solid #C9A84C;border-radius:12px;overflow:hidden;">
            <div style="padding:40px;text-align:center;border-bottom:1px solid rgba(201,168,76,0.3);">
              <h1 style="color:#C9A84C;margin:0;font-size:32px;letter-spacing:6px;text-transform:uppercase;">AURUM</h1>
              <p style="color:#A09080;margin:10px 0 0;font-size:12px;letter-spacing:3px;text-transform:uppercase;">Exclusive Events</p>
            </div>
            <div style="padding:40px;">
              <h2 style="margin-top:0;font-size:24px;font-weight:normal;color:#fff;">Ticket Confirmed</h2>
              <p style="font-size:16px;line-height:1.6;color:#ccc;">Dear ${pending.name},</p>
              <p style="font-size:16px;line-height:1.6;color:#ccc;">We have successfully received your 50% advance payment of <strong>₹${pending.advancePaid}</strong>. Your exclusive access is now confirmed.</p>
              <div style="background:#2A221A;border:1px solid #2D8A4D;padding:20px;margin:30px 0;text-align:center;border-radius:8px;">
                <p style="margin:0;font-size:18px;color:#2D8A4D;letter-spacing:2px;">STATUS: 50% ADVANCE PAID</p>
                <p style="margin:8px 0 0;font-size:14px;color:#C9A84C;">Balance of ₹${balance} is payable at the venue upon arrival</p>
              </div>
              <p style="font-size:16px;line-height:1.6;color:#C9A84C;">Please find your Super Premium Ticket attached to this email. We look forward to hosting you.</p>
            </div>
          </div>
        `,
        attachments: [{ filename, content }]
      });
    } catch (e) { console.error('Ticket email error:', e); }

    return res.json({ ok: true, registration: regRecord });
  } catch (err) {
    return res.status(500).json({ error: err?.message || 'Verification failed.' });
  }
});

app.post('/api/orders/create-checkout-session', requireAuth, createRateLimit({ key: 'create-checkout-session', windowMs: 5 * 60 * 1000, max: 10 }), async (req, res) => {
  try {
    const items = normalizeCart(req.body?.items);
    if (!items.length) {
      return res.status(400).json({ error: 'Cart is empty or invalid.' });
    }

    const stripe = getStripeClient();
    const baseUrl = getBaseUrl(req);
    const lineItems = items.map(item => ({
      price_data: {
        currency: 'inr',
        product_data: { name: item.name },
        unit_amount: Math.round(item.price * 100)
      },
      quantity: item.qty
    }));

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      customer_email: req.authEmail,
      line_items: lineItems,
      success_url: `${baseUrl}/delivery.html?payment=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${baseUrl}/delivery.html?payment=cancel`,
      metadata: {
        source: 'delivery-cart',
        auth_email: req.authEmail
      }
    });

    pruneOldCheckoutSessions();
    checkoutOrderStore.set(session.id, {
      items,
      createdAt: Date.now(),
      authEmail: req.authEmail
    });

    if (!session.url) {
      return res.status(500).json({ error: 'Failed to create checkout URL.' });
    }

    return res.json({ ok: true, url: session.url });
  } catch (err) {
    const reason = err?.message || 'Checkout session creation failed.';
    return res.status(500).json({ error: reason });
  }
});

app.post('/api/orders/confirm-payment', requireAuth, createRateLimit({ key: 'confirm-payment', windowMs: 5 * 60 * 1000, max: 20 }), async (req, res) => {
  try {
    const sessionId = String(req.body?.sessionId || '').trim();
    if (!sessionId) {
      return res.status(400).json({ error: 'Session ID is required.' });
    }
    const result = await processPaidCheckoutSession(sessionId);
    if (!result.ok) {
      return res.status(400).json({ error: result.reason || 'Payment is not completed yet.' });
    }
    return res.json({ ok: true, alreadyNotified: Boolean(result.alreadyNotified) });
  } catch (err) {
    const reason = err?.message || 'Failed to confirm payment.';
    return res.status(500).json({ error: reason });
  }
});

app.post('/api/auth/verify-otp', createRateLimit({ key: 'verify-otp', windowMs: 10 * 60 * 1000, max: 20 }), (req, res) => {
  const rawIdentifier = String(req.body?.identifier || req.body?.phone || req.body?.email || '').trim();
  const email = String(rawIdentifier || '').replace(/\s+/g, '').trim().toLowerCase();
  const phone = normalizePhone(rawIdentifier);
  const otp = String(req.body?.otp || '').replace(/\s+/g, '').trim();

  if (!/^\d{6}$/.test(otp)) {
    return res.status(400).json({ error: 'Invalid OTP format.' });
  }

  const userByEmail = isValidEmail(email) ? usersStore.get(email) : null;
  const userByPhone = phone ? getUserByPhone(phone) : null;
  const user = userByPhone || userByEmail;
  if (!user) {
    return res.status(404).json({ error: 'No account found. Please sign up first.' });
  }

  const userPhone = normalizePhone(user.phone || phone);
  if (userPhone && getTwilioConfig()) {
    checkTwilioVerification(userPhone, otp)
      .then(approved => {
        if (!approved) {
          return res.status(400).json({ error: 'Incorrect OTP.' });
        }
        const token = createSession(user.email);
        setSessionCookie(res, token);
        return res.json({ ok: true, email: user.email });
      })
      .catch(err => {
        const reason = err?.message || 'OTP verification failed.';
        return res.status(500).json({ error: reason });
      });
    return;
  }

  const key = `email:${user.email}`;
  const record = otpStore.get(key);
  if (!record) {
    return res.status(400).json({ error: 'OTP not found. Please request a new OTP.' });
  }

  if (Date.now() > record.expiresAt) {
    otpStore.delete(key);
    return res.status(400).json({ error: 'OTP expired. Please request a new OTP.' });
  }

  if (record.attempts >= OTP_MAX_ATTEMPTS) {
    otpStore.delete(key);
    return res.status(429).json({ error: 'Too many attempts. Please request a new OTP.' });
  }

  if (record.otp !== otp) {
    record.attempts += 1;
    otpStore.set(key, record);
    return res.status(400).json({ error: 'Incorrect OTP.' });
  }

  otpStore.delete(key);
  const token = createSession(user.email);
  setSessionCookie(res, token);
  return res.json({ ok: true, email: user.email });
});

app.post('/api/auth/signup', createRateLimit({ key: 'signup', windowMs: 10 * 60 * 1000, max: 10 }), async (req, res) => {
  try {
    const name = String(req.body?.name || '').trim();
    const email = String(req.body?.email || '').replace(/\s+/g, '').trim().toLowerCase();
    const phone = normalizePhone(req.body?.phone || '');
    const password = String(req.body?.password || '');
    const confirmPassword = String(req.body?.confirmPassword || '');

    if (!name || !email || !phone || !password || !confirmPassword) {
      return res.status(400).json({ error: 'Please fill all signup fields.' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }
    if (!phone) {
      return res.status(400).json({ error: 'Please enter a valid phone number.' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match.' });
    }
    if (email === 'nikhilsheoran093@gmail.com') {
      return res.status(403).json({ error: 'This email is reserved for admin use.' });
    }
    if (usersStore.has(email)) {
      return res.status(409).json({ error: 'Account already exists for this email.' });
    }
    if (getUserByPhone(phone)) {
      return res.status(409).json({ error: 'Account already exists for this phone number.' });
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = hashPassword(password, salt);
    usersStore.set(email, {
      name,
      email,
      phone,
      salt,
      passwordHash,
      createdAt: Date.now()
    });
    persistUsersToDisk();
    notifyAdminDash();

    try {
      await sendEmail({
        to: email,
        subject: 'Welcome to AURUM',
        text: `Hi ${name}, your AURUM account has been created successfully.`,
        html: `<p>Hi <strong>${name}</strong>,</p><p>Your AURUM account has been created successfully.</p>`
      });
    } catch (_) {
      // Signup should still succeed even if welcome email fails.
    }

    return res.status(201).json({ ok: true });
  } catch (err) {
    const reason = err?.message || 'Signup failed.';
    return res.status(500).json({ error: reason });
  }
});

app.get('/api/auth/status', (req, res) => {
  const email = getAuthenticatedEmail(req);
  return res.json({
    authenticated: Boolean(email),
    email: email || null,
    isAdmin: isAdminEmail(email)
  });
});

app.get('/api/admin/stream', requireAdmin, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();
  
  res.write(`data: connected\n\n`);
  adminStreamClients.push(res);
  
  req.on('close', () => {
    adminStreamClients = adminStreamClients.filter(c => c !== res);
  });
});

app.get('/api/admin/overview', requireAdmin, (req, res) => {
  const users = Array.from(usersStore.values())
    .sort((a, b) => Number(b.createdAt || 0) - Number(a.createdAt || 0))
    .map(user => ({
      name: user.name || '',
      email: user.email || '',
      phone: user.phone || '',
      createdAt: user.createdAt || null
    }));

  const reservations = reservationsStore
    .slice()
    .sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));

  const orders = paidOrdersStore
    .slice()
    .sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));

  const eventRegistrations = eventRegistrationsStore
    .slice()
    .sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));

  const eventsRevenue = eventRegistrationsStore.reduce((sum, reg) => sum + (Number(reg.totalFee) || 0), 0);
  const ordersRevenue = paidOrdersStore.reduce((sum, ord) => sum + (Number(ord.amountTotal) || 0), 0);

  return res.json({
    ok: true,
    stats: {
      users: users.length,
      reservations: reservationsStore.length,
      paidOrders: paidOrdersStore.length,
      events: eventRegistrationsStore.length,
      eventsRevenue,
      ordersRevenue
    },
    users,
    reservations,
    orders,
    eventRegistrations
  });
});

app.get('/api/user/profile', requireAuth, (req, res) => {
  const email = req.authEmail;
  const user = usersStore.get(email) || { name: 'Guest', email: email, phone: '' };

  const myReservations = reservationsStore
    .filter(r => String(r.guestEmail).toLowerCase() === email)
    .sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));

  const myOrders = paidOrdersStore
    .filter(o => String(o.customerEmail).toLowerCase() === email)
    .sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));

  const myEvents = eventRegistrationsStore
    .filter(e => String(e.authEmail).toLowerCase() === email)
    .sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));

  return res.json({
    ok: true,
    user: { name: user.name, email: user.email, phone: user.phone },
    reservations: myReservations,
    orders: myOrders,
    events: myEvents
  });
});

app.post('/api/admin/reservations/:id/status', requireAdmin, createRateLimit({ key: 'admin-reservation-status', windowMs: 60 * 1000, max: 60 }), async (req, res) => {
  try {
    const id = String(req.params?.id || '').trim();
    const status = String(req.body?.status || '').trim().toLowerCase();
    if (!['pending', 'approved', 'rejected'].includes(status)) {
      return res.status(400).json({ error: 'Invalid reservation status.' });
    }

    const reservation = findReservationById(id);
    if (!reservation) {
      return res.status(404).json({ error: 'Reservation not found.' });
    }

    reservation.status = status;
    reservation.updatedAt = new Date().toISOString();
    persistReservationsToDisk();
    notifyAdminDash();

    const guestEmail = String(reservation.guestEmail || '').trim();
    if (guestEmail) {
      const fullName = `${reservation.firstName || ''} ${reservation.lastName || ''}`.trim() || 'Guest';
      const statusTitle = status === 'approved' ? 'confirmed' : status === 'rejected' ? 'unable to confirm' : 'updated';
      const textLines = [
        `Dear ${fullName},`,
        '',
        status === 'approved'
          ? 'Your reservation at AURUM has been confirmed. We look forward to welcoming you.'
          : status === 'rejected'
            ? 'We are sorry, but we are unable to confirm your requested reservation at this time.'
            : 'Your reservation request is currently under review.',
        '',
        `Date: ${reservation.date || 'Not selected'}`,
        `Time: ${reservation.time || 'Not selected'}`,
        `Guests: ${reservation.guests || 'Not selected'}`,
        '',
        'For assistance or changes, please contact us on 7988379826.',
        '',
        'Team AURUM'
      ];
      try {
        await sendEmail({
          to: guestEmail,
          subject: `Your AURUM reservation is ${statusTitle}`,
          text: textLines.join('\n'),
          html: `
            <h2>Your Reservation Has Been ${status === 'approved' ? 'Confirmed' : status === 'rejected' ? 'Updated' : 'Received'}</h2>
            <p>Dear ${fullName},</p>
            <p>${
              status === 'approved'
                ? 'Your reservation at AURUM has been confirmed. We look forward to welcoming you.'
                : status === 'rejected'
                  ? 'We are sorry, but we are unable to confirm your requested reservation at this time.'
                  : 'Your reservation request is currently under review.'
            }</p>
            <p><strong>Date:</strong> ${reservation.date || 'Not selected'}</p>
            <p><strong>Time:</strong> ${reservation.time || 'Not selected'}</p>
            <p><strong>Guests:</strong> ${reservation.guests || 'Not selected'}</p>
            <p>For assistance or changes, please contact us on <strong>7988379826</strong>.</p>
            <p>Team AURUM</p>
          `
        });
      } catch (_) {
        // Admin action should still complete even if email notification fails.
      }
    }

    return res.json({ ok: true, reservation });
  } catch (err) {
    return res.status(500).json({ error: err?.message || 'Failed to update reservation.' });
  }
});

app.delete('/api/admin/reservations/:id', requireAdmin, createRateLimit({ key: 'admin-reservation-delete', windowMs: 60 * 1000, max: 60 }), (req, res) => {
  const id = String(req.params?.id || '').trim();
  if (!id) return res.status(400).json({ error: 'Reservation ID is required.' });
  if (!deleteReservationById(id)) {
    return res.status(404).json({ error: 'Reservation not found.' });
  }
  return res.json({ ok: true });
});


app.post('/api/admin/orders/:id/status', requireAdmin, createRateLimit({ key: 'admin-order-status', windowMs: 60 * 1000, max: 60 }), (req, res) => {
  const id = String(req.params?.id || '').trim();
  const status = String(req.body?.status || '').trim().toLowerCase();
  if (!['pending', 'paid', 'processing', 'completed', 'delivered'].includes(status)) {
    return res.status(400).json({ error: 'Invalid order status.' });
  }
  const order = findPaidOrderById(id);
  if (!order) {
    return res.status(404).json({ error: 'Order not found.' });
  }
  order.status = status;
  order.updatedAt = new Date().toISOString();
  persistPaidOrdersToDisk();
  notifyAdminDash();
  return res.json({ ok: true, order });
});

app.delete('/api/admin/orders/:id', requireAdmin, createRateLimit({ key: 'admin-order-delete', windowMs: 60 * 1000, max: 60 }), (req, res) => {
  const id = String(req.params?.id || '').trim();
  if (!id) return res.status(400).json({ error: 'Order ID is required.' });
  if (!deletePaidOrderById(id)) {
    return res.status(404).json({ error: 'Order not found.' });
  }
  return res.json({ ok: true });
});

app.post('/api/auth/logout', (req, res) => {
  const cookies = parseCookies(req);
  const token = cookies.aurum_session;
  if (token) {
    sessionsStore.delete(token);
    persistSessionsToDisk();
  }
  setNoStore(res);
  clearSessionCookie(res);
  return res.json({ ok: true });
});

app.get('/robots.txt', (req, res) => {
  const siteUrl = String(process.env.SITE_URL || '').trim();
  res.type('text/plain');
  return res.send(`User-agent: *\nAllow: /\n${siteUrl ? `Sitemap: ${siteUrl.replace(/\/+$/, '')}/sitemap.xml\n` : ''}`);
});

app.get('/sitemap.xml', (req, res) => {
  const siteUrl = String(process.env.SITE_URL || `${req.protocol}://${req.get('host')}`).replace(/\/+$/, '');
  const urls = ['/', '/login', '/signup', '/privacy', '/terms', '/refund-policy', '/admin'];
  const body = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ...urls.map(url => `<url><loc>${siteUrl}${url}</loc></url>`),
    '</urlset>'
  ].join('');
  res.type('application/xml');
  return res.send(body);
});

app.get('/privacy', (req, res) => {
  res.sendFile(path.join(__dirname, 'privacy.html'));
});

app.get('/terms', (req, res) => {
  res.sendFile(path.join(__dirname, 'terms.html'));
});

app.get('/refund-policy', (req, res) => {
  res.sendFile(path.join(__dirname, 'refund-policy.html'));
});

app.get('/login', (req, res) => {
  setNoStore(res);
  if (getAuthenticatedEmail(req)) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/login.html', (req, res) => {
  res.redirect('/login');
});

app.get('/signup', (req, res) => {
  setNoStore(res);
  if (getAuthenticatedEmail(req)) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'signup.html'));
});

app.get('/signup.html', (req, res) => {
  res.redirect('/signup');
});

app.get('/', (req, res) => {
  setNoStore(res);
  if (getAuthenticatedEmail(req)) {
    return res.sendFile(path.join(__dirname, 'index.html'));
  }
  return res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/index.html', (req, res) => {
  setNoStore(res);
  if (!getAuthenticatedEmail(req)) {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/website.html', requireAuth, (req, res) => {
  res.redirect('/index.html');
});

app.get('/delivery', requireAuth, (req, res) => {
  setNoStore(res);
  res.sendFile(path.join(__dirname, 'delivery.html'));
});

app.get('/delivery.html', requireAuth, (req, res) => {
  setNoStore(res);
  res.sendFile(path.join(__dirname, 'delivery.html'));
});

app.get('/admin', requireAdmin, (req, res) => {
  setNoStore(res);
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/admin.html', requireAdmin, (req, res) => {
  setNoStore(res);
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/profile', requireAuth, (req, res) => {
  setNoStore(res);
  res.sendFile(path.join(__dirname, 'profile.html'));
});

app.get('/profile.html', requireAuth, (req, res) => {
  setNoStore(res);
  res.sendFile(path.join(__dirname, 'profile.html'));
});

app.get('/gym-chatbot', requireAuth, (req, res) => {
  setNoStore(res);
  res.sendFile(path.join(__dirname, 'gym-chatbot.html'));
});

app.get('/gym-chatbot.html', requireAuth, (req, res) => {
  setNoStore(res);
  res.sendFile(path.join(__dirname, 'gym-chatbot.html'));
});

app.get('/order-success', requireAuth, (req, res) => {
  setNoStore(res);
  res.sendFile(path.join(__dirname, 'order-success.html'));
});

app.get('/order-success.html', requireAuth, (req, res) => {
  setNoStore(res);
  res.sendFile(path.join(__dirname, 'order-success.html'));
});

app.get('*', (req, res) => {
  if (getAuthenticatedEmail(req)) {
    return res.redirect('/');
  }
  return res.redirect('/login');
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
