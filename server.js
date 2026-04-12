const express = require('express');
const nodemailer = require('nodemailer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const Stripe = require('stripe');
const Razorpay = require('razorpay');
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
let stripeClient = null;
let razorpayClient = null;

app.use((req, res, next) => {
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

app.use(express.json());

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || '').trim());
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function loadUsersFromDisk() {
  try {
    if (!fs.existsSync(USERS_DB_PATH)) return;
    const raw = fs.readFileSync(USERS_DB_PATH, 'utf8');
    if (!raw) return;
    const records = JSON.parse(raw);
    if (!Array.isArray(records)) return;
    records.forEach(user => {
      if (user && user.email && user.salt && user.passwordHash) {
        usersStore.set(String(user.email).toLowerCase(), user);
      }
    });
  } catch (_) {
    // Ignore broken disk data and continue with empty store.
  }
}

function persistUsersToDisk() {
  const records = Array.from(usersStore.values());
  fs.writeFileSync(USERS_DB_PATH, JSON.stringify(records, null, 2), 'utf8');
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
  return token;
}

function setSessionCookie(res, token) {
  const maxAge = Math.floor(SESSION_TTL_MS / 1000);
  const isProduction = process.env.NODE_ENV === 'production';
  const sameSite = isProduction ? 'None' : 'Lax';
  const secure = isProduction ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    `aurum_session=${token}; HttpOnly; Path=/; Max-Age=${maxAge}; SameSite=${sameSite}${secure}`
  );
}

function clearSessionCookie(res) {
  const isProduction = process.env.NODE_ENV === 'production';
  const sameSite = isProduction ? 'None' : 'Lax';
  const secure = isProduction ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    `aurum_session=; HttpOnly; Path=/; Max-Age=0; SameSite=${sameSite}${secure}`
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

loadUsersFromDisk();

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

  const { transporter, fromEmail } = createTransporter();
  const toEmail = process.env.ORDER_NOTIFICATION_EMAIL || 'nikhilsheoran093@gmail.com';
  await transporter.sendMail({
    from: fromEmail,
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

  const { transporter, fromEmail } = createTransporter();
  const toEmail = process.env.ORDER_NOTIFICATION_EMAIL || 'nikhilsheoran093@gmail.com';
  await transporter.sendMail({
    from: fromEmail,
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

app.post('/api/reservations', async (req, res) => {
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

    const toEmail = process.env.TO_EMAIL || 'nikhilsheoran78@gmail.com';
    const { transporter, fromEmail } = createTransporter();

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

    await transporter.sendMail({
      from: fromEmail,
      to: toEmail,
      replyTo: guestEmail,
      subject,
      text,
      html
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

app.post('/api/auth/send-otp', async (req, res) => {
  try {
    const email = String(req.body?.email || '').replace(/\s+/g, '').trim().toLowerCase();
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }
    if (!usersStore.has(email)) {
      return res.status(404).json({ error: 'No account found for this email. Please sign up first.' });
    }

    const existing = otpStore.get(email);
    if (existing && Date.now() - existing.lastSentAt < OTP_RESEND_GAP_MS) {
      return res.status(429).json({ error: 'Please wait 60 seconds before requesting another OTP.' });
    }

    const otp = String(Math.floor(100000 + Math.random() * 900000));
    otpStore.set(email, {
      otp,
      expiresAt: Date.now() + OTP_TTL_MS,
      attempts: 0,
      lastSentAt: Date.now()
    });

    const { transporter, fromEmail } = createTransporter();
    await transporter.sendMail({
      from: fromEmail,
      to: email,
      subject: 'Your AURUM Login OTP',
      text: `Your OTP is ${otp}. It expires in 5 minutes.`,
      html: `<p>Your OTP is <strong>${otp}</strong>.</p><p>It expires in 5 minutes.</p>`
    });

    return res.json({ ok: true, expiresInSeconds: 300 });
  } catch (err) {
    const reason = err?.response || err?.message || 'Failed to send OTP.';
    return res.status(500).json({ error: `Failed to send OTP: ${reason}` });
  }
});

app.post('/api/gym-chatbot', requireAuth, async (req, res) => {
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

app.post('/api/orders/create-razorpay-order', requireAuth, async (req, res) => {
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

app.post('/api/orders/verify-razorpay-payment', requireAuth, async (req, res) => {
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

app.post('/api/orders/create-checkout-session', requireAuth, async (req, res) => {
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

app.post('/api/orders/confirm-payment', requireAuth, async (req, res) => {
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

app.post('/api/auth/verify-otp', (req, res) => {
  const email = String(req.body?.email || '').replace(/\s+/g, '').trim().toLowerCase();
  const otp = String(req.body?.otp || '').replace(/\s+/g, '').trim();

  if (!isValidEmail(email) || !/^\d{6}$/.test(otp)) {
    return res.status(400).json({ error: 'Invalid email or OTP format.' });
  }

  const record = otpStore.get(email);
  if (!record) {
    return res.status(400).json({ error: 'OTP not found. Please request a new OTP.' });
  }

  if (Date.now() > record.expiresAt) {
    otpStore.delete(email);
    return res.status(400).json({ error: 'OTP expired. Please request a new OTP.' });
  }

  if (record.attempts >= OTP_MAX_ATTEMPTS) {
    otpStore.delete(email);
    return res.status(429).json({ error: 'Too many attempts. Please request a new OTP.' });
  }

  if (record.otp !== otp) {
    record.attempts += 1;
    otpStore.set(email, record);
    return res.status(400).json({ error: 'Incorrect OTP.' });
  }

  otpStore.delete(email);
  const token = createSession(email);
  setSessionCookie(res, token);
  return res.json({ ok: true, email });
});

app.post('/api/auth/signup', async (req, res) => {
  try {
    const name = String(req.body?.name || '').trim();
    const email = String(req.body?.email || '').replace(/\s+/g, '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const confirmPassword = String(req.body?.confirmPassword || '');

    if (!name || !email || !password || !confirmPassword) {
      return res.status(400).json({ error: 'Please fill all signup fields.' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match.' });
    }
    if (usersStore.has(email)) {
      return res.status(409).json({ error: 'Account already exists for this email.' });
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = hashPassword(password, salt);
    usersStore.set(email, {
      name,
      email,
      salt,
      passwordHash,
      createdAt: Date.now()
    });
    persistUsersToDisk();

    try {
      const { transporter, fromEmail } = createTransporter();
      await transporter.sendMail({
        from: fromEmail,
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
  return res.json({ authenticated: Boolean(email), email: email || null });
});

app.post('/api/auth/logout', (req, res) => {
  const cookies = parseCookies(req);
  const token = cookies.aurum_session;
  if (token) sessionsStore.delete(token);
  clearSessionCookie(res);
  return res.json({ ok: true });
});

app.get('/login', (req, res) => {
  if (getAuthenticatedEmail(req)) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/signup', (req, res) => {
  if (getAuthenticatedEmail(req)) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'signup.html'));
});

app.get('/', (req, res) => {
  if (getAuthenticatedEmail(req)) {
    return res.sendFile(path.join(__dirname, 'index.html'));
  }
  return res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/index.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/website.html', requireAuth, (req, res) => {
  res.redirect('/index.html');
});

app.get('/delivery', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'delivery.html'));
});

app.get('/delivery.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'delivery.html'));
});

app.get('/gym-chatbot', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'gym-chatbot.html'));
});

app.get('/gym-chatbot.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'gym-chatbot.html'));
});

app.get('/order-success', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'order-success.html'));
});

app.get('/order-success.html', requireAuth, (req, res) => {
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
