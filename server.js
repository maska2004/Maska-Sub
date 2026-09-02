require("dotenv").config();
const express = require("express");
const fetch = require("node-fetch");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

const app = express();

// Render sits our app behind its own proxy. This tells Express to trust the
// X-Forwarded-For header from exactly one hop (Render's proxy) so rate
// limiting can correctly identify each visitor's real IP address.
app.set("trust proxy", 1);

// --- Security headers (protects against clickjacking, sniffing, some XSS) ---
app.use(helmet({ contentSecurityPolicy: false })); // CSP off for now since we load Paystack's script; can tighten later

app.use(cors());
app.use(express.json({ limit: "50kb" })); // caps request body size to stop abuse
app.use(express.static(path.join(__dirname, "public")));

// --- Rate limiting: slows down brute-force password guessing / spam signups ---
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per IP per window
  message: { error: "Too many attempts. Please wait a few minutes and try again." },
  standardHeaders: true,
  legacyHeaders: false,
});

const orderLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 30,
  message: { error: "Too many requests. Please slow down and try again shortly." },
});

const publicDataLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 60,
  message: { error: "Too many requests. Please slow down and try again shortly." },
});

// Stricter than the general auth limiter — this route sends an email, so it's
// the one most worth protecting from being spammed to flood someone's inbox.
const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  message: { error: "Too many reset requests. Please try again later." },
});

const PLANS_FILE = path.join(__dirname, "plans.json");
const AIRTIME_FILE = path.join(__dirname, "airtime.json");
const ORDERS_FILE = path.join(__dirname, "orders.json");
const USERS_FILE = path.join(__dirname, "users.json");
const JWT_SECRET = process.env.JWT_SECRET || "dev-only-insecure-secret-change-me";
if (process.env.NODE_ENV === "production" && JWT_SECRET === "dev-only-insecure-secret-change-me") {
  console.error("FATAL: JWT_SECRET is not set. Refusing to start with an insecure default in production.");
  process.exit(1);
}

const { Resend } = require("resend");
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

async function sendResetEmail(toEmail, resetUrl) {
  if (!resend) {
    console.error("Cannot send reset email — RESEND_API_KEY not configured.");
    return false;
  }
  try {
    await resend.emails.send({
      from: "Maska Sub <onboarding@resend.dev>",
      to: toEmail,
      subject: "Reset your Maska Sub password",
      text: `You requested a password reset. This link expires in 30 minutes:\n\n${resetUrl}\n\nIf you didn't request this, you can safely ignore this email.`,
      html: `<p>You requested a password reset. This link expires in <strong>30 minutes</strong>:</p><p><a href="${resetUrl}">${resetUrl}</a></p><p>If you didn't request this, you can safely ignore this email.</p>`,
    });
    return true;
  } catch (err) {
    console.error("Failed to send reset email:", err);
    return false;
  }
}



// Make sure orders.json and users.json exist
if (!fs.existsSync(ORDERS_FILE)) {
  fs.writeFileSync(ORDERS_FILE, "[]");
}
if (!fs.existsSync(USERS_FILE)) {
  fs.writeFileSync(USERS_FILE, "[]");
}

function loadPlans() {
  return JSON.parse(fs.readFileSync(PLANS_FILE, "utf-8"));
}

function loadAirtimeNetworks() {
  return JSON.parse(fs.readFileSync(AIRTIME_FILE, "utf-8"));
}

function loadElectricityDiscos() {
  return JSON.parse(fs.readFileSync(path.join(__dirname, "electricity.json"), "utf-8"));
}

function loadCableTv() {
  return JSON.parse(fs.readFileSync(path.join(__dirname, "cabletv.json"), "utf-8"));
}

function loadExams() {
  return JSON.parse(fs.readFileSync(path.join(__dirname, "exams.json"), "utf-8"));
}

function loadOrders() {
  return JSON.parse(fs.readFileSync(ORDERS_FILE, "utf-8"));
}

function saveOrders(orders) {
  fs.writeFileSync(ORDERS_FILE, JSON.stringify(orders, null, 2));
}

function loadUsers() {
  return JSON.parse(fs.readFileSync(USERS_FILE, "utf-8"));
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// --- Auth middleware: verifies the JWT sent in the Authorization header ---
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "Please log in to continue." });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Your session has expired. Please log in again." });
  }
}

// --- Sign up: create a new account ---
app.post("/api/auth/signup", authLimiter, async (req, res) => {
  try {
    const { phone, password, email } = req.body;

    if (!phone || !password || !email) {
      return res.status(400).json({ error: "Phone, password, and email are all required." });
    }

    const cleanPhone = String(phone).trim();
    if (!/^0[789][01]\d{8}$/.test(cleanPhone)) {
      return res.status(400).json({ error: "Enter a valid Nigerian phone number (e.g. 08012345678)." });
    }

    if (password.length < 6 || password.length > 128) {
      return res.status(400).json({ error: "Password must be between 6 and 128 characters." });
    }

    const cleanEmail = String(email).trim().toLowerCase();
    if (!cleanEmail.includes("@") || !cleanEmail.includes(".")) {
      return res.status(400).json({ error: "Enter a valid email address." });
    }

    const users = loadUsers();
    if (users.find((u) => u.phone === cleanPhone)) {
      return res.status(409).json({ error: "An account with this phone number already exists." });
    }
    if (users.find((u) => u.email === cleanEmail)) {
      return res.status(409).json({ error: "An account with this email already exists." });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = {
      id: "user_" + crypto.randomBytes(8).toString("hex"),
      phone: cleanPhone,
      email: cleanEmail,
      passwordHash,
      resetTokenHash: null,
      resetTokenExpiresAt: null,
      createdAt: new Date().toISOString(),
    };
    users.push(user);
    saveUsers(users);

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, phone: user.phone });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Something went wrong creating your account." });
  }
});

// --- Log in: verify credentials, issue a token ---
app.post("/api/auth/login", authLimiter, async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) {
      return res.status(400).json({ error: "Phone and password are required." });
    }

    const cleanPhone = String(phone).trim();
    const users = loadUsers();
    const user = users.find((u) => u.phone === cleanPhone);

    // Same generic error whether the phone doesn't exist or the password is wrong —
    // this stops an attacker from using the error message to find out which phone
    // numbers have accounts.
    if (!user) {
      await bcrypt.compare(password, "$2a$10$invalidsaltinvalidsaltinvalidsaltinvalidsal"); // dummy hash so timing looks the same either way
      return res.status(401).json({ error: "Incorrect phone number or password." });
    }

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      return res.status(401).json({ error: "Incorrect phone number or password." });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, phone: user.phone });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Something went wrong logging in." });
  }
});

// --- Request a password reset link by email ---
app.post("/api/auth/forgot-password", resetLimiter, async (req, res) => {
  // Always return the same generic message whether or not the account
  // exists — this stops someone from using this route to check which
  // emails have accounts (account enumeration).
  const genericResponse = {
    message: "If that email has an account, a reset link has been sent to it.",
  };

  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: "Email is required." });
    }

    const cleanEmail = String(email).trim().toLowerCase();
    const users = loadUsers();
    const user = users.find((u) => u.email === cleanEmail);

    if (!user) {
      return res.json(genericResponse); // don't reveal which case it was
    }

    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");

    user.resetTokenHash = tokenHash;
    user.resetTokenExpiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString(); // 30 min
    saveUsers(users);

    const baseUrl = `${req.protocol}://${req.get("host")}`;
    // The link itself still identifies the account by phone internally —
    // this is just an implementation detail, invisible to the customer.
    const resetUrl = `${baseUrl}/reset-password.html?token=${rawToken}&phone=${encodeURIComponent(user.phone)}`;

    const sent = await sendResetEmail(user.email, resetUrl);
    if (!sent) {
      console.error(`Reset email failed to send for ${cleanEmail} — check SMTP_EMAIL/SMTP_APP_PASSWORD are set correctly in environment variables.`);
    }

    res.json(genericResponse);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

// --- Complete a password reset using the emailed token ---
app.post("/api/auth/reset-password", resetLimiter, async (req, res) => {
  try {
    const { phone, token, newPassword } = req.body;
    if (!phone || !token || !newPassword) {
      return res.status(400).json({ error: "Phone, token and new password are required." });
    }
    if (newPassword.length < 6 || newPassword.length > 128) {
      return res.status(400).json({ error: "Password must be between 6 and 128 characters." });
    }

    const cleanPhone = String(phone).trim();
    const users = loadUsers();
    const user = users.find((u) => u.phone === cleanPhone);

    if (!user || !user.resetTokenHash || !user.resetTokenExpiresAt) {
      return res.status(400).json({ error: "This reset link is invalid or has expired. Please request a new one." });
    }

    if (new Date() > new Date(user.resetTokenExpiresAt)) {
      user.resetTokenHash = null;
      user.resetTokenExpiresAt = null;
      saveUsers(users);
      return res.status(400).json({ error: "This reset link has expired. Please request a new one." });
    }

    const tokenHash = crypto.createHash("sha256").update(String(token)).digest("hex");
    if (tokenHash !== user.resetTokenHash) {
      return res.status(400).json({ error: "This reset link is invalid. Please request a new one." });
    }

    user.passwordHash = await bcrypt.hash(newPassword, 10);
    user.resetTokenHash = null; // single-use — token is now dead either way
    user.resetTokenExpiresAt = null;
    saveUsers(users);

    res.json({ message: "Your password has been reset. You can now log in." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

// --- Public config (safe to expose — public key only, never the secret key) ---
app.get("/api/config", (req, res) => {
  res.json({ paystackPublicKey: process.env.PAYSTACK_PUBLIC_KEY || "" });
});

// --- Public: list plans (cost price hidden from customers) ---
app.get("/api/plans", publicDataLimiter, (req, res) => {
  const plans = loadPlans().map(({ id, network, label, sellPriceNaira }) => ({
    id,
    network,
    label,
    priceNaira: sellPriceNaira,
  }));
  res.json(plans);
});

// --- Public: list airtime networks (no cost info exposed since price = customer-entered amount) ---
app.get("/api/airtime-networks", publicDataLimiter, (req, res) => {
  const networks = loadAirtimeNetworks().map(({ id, label, minAmount, maxAmount }) => ({
    id,
    label,
    minAmount,
    maxAmount,
  }));
  res.json(networks);
});

// --- Public: list electricity discos ---
app.get("/api/electricity-discos", publicDataLimiter, (req, res) => {
  res.json(loadElectricityDiscos());
});

// --- Public: list cable TV bouquets ---
app.get("/api/cabletv-bouquets", publicDataLimiter, (req, res) => {
  res.json(loadCableTv());
});

// --- Public: list exam pin options ---
app.get("/api/exam-services", publicDataLimiter, (req, res) => {
  res.json(loadExams());
});

// --- Verify a meter/smartcard/JAMB profile ID before purchase (login required) ---
// This never trusts a customer name typed by the customer — it always asks
// VTpass to confirm who actually owns that number before money changes hands.
app.post("/api/verify-biller", orderLimiter, requireAuth, async (req, res) => {
  try {
    const { serviceID, billersCode, type } = req.body;
    if (!serviceID || !billersCode) {
      return res.status(400).json({ error: "serviceID and billersCode are required." });
    }
    if (!process.env.VTPASS_BASE_URL || !process.env.VTPASS_API_KEY || !process.env.VTPASS_SECRET_KEY) {
      return res.status(500).json({ error: "VTU provider is not configured yet." });
    }

    const body = { serviceID, billersCode: String(billersCode).trim() };
    if (type) body.type = type;

    const vtRes = await fetch(`${process.env.VTPASS_BASE_URL}/merchant-verify`, {
      method: "POST",
      headers: {
        "api-key": process.env.VTPASS_API_KEY,
        "secret-key": process.env.VTPASS_SECRET_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
    const data = await vtRes.json();

    if (data.code !== "000" || !data.content) {
      return res.status(400).json({ error: "Could not verify — please check the number and try again." });
    }

    // Only return the safe, minimal fields the customer needs to confirm — not
    // the raw provider response, which can include internal fields we don't need to expose.
    res.json({
      customerName: data.content.Customer_Name || null,
      address: data.content.Address || null,
      minPurchaseAmount: data.content.Min_Purchase_Amount || null,
      meterType: data.content.Meter_Type || null,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Verification failed. Please try again." });
  }
});

// --- Start a payment: create a pending order + Paystack transaction (login required) ---
app.post("/api/orders/initialize", orderLimiter, requireAuth, async (req, res) => {
  try {
    const { type, planId, networkId, amountNaira, phone, email } = req.body;

    if (!phone || !email) {
      return res.status(400).json({ error: "Phone and email are required" });
    }
    if (!/^0[789][01]\d{8}$/.test(String(phone).trim())) {
      return res.status(400).json({ error: "Enter a valid Nigerian phone number." });
    }
    if (!email.includes("@")) {
      return res.status(400).json({ error: "Enter a valid email address." });
    }
    if (!process.env.PAYSTACK_SECRET_KEY) {
      return res.status(500).json({
        error: "Server is missing PAYSTACK_SECRET_KEY. Add it to your .env file.",
      });
    }

    let orderRecord;

    if (type === "airtime") {
      const network = loadAirtimeNetworks().find((n) => n.id === networkId);
      if (!network) {
        return res.status(404).json({ error: "Network not found" });
      }

      // IMPORTANT: never trust an amount sent from the browser without checking it —
      // a customer could otherwise tamper with the request and pay less than they
      // should. We only trust the min/max bounds we ourselves defined in airtime.json.
      const amount = Number(amountNaira);
      if (!Number.isInteger(amount) || amount < network.minAmount || amount > network.maxAmount) {
        return res.status(400).json({
          error: `Enter an amount between ₦${network.minAmount} and ₦${network.maxAmount}.`,
        });
      }

      orderRecord = {
        type: "airtime",
        network: network.label,
        networkId: network.id,
        label: "Airtime Top-up",
        amountNaira: amount,
      };
    } else if (type === "electricity") {
      const { discoId, meterNumber, meterType } = req.body;
      const disco = loadElectricityDiscos().find((d) => d.id === discoId);
      if (!disco) {
        return res.status(404).json({ error: "Disco not found" });
      }
      if (!meterNumber || !/^\d{6,20}$/.test(String(meterNumber).trim())) {
        return res.status(400).json({ error: "Enter a valid meter number." });
      }
      if (!["prepaid", "postpaid"].includes(meterType)) {
        return res.status(400).json({ error: "Meter type must be prepaid or postpaid." });
      }

      // Re-verify server-side right before payment — this both confirms the
      // meter is real and gives us the authoritative minimum purchase amount,
      // rather than trusting whatever the browser last showed the customer.
      if (!process.env.VTPASS_BASE_URL || !process.env.VTPASS_API_KEY || !process.env.VTPASS_SECRET_KEY) {
        return res.status(500).json({ error: "VTU provider is not configured yet." });
      }
      const verifyRes = await fetch(`${process.env.VTPASS_BASE_URL}/merchant-verify`, {
        method: "POST",
        headers: {
          "api-key": process.env.VTPASS_API_KEY,
          "secret-key": process.env.VTPASS_SECRET_KEY,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ serviceID: disco.vtpassServiceID, billersCode: String(meterNumber).trim(), type: meterType }),
      });
      const verifyData = await verifyRes.json();
      if (verifyData.code !== "000" || !verifyData.content) {
        return res.status(400).json({ error: "Could not verify this meter number. Please check and try again." });
      }

      const minAmount = Number(verifyData.content.Min_Purchase_Amount) || 500;
      const amount = Number(amountNaira);
      if (!Number.isInteger(amount) || amount < minAmount) {
        return res.status(400).json({ error: `Enter an amount of at least ₦${minAmount}.` });
      }

      orderRecord = {
        type: "electricity",
        network: disco.label,
        discoId: disco.id,
        meterNumber: String(meterNumber).trim(),
        meterType,
        label: `${meterType === "prepaid" ? "Prepaid" : "Postpaid"} electricity — ${verifyData.content.Customer_Name || "verified meter"}`,
        amountNaira: amount,
      };
    } else if (type === "cabletv") {
      const { provider, variationCode, smartcardNumber } = req.body;
      const cabletv = loadCableTv();
      const providerConfig = cabletv[provider];
      if (!providerConfig) {
        return res.status(404).json({ error: "Provider not found" });
      }
      const bouquet = providerConfig.bouquets.find((b) => b.variation_code === variationCode);
      if (!bouquet) {
        return res.status(404).json({ error: "Bouquet not found" });
      }
      if (!smartcardNumber || !/^\d{6,20}$/.test(String(smartcardNumber).trim())) {
        return res.status(400).json({ error: "Enter a valid smartcard/IUC number." });
      }

      orderRecord = {
        type: "cabletv",
        network: providerConfig.label,
        provider,
        variationCode,
        smartcardNumber: String(smartcardNumber).trim(),
        label: bouquet.label,
        // Always the price WE defined in cabletv.json — never trust a price from the browser.
        amountNaira: bouquet.amountNaira,
      };
    } else if (type === "exam") {
      const { examType, variationCode, profileId } = req.body;
      const exams = loadExams();
      const examConfig = exams[examType];
      if (!examConfig) {
        return res.status(404).json({ error: "Exam service not found" });
      }
      const variation = examConfig.variations.find((v) => v.variation_code === variationCode);
      if (!variation) {
        return res.status(404).json({ error: "Option not found" });
      }

      let billersCode = phone; // WAEC just needs a phone number as the biller reference
      if (examConfig.requiresProfileVerify) {
        if (!profileId || !/^\d{6,15}$/.test(String(profileId).trim())) {
          return res.status(400).json({ error: "Enter a valid JAMB Profile ID." });
        }
        billersCode = String(profileId).trim();
      }

      orderRecord = {
        type: "exam",
        network: examConfig.label,
        examType,
        variationCode,
        billersCode,
        label: variation.label,
        amountNaira: variation.amountNaira,
      };
    } else {
      const plan = loadPlans().find((p) => p.id === planId);
      if (!plan) {
        return res.status(404).json({ error: "Plan not found" });
      }
      orderRecord = {
        type: "data",
        planId,
        network: plan.network,
        label: plan.label,
        // Always use OUR stored price, never anything the browser might send —
        // this is what stops a tampered request from paying less than the real price.
        amountNaira: plan.sellPriceNaira,
      };
    }

    const reference = "order_" + crypto.randomBytes(8).toString("hex");
    const amountKobo = orderRecord.amountNaira * 100; // Paystack uses kobo

    const paystackRes = await fetch("https://api.paystack.co/transaction/initialize", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email,
        amount: amountKobo,
        reference,
        metadata: { type: orderRecord.type, planId, networkId, phone },
      }),
    });

    const paystackData = await paystackRes.json();

    if (!paystackData.status) {
      return res.status(502).json({ error: "Paystack initialization failed", details: paystackData });
    }

    const orders = loadOrders();
    orders.push({
      reference,
      userId: req.userId,
      ...orderRecord,
      phone,
      email,
      status: "pending",
      fulfilled: false,
      createdAt: new Date().toISOString(),
    });
    saveOrders(orders);

    res.json({
      authorization_url: paystackData.data.authorization_url,
      reference,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Something went wrong starting payment" });
  }
});

// --- Verify a payment after the customer returns from Paystack ---
app.get("/api/orders/verify/:reference", async (req, res) => {
  try {
    const { reference } = req.params;

    const paystackRes = await fetch(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
      }
    );
    const paystackData = await paystackRes.json();

    const orders = loadOrders();
    const order = orders.find((o) => o.reference === reference);
    if (!order) {
      return res.status(404).json({ error: "Order not found" });
    }

    if (paystackData.status && paystackData.data.status === "success") {
      order.status = "paid";
      saveOrders(orders);

      // Attempt automatic fulfillment via VTU provider (stub — see fulfillOrder below)
      const fulfillResult = await fulfillOrder(order);
      order.fulfilled = fulfillResult.success;
      order.fulfillmentNote = fulfillResult.message;
      order.deliveredCode = fulfillResult.deliveredCode || null;
      saveOrders(orders);

      return res.json({ status: "paid", order });
    } else {
      order.status = "failed";
      saveOrders(orders);
      return res.json({ status: "failed", order });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not verify payment" });
  }
});

// --- VTU fulfillment via VTpass ---
// Requires VTPASS_BASE_URL, VTPASS_API_KEY, VTPASS_SECRET_KEY in .env.
// If those are missing, orders are just logged for manual fulfillment instead.
function makeVtpassRequestId() {
  // VTpass requires a unique ID shaped like YYYYMMDDHHII + random suffix
  const now = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  const stamp =
    now.getFullYear().toString() +
    pad(now.getMonth() + 1) +
    pad(now.getDate()) +
    pad(now.getHours()) +
    pad(now.getMinutes());
  return stamp + crypto.randomBytes(6).toString("hex");
}

async function fulfillOrder(order) {
  if (!process.env.VTPASS_BASE_URL || !process.env.VTPASS_API_KEY || !process.env.VTPASS_SECRET_KEY) {
    return {
      success: false,
      message: "No VTU provider connected yet — fulfill this order manually.",
    };
  }

  let serviceID, variation_code, billersCode, amount, extraType;

  if (order.type === "airtime") {
    const network = loadAirtimeNetworks().find((n) => n.id === order.networkId);
    if (!network) {
      return { success: false, message: `Unknown airtime network "${order.networkId}" — fulfill manually.` };
    }
    serviceID = network.vtpassServiceID;
    billersCode = order.phone;
    amount = order.amountNaira;
  } else if (order.type === "electricity") {
    const disco = loadElectricityDiscos().find((d) => d.id === order.discoId);
    if (!disco) {
      return { success: false, message: `Unknown disco "${order.discoId}" — fulfill manually.` };
    }
    serviceID = disco.vtpassServiceID;
    billersCode = order.meterNumber;
    variation_code = order.meterType; // "prepaid" or "postpaid"
    amount = order.amountNaira;
  } else if (order.type === "cabletv") {
    const cabletv = loadCableTv();
    const providerConfig = cabletv[order.provider];
    if (!providerConfig) {
      return { success: false, message: `Unknown cable TV provider "${order.provider}" — fulfill manually.` };
    }
    serviceID = providerConfig.vtpassServiceID;
    billersCode = order.smartcardNumber;
    variation_code = order.variationCode;
    amount = order.amountNaira;
  } else if (order.type === "exam") {
    const exams = loadExams();
    const examConfig = exams[order.examType];
    if (!examConfig) {
      return { success: false, message: `Unknown exam service "${order.examType}" — fulfill manually.` };
    }
    serviceID = examConfig.vtpassServiceID;
    billersCode = order.billersCode;
    variation_code = order.variationCode;
    amount = order.amountNaira;
    extraType = "exam"; // marks that we should capture a PIN/token from the response
  } else {
    const plan = loadPlans().find((p) => p.id === order.planId);
    if (!plan || !plan.vtpassServiceID || !plan.vtpassVariationCode || plan.vtpassVariationCode === "REPLACE_ME") {
      return {
        success: false,
        message: `Plan "${order.planId}" is missing a real vtpassVariationCode in plans.json — fulfill manually and fix plans.json.`,
      };
    }
    serviceID = plan.vtpassServiceID;
    billersCode = order.phone;
    variation_code = plan.vtpassVariationCode;
  }

  try {
    const body = {
      request_id: makeVtpassRequestId(),
      serviceID,
      billersCode,
      phone: order.phone,
    };
    if (variation_code) body.variation_code = variation_code;
    if (amount) body.amount = amount;

    const res = await fetch(`${process.env.VTPASS_BASE_URL}/pay`, {
      method: "POST",
      headers: {
        "api-key": process.env.VTPASS_API_KEY,
        "secret-key": process.env.VTPASS_SECRET_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });

    const data = await res.json();
    const delivered =
      data.code === "000" &&
      data.content &&
      data.content.transactions &&
      data.content.transactions.status === "delivered";

    // Electricity prepaid tokens and exam PINs are the actual "product" — capture
    // them so the customer can retrieve their code, not just a "delivered" status.
    let deliveredCode = null;
    if (delivered) {
      if (order.type === "electricity" && data.content.transactions.extras) {
        deliveredCode = data.content.transactions.extras; // e.g. "Token : 1234567890"
      } else if (order.type === "exam") {
        if (data.purchased_code) {
          deliveredCode = data.purchased_code;
        } else if (Array.isArray(data.cards) && data.cards[0]) {
          deliveredCode = `Serial: ${data.cards[0].Serial}, PIN: ${data.cards[0].Pin}`;
        } else if (Array.isArray(data.tokens) && data.tokens[0]) {
          deliveredCode = `Token: ${data.tokens[0]}`;
        }
      }
    }

    return {
      success: delivered,
      message: delivered
        ? "Delivered automatically via VTpass."
        : `VTpass response: ${data.response_description || "unknown error"} — fulfill manually if needed.`,
      deliveredCode,
    };
  } catch (err) {
    console.error("VTpass fulfillment error:", err);
    return { success: false, message: "VTpass request failed — fulfill this order manually." };
  }
}

// --- Logged-in customer: see my own order history ---
app.get("/api/orders/mine", requireAuth, (req, res) => {
  const orders = loadOrders().filter((o) => o.userId === req.userId);
  res.json(orders.reverse());
});

// --- Public: check a single order's status (customer-facing, no admin key needed) ---
// Requires BOTH the phone number and the exact order reference, so a customer
// can only look up an order they actually have the reference for — not browse
// other people's orders.
app.get("/api/orders/status", (req, res) => {
  const { reference, phone } = req.query;
  if (!reference || !phone) {
    return res.status(400).json({ error: "reference and phone are required" });
  }

  const orders = loadOrders();
  const order = orders.find(
    (o) => o.reference === reference && o.phone === phone
  );

  if (!order) {
    return res.status(404).json({ error: "No matching order found. Check your reference and phone number." });
  }

  // Only return safe, customer-facing fields — never email or internal notes.
  res.json({
    reference: order.reference,
    network: order.network,
    label: order.label,
    amountNaira: order.amountNaira,
    phone: order.phone,
    status: order.status,
    fulfilled: order.fulfilled,
    deliveredCode: order.deliveredCode || null,
    createdAt: order.createdAt,
  });
});

// --- Simple admin view of orders (protect with a key) ---
app.get("/api/admin/orders", (req, res) => {
  const key = req.query.key;
  if (!process.env.ADMIN_KEY || key !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: "Unauthorized. Add ?key=YOUR_ADMIN_KEY" });
  }
  res.json(loadOrders().reverse());
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
