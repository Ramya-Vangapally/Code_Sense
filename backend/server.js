const connectDB = require("./db");
const express = require("express");
const cors = require("cors");
const axios = require("axios");
connectDB();
const Login = require("./models/User.js");
const User_history = require("./models/History.js");
const EmailHistory = require("./models/EmailHistory.js");
const ModelSettings = require("./models/ModelSettings.js");
const client = require('prom-client');

client.collectDefaultMetrics({ prefix: 'code3sense_' });

const loginCounter = new client.Counter({
  name: 'code3sense_user_logins_total',
  help: 'Total number of user logins',
  labelNames: ['user_type'],
});

const registrationCounter = new client.Counter({
  name: 'code3sense_registration_total',
  help: 'Total number of successful registrations',
});

const activeGauge = new client.Gauge({
  name: 'code3sense_active_users',
  help: 'Current number of active users',
});

const sessionHistogram = new client.Histogram({
  name: 'code3sense_session_duration_seconds',
  help: 'Observed session durations in seconds',
  buckets: [5, 15, 30, 60, 120, 300, 600],
});

const adminHistoryCounter = new client.Counter({
  name: 'code3sense_admin_history_total',
  help: 'Total number of admin history actions',
  labelNames: ['action'],
});
// Load environment variables BEFORE any service initialization
require("dotenv").config();

const bcrypt = require("bcrypt");

const app = express();
app.use(express.json());
const nodemailer = require('nodemailer');
// Configure Gmail SMTP with SSL port 465 (more reliable for Render)
const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,  // Crucial for Render
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
    connectionTimeout: 10000
});

// Generate a 6-digit OTP
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ===== REDIS CLIENT INITIALIZATION =====
// Single Redis client instance - ONLY via Render internal network
const session = require("express-session");
const RedisStore = require("connect-redis")(session);
const Redis = require("ioredis");
const Bull = require("bull");

let redisReady = false;

// Validate Redis URL is set from environment (Render internal)
if (!process.env.REDIS_URL) {
  console.error("❌ REDIS_URL environment variable is NOT SET");
  console.error("Cannot proceed without Redis connection URL from Render");
  process.exit(1);
}

console.log("✓ Redis URL configured from environment");

// Initialize Redis for Render internal network
// Force IPv4 to avoid IPv6 AggregateError on Render
const redisClient = new Redis(process.env.REDIS_URL, { family: 4 });

// Redis connection event handlers
redisClient.on("connect", () => {
  console.log("✓ Redis: Connected to Render Valkey");
});

redisClient.on("ready", () => {
  console.log("✓ Redis: Connection ready and authenticated");
  redisReady = true;
});

redisClient.on("error", (err) => {
  console.error("❌ Redis connection error:", err.message);
  console.error("   Code:", err.code);
  redisReady = false;
});

redisClient.on("close", () => {
  console.warn("⚠ Redis connection closed");
  redisReady = false;
});

// ===== BULL EMAIL QUEUE SETUP =====
// Create email queue using Redis (with IPv4 support for Render)
const emailQueue = new Bull('email-queue', {
  redis: {
    host: process.env.REDIS_URL ? new URL(process.env.REDIS_URL).hostname : 'localhost',
    port: process.env.REDIS_URL ? new URL(process.env.REDIS_URL).port || 6379 : 6379,
    password: process.env.REDIS_URL ? new URL(process.env.REDIS_URL).password : undefined,
    family: 4  // Force IPv4 for Render compatibility
  }
});

// Define email queue worker
emailQueue.process(async (job) => {
  const { email, subject, message } = job.data;
  
  try {
    await transporter.sendMail({
      from: process.env.SMTP_USER,
      to: email,
      subject: subject,
      text: message,
      html: `<p>${message.replace(/\n/g, '<br>')}</p>`
    });
    
    console.log(`✓ Email sent to ${email}`);
    return { success: true, email };
  } catch (error) {
    console.error(`❌ Failed to send email to ${email}:`, error.message);
    throw error; // Retry the job
  }
});

// Email queue event handlers
emailQueue.on('completed', (job) => {
  console.log(`Email job ${job.id} completed`);
});

emailQueue.on('failed', (job, error) => {
  console.error(`Email job ${job.id} failed:`, error.message);
});

// app.set("trust proxy", 1);

// CORS — MUST come BEFORE routes
app.use(cors({
    origin:[ 
        "http://localhost:5502",
        "http://127.0.0.1:5502",
        "https://code-sense-one.vercel.app"
    ],
    credentials: true,
}));

// // Required to allow browser to store session cookie
// app.use((req, res, next) => {
//     res.header("Access-Control-Allow-Origin", "http://localhost:5502");
//     res.header("Access-Control-Allow-Credentials", "true");
//     res.header("Access-Control-Allow-Headers", "Content-Type");
//     next();
// });

// Session config
app.set("trust proxy", 1);

// Function to register all session-dependent routes
// Called AFTER session middleware is initialized
function registerSessionRoutes(app) {
  // Test session endpoint
  app.get("/test-session", (req, res) => {
    req.session.test = "working";
    res.json({ session: req.session });
  });

  // STEP 1: user submits email+username+password, we send OTP and store data in Redis (temporary)
  app.post('/register/request-otp', async (req, res) => {
    // Guard: ensure Redis is ready before using it
    if (!redisReady) {
      return res.status(503).json({ message: "Redis not ready, try again" });
    }

    const { email, username, password } = req.body;

    if (!email || !username || !password) {
      return res.status(400).json({ message: "Email, username, and password are required" });
    }

    try {
      // Check if already registered
      const existingUser = await Login.findOne({
        $or: [{ email: email.toLowerCase() }, { username }]
      });
      if (existingUser) {
        return res.status(400).json({ message: "Email or username already registered" });
      }

      const hashed = await bcrypt.hash(password, 10);
      const otp = generateOtp();

      const key = `pending_user:${email.toLowerCase()}`;

      // Store pending user + OTP in Redis for 5 minutes
      await redisClient.set(
        key,
        JSON.stringify({
          email: email.toLowerCase(),
          username,
          passwordHash: hashed,
          otp
        }),
        'EX',
        300 // 300 seconds = 5 minutes
      );

      // Send OTP email
      await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: email,
        subject: 'Code Sense – Email Verification OTP',
        html: `
          <p>Hi ${username || ''},</p>
          <p>Your verification OTP is: <b>${otp}</b></p>
          <p>This code will expire in 5 minutes.</p>
        `
      });

      return res.json({ message: "OTP sent to your email. Please verify to complete signup." });

    } catch (e) {
      console.log(e);
      return res.status(500).json({ message: "Unable to send OTP", error: e.message });
    }
  });

  // STEP 2: user sends email+username+otp, we verify and create account in Mongo
  app.post('/register', async (req, res) => {
    // Guard: ensure Redis is ready before using it
    if (!redisReady) {
      return res.status(503).json({ message: "Redis not ready, try again" });
    }

    const { email, username, otp } = req.body;

    if (!email || !username || !otp) {
      return res.status(400).json({ message: "Email, username, and OTP are required" });
    }

    try {
      const key = `pending_user:${email.toLowerCase()}`;
      const pendingJson = await redisClient.get(key);

      if (!pendingJson) {
        return res.status(400).json({ message: "No pending signup found or OTP expired. Please sign up again." });
      }

      const pending = JSON.parse(pendingJson);

      // Ensure email + username match what we stored
      if (
        pending.email !== email.toLowerCase() ||
        pending.username !== username
      ) {
        return res.status(400).json({ message: "Signup details do not match pending request." });
      }

      if (pending.otp !== otp) {
        return res.status(400).json({ message: "Invalid OTP." });
      }

      // Extra safety: make sure not already created
      const existingUser = await Login.findOne({
        $or: [{ email: email.toLowerCase() }, { username }]
      });
      if (existingUser) {
        await redisClient.del(key);
        return res.status(400).json({ message: "Email or username already registered" });
      }

      // Create user in Mongo using stored hashed password
      const user = await Login.create({
        email: pending.email,
        username: pending.username,
        displayName: pending.username,
        password: pending.passwordHash,
        preferredLanguage: "Auto",
        role: "user"
      });

      // Clear temp data
      await redisClient.del(key);

      // PROMETHEUS: increment registration counter here
      registrationCounter.inc();

      return res.json({
        message: "Account created successfully",
        user: {
          email: user.email,
          username: user.username,
          role: user.role
        }
      });

    } catch (e) {
      console.log(e);
      return res.status(500).json({ message: "Unable to create account", error: e.message });
    }
  });

  // Login endpoint
  app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = await Login.findOne({ username });
    if (!user) return res.status(404).json({ message: "Username not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Incorrect password" });

    // Keep your Redis session
    req.session.user = {
      username: user.username,
      email: user.email,
      role: user.role,
      displayName: user.displayName || user.username,
      preferredLanguage: user.preferredLanguage || "Auto"
    };

    // PROMETHEUS: increment login counter here
    loginCounter.inc({ user_type: user.role || 'user' }, 1);
    req.session.createdAt = Date.now();

    const token = generateToken(user);

    req.session.save(() => {
      return res.json({
        token,
        username: user.username,
        email: user.email,
        role: user.role,
        displayName: user.displayName || user.username,
        preferredLanguage: user.preferredLanguage || "Auto"
      });
    });
  });

  // Google OAuth endpoint
  app.post("/auth/google", async (req, res) => {
    const { credential } = req.body; // Google JWT

    if (!credential) {
      return res.status(400).json({ message: "Missing Google credential" });
    }

    try {
      // 1. Verify Google token
      const ticket = await googleClient.verifyIdToken({
        idToken: credential,
        audience: process.env.GOOGLE_CLIENT_ID
      });

      const payload = ticket.getPayload();
      const { sub: googleId, email, name, picture } = payload;
      const derivedUsername = (email && email.split("@")[0]) || googleId;
      const derivedDisplayName = name || derivedUsername;

      // 2. Check if user already exists
      let user = await Login.findOne({ email });

      // 3. If new → create user
      if (!user) {
        user = await Login.create({
          email,
          username: derivedUsername,
          displayName: derivedDisplayName,
          preferredLanguage: "Auto",
          googleId,
          picture,
          role: "user",
          password: null
        });
      }

      // 4. Create session in Redis
      req.session.user = {
        username: user.username,
        email: user.email,
        role: user.role,
        displayName: user.displayName || user.username,
        preferredLanguage: user.preferredLanguage || "Auto"
      };

      // 5. Create your own JWT
      const token = generateToken(user);

      return res.json({
        message: "Google login successful",
        token,
        username: user.username,
        email: user.email,
        role: user.role,
        displayName: user.displayName || user.username,
        preferredLanguage: user.preferredLanguage || "Auto"
      });

    } catch (err) {
      console.error("Google auth error:", err);
      return res.status(400).json({ message: "Google authentication failed" });
    }
  });

  // Logout endpoint
  app.post('/logout', (req, res) => {
    const createdAt = req.session?.createdAt;
    if (createdAt) {
      const durationSeconds = (Date.now() - createdAt) / 1000;
      sessionHistogram.observe(durationSeconds);
    }

    req.session.destroy(() => {
      res.clearCookie('connect.sid');
      res.json({ message: "Logged out" });
    });
  });

  // Get current user info
  app.get('/me', async (req, res) => {
    if (!req.session.user) {
      return res.status(401).json(null);
    }

    try {
      const userDoc = await loadUserFromSession(req);
      if (!userDoc) {
        return res.status(404).json({ message: "User not found" });
      }
      return res.json(req.session.user);
    } catch (err) {
      console.error('session lookup error', err);
      return res.status(500).json({ message: "Unable to load session" });
    }
  });

  // User settings routes
  app.get('/user/settings', requireLogin, async (req, res) => {
    try {
      const user = await loadUserFromSession(req);
      if (!user) return res.status(404).json({ message: "User not found" });

      return res.json({
        username: user.username,
        email: user.email,
        displayName: user.displayName || user.username,
        preferredLanguage: user.preferredLanguage || "Auto"
      });
    } catch (err) {
      console.error('settings fetch error', err);
      return res.status(500).json({ message: "Unable to load settings" });
    }
  });

  app.patch('/user/settings', requireLogin, async (req, res) => {
    const { displayName, preferredLanguage, newPassword } = req.body || {};

    try {
      const user = await loadUserFromSession(req);
      if (!user) return res.status(404).json({ message: "User not found" });

      if (typeof displayName === 'string' && displayName.trim()) {
        user.displayName = displayName.trim();
      }

      if (typeof preferredLanguage === 'string' && preferredLanguage.trim()) {
        user.preferredLanguage = preferredLanguage.trim();
      }

      if (newPassword) {
        if (typeof newPassword !== 'string' || newPassword.length < 6) {
          return res.status(400).json({ message: "Password must be at least 6 characters" });
        }
        user.password = await bcrypt.hash(newPassword, 10);
      }

      await user.save();

      req.session.user.displayName = user.displayName || user.username;
      req.session.user.preferredLanguage = user.preferredLanguage || "Auto";
      req.session.user.email = user.email;

      return res.json({
        message: "Settings updated",
        user: {
          username: user.username,
          email: user.email,
          displayName: user.displayName || user.username,
          preferredLanguage: user.preferredLanguage || "Auto"
        }
      });
    } catch (err) {
      console.error('settings update error', err);
      return res.status(500).json({ message: "Unable to save settings" });
    }
  });

  // Admin model settings routes
  app.get('/admin/model-settings', requireAdmin, async (req, res) => {
    try {
      const settings = await getOrCreateModelSettings();
      return res.json(serializeModelSettings(settings));
    } catch (err) {
      console.error('model settings fetch error', err);
      return res.status(500).json({ message: 'Unable to load model settings' });
    }
  });

  app.patch('/admin/model-settings', requireAdmin, async (req, res) => {
    try {
      const settings = await getOrCreateModelSettings();
      const { explanationLength, temperature, maxTokens, enableHighlighting } = req.body || {};

      if (explanationLength && EXPLANATION_LENGTH_HINTS[explanationLength]) {
        settings.explanationLength = explanationLength;
      }

      if (typeof temperature !== 'undefined') {
        settings.temperature = parseFloat(clampNumber(temperature, 0, 1).toFixed(2));
      }

      if (typeof maxTokens !== 'undefined') {
        settings.maxTokens = Math.round(clampNumber(maxTokens, 50, 2000));
      }

      if (typeof enableHighlighting !== 'undefined') {
        settings.enableHighlighting = coerceBoolean(enableHighlighting);
      }

      settings.updatedBy = req.session.user?.username || 'admin';
      settings.updatedAt = new Date();
      await settings.save();

      return res.json({
        message: 'Model settings updated',
        settings: serializeModelSettings(settings)
      });
    } catch (err) {
      console.error('model settings update error', err);
      return res.status(500).json({ message: 'Unable to update model settings' });
    }
  });

  // Get all users
  app.get('/get-users', requireAdmin, async (req, res) => {
    try {
      const users = await Login.find({}, { password: 0 });
      activeGauge.set(users.length);
      res.json(users);
    } catch (e) {
      res.status(404).json({ message: e });
    }
  });

  // Bulk email endpoint
  app.post('/admin/bulk-email', requireAdmin, async (req, res) => {
    const { subject, message, recipients } = req.body;

    // Validate required fields
    if (!subject || !message) {
      return res.status(400).json({ message: "Subject and message are required." });
    }

    try {
      let emailList = [];

      // Logic: Check if specific recipients were provided
      if (recipients && Array.isArray(recipients) && recipients.length > 0) {
        // Targeted send: Use provided recipient list
        emailList = recipients.filter(email => email && email.includes('@'));
        console.log(`📧 Targeted send to ${emailList.length} specific users`);
      } else {
        // Bulk send: Fetch all users from database
        const users = await Login.find({}, 'email');
        emailList = users
          .map(u => u.email)
          .filter(e => e && e.includes('@'));
        console.log(`📧 Bulk send to all ${emailList.length} users`);
      }

      if (emailList.length === 0) {
        return res.status(400).json({ message: "No valid email addresses found." });
      }

      // Add each email to the queue
      for (const email of emailList) {
        await emailQueue.add(
          { email, subject, message },
          { 
            attempts: 3,           // Retry up to 3 times
            backoff: {
              type: 'exponential',
              delay: 2000          // Start with 2 second delay
            }
          }
        );
      }

      console.log(`✓ Added ${emailList.length} emails to queue`);

      // Save email history for admin dashboard
      try {
        await EmailHistory.create({
          subject: subject,
          recipients: emailList.length + " users",  // Save count like "5 users"
          sentDate: new Date(),
          status: "Sent"
        });
        console.log(`✓ Email history saved for ${emailList.length} users`);
      } catch (historyErr) {
        console.error("History Save Error:", historyErr.message);
        // Don't fail the whole request if history save fails
      }

      // Return immediately (don't wait for emails to send)
      res.json({ 
        message: `${emailList.length} emails added to queue and will be sent shortly!`,
        count: emailList.length
      });

    } catch (error) {
      console.error("❌ Bulk Email Queue Error:", error.message);
      res.status(500).json({ message: "Failed to queue emails. Check server logs." });
    }
  });

  // Email history endpoint
  app.get('/admin/email-history', requireAdmin, async (req, res) => {
    try {
      const rows = await EmailHistory.find({}).sort({ sentAt: -1 }).limit(50).lean();
      res.json(rows);
    } catch (e) {
      res.status(500).json({ message: 'Unable to fetch email history', error: e.message });
    }
  });

  // Active usage endpoint
  app.get('/admin/active-usage', requireAdmin, async (req, res) => {
    try {
      const days = parseInt(req.query.days || '14', 10);
      const since = new Date();
      since.setDate(since.getDate() - days + 1);

      const agg = await User_history.aggregate([
        { $match: { time: { $gte: since } } },
        { $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$time" } },
          count: { $sum: 1 }
        }},
        { $sort: { _id: 1 } }
      ]);

      const labels = [];
      const counts = [];
      for (let i = 0; i < days; i++) {
        const d = new Date();
        d.setDate(d.getDate() - (days - 1 - i));
        const key = d.toISOString().slice(0, 10);
        labels.push(key);
        const found = agg.find(a => a._id === key);
        counts.push(found ? found.count : 0);
      }

      res.json({ labels, counts });
    } catch (e) {
      res.status(500).json({ message: 'Unable to compute active usage', error: e.message });
    }
  });

  // Delete user endpoint
  app.post("/delete-user", requireAdmin, async (req, res) => {
    const { username, userId } = req.body;
    const query = userId ? { _id: userId } : { username };
    const user = await Login.findOne(query);
    if (!user) return res.status(404).json({ message: "User not found" });
    await Login.deleteOne({ _id: user._id });
    return res.json({ message: "user deleted successfully" });
  });

  // Admin history endpoint
  app.get('/admin-history', requireAdmin, async (req, res) => {
    try {
      const history = await User_history.find({});
      res.json(history);
    } catch (e) {
      res.status(400).json({ message: e });
    }
  });

  // User history endpoint
  app.post('/user-history', requireLogin, async (req, res) => {
    const username = req.session.user.username;
    try {
      const history = await User_history.find({ username });
      res.json(history);
    } catch (e) {
      res.status(400).json({ message: e });
    }
  });

  // Save new history entry (code explanation action)
  app.post('/add-history', async (req, res) => {
    const { username, action, language, role } = req.body;

    // Validate required fields
    if (!username || !action || !language || !role) {
      return res.status(400).json({ 
        message: "Missing required fields: username, action, language, role" 
      });
    }

    try {
      const historyEntry = new User_history({
        username,
        action,
        language,
        role,
        time: new Date()
      });

      await historyEntry.save();

      res.status(201).json({
        success: true,
        message: "History entry saved successfully",
        data: historyEntry
      });
    } catch (error) {
      console.error("Error saving history:", error);
      res.status(500).json({
        message: "Failed to save history",
        error: error.message
      });
    }
  });

  // Admin: create user endpoint
  app.post('/admin/create-user', requireAdmin, async (req, res) => {
    const { email, username, password, role } = req.body;

    if (!email || !username || !password) {
      return res.status(400).json({ message: "Email, username, and password are required" });
    }

    try {
      const existingUser = await Login.findOne({
        $or: [{ email: email.toLowerCase() }, { username }]
      });
      if (existingUser) {
        return res.status(400).json({ message: "Email or username already registered" });
      }

      const hashed = await bcrypt.hash(password, 10);
      const newUser = await Login.create({
        email: email.toLowerCase(),
        username,
        displayName: username,
        password: hashed,
        preferredLanguage: "Auto",
        role: role === "admin" ? "admin" : "user"
      });

      // PROMETHEUS: increment registration counter here
      registrationCounter.inc();

      return res.json({
        message: "User created successfully",
        user: {
          username: newUser.username,
          email: newUser.email,
          role: newUser.role
        }
      });
    } catch (e) {
      console.log(e);
      res.status(500).json({ message: "Unable to create user", error: e.message });
    }
  });
}

function requireLogin(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ message: "Not logged in" });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access only" });
  }
  next();
}

const EXPLANATION_LENGTH_HINTS = {
  concise: "Keep explanations concise (around 50-100 words) while covering the key ideas.",
  medium: "Provide a balanced explanation (roughly 100-200 words) with key details and rationale.",
  detailed: "Provide a thorough explanation (200+ words) that walks through the code step-by-step."
};

async function getOrCreateModelSettings() {
  let doc = await ModelSettings.findOne();
  if (!doc) {
    doc = await ModelSettings.create({});
  }
  return doc;
}

function serializeModelSettings(doc) {
  if (!doc) return null;
  return {
    explanationLength: doc.explanationLength,
    temperature: doc.temperature,
    maxTokens: doc.maxTokens,
    enableHighlighting: doc.enableHighlighting,
    updatedBy: doc.updatedBy || null,
    updatedAt: doc.updatedAt || null
  };
}

function clampNumber(value, min, max) {
  const num = typeof value === 'number' ? value : parseFloat(value);
  if (Number.isNaN(num)) return min;
  return Math.min(max, Math.max(min, num));
}

function coerceBoolean(value) {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    return value.toLowerCase() === 'true' || value === '1' || value.toLowerCase() === 'yes';
  }
  return Boolean(value);
}

async function loadUserFromSession(req) {
  const sessionUser = req.session?.user;
  if (!sessionUser) return null;

  const query = sessionUser.email
    ? { email: sessionUser.email }
    : sessionUser.username
    ? { username: sessionUser.username }
    : null;

  if (!query) return null;

  const userDoc = await Login.findOne(query);
  if (userDoc) {
    req.session.user.email = userDoc.email;
    req.session.user.username = userDoc.username;
    req.session.user.displayName = userDoc.displayName || userDoc.username;
    req.session.user.preferredLanguage = userDoc.preferredLanguage || "Auto";
  }

  return userDoc;
}

// Delay session middleware initialization until Redis is ready
redisClient.once("ready", () => {
  console.log("Initializing express-session middleware...");
  
  app.use(session({
    store: new RedisStore({ client: redisClient }),
    secret:  process.env.JWT_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true,           // REQUIRED for Render (HTTPS)
      httpOnly: true,
      sameSite: 'none',       // REQUIRED for Vercel -> Render communication
      maxAge: 24 * 60 * 60 * 1000
    }
  }));
  
  console.log("express-session middleware initialized with Redis store");
  
  // Register all session-dependent routes AFTER middleware is initialized
  registerSessionRoutes(app);
});

const generateToken = require("./middleware/generateToken");

const { OAuth2Client } = require("google-auth-library");
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Non-session route (no req.session used)
app.post("/api/explain", async (req, res) => {
  const { code, language } = req.body;

  if (!code || !code.trim()) {
    return res.status(400).json({ message: "Code snippet is required" });
  }

  let modelSettings = null;
  try {
    modelSettings = await getOrCreateModelSettings();
  } catch (err) {
    console.warn('model settings unavailable, using defaults', err?.message || err);
  }

  const lengthKey = modelSettings?.explanationLength || 'concise';
  const lengthHint = EXPLANATION_LENGTH_HINTS[lengthKey] || EXPLANATION_LENGTH_HINTS.concise;
  const highlightHint = modelSettings?.enableHighlighting
    ? 'Use fenced Markdown code blocks with language identifiers when you include code snippets.'
    : '';

  const temperature = clampNumber(modelSettings?.temperature ?? 0.4, 0, 1);
  const maxTokens = Math.round(clampNumber(modelSettings?.maxTokens ?? 500, 50, 2000));

  const prompt = `
${lengthHint}
${highlightHint}

Explain this ${language} code in simple steps.
Break down logic and purpose clearly for a beginner.

Code:
${code}
`;

  try {
    const response = await axios.post(
      "https://api.groq.com/openai/v1/chat/completions",
      {
        model: "openai/gpt-oss-20b",
        messages: [
          { role: "user", content: prompt }
        ],
        temperature,
        max_completion_tokens: maxTokens
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
          "Content-Type": "application/json"
        }
      }
    );

    return res.json({
      explanation: response.data.choices[0].message.content
    });

  } catch (err) {
    console.error("Groq API ERROR:", err.response?.data || err.message);
    return res.status(500).json({
      message: "Groq API Failed",
      error: err.response?.data || err.message
    });
  }
});

const PORT = process.env.PORT || 5000;

// Prometheus metrics endpoint (doesn't require session)
app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', client.register.contentType);
    res.send(await client.register.metrics());
  } catch (err) {
    res.status(500).end(err.message);
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} 🚀`);
});
