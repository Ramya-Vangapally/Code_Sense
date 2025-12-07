const connectDB = require("./db");
const express = require("express");
const cors = require("cors");
const axios = require("axios");
connectDB();
const Login = require("./models/User.js");
const User_history = require("./models/History.js");
const EmailHistory = require("./models/EmailHistory.js");
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
const bcrypt = require("bcrypt");
require("dotenv").config();

const app = express();
app.use(express.json());
const nodemailer = require('nodemailer');
// Re-use Gmail for OTP emails
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// Generate a 6-digit OTP
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}


// Redis Session
const session = require("express-session");
const RedisStore = require("connect-redis")(session);
const Redis = require("ioredis");
const redisClient = new Redis();

// app.set("trust proxy", 1);

// CORS — MUST come BEFORE routes
app.use(cors({
    origin:[ "http://localhost:5502",
        "http://127.0.0.1:5502"],
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

app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: "super-secret-key",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,          
    httpOnly: true,
    sameSite: "lax",
    maxAge: 24 * 60 * 60 * 1000
  }
}));


app.get("/test-session", (req, res) => {
  req.session.test = "working";
  res.json({ session: req.session });
});


function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ message: "Not logged in" });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access only" });
  }
  next();
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
// STEP 1: user submits email+username+password, we send OTP and store data in Redis (temporary)
app.post('/register/request-otp', async (req, res) => {
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

const generateToken = require("./middleware/generateToken");

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

  const token = generateToken(user); // NEW

  req.session.save(() => {
    return res.json({
      token,                      // NEW
      username: user.username,
      email: user.email,
      role: user.role,
      displayName: user.displayName || user.username,
      preferredLanguage: user.preferredLanguage || "Auto"
    });
  });
});

const { OAuth2Client } = require("google-auth-library");
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

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
        password: null // password not needed
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


app.post('/logout', (req,res)=>{
  const createdAt = req.session?.createdAt;
  if (createdAt) {
    const durationSeconds = (Date.now() - createdAt) / 1000;
    // PROMETHEUS: observe session duration here
    sessionHistogram.observe(durationSeconds);
  }

  req.session.destroy(()=>{
    res.clearCookie('connect.sid');
    res.json({ message: "Logged out" });
  });
});

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



app.get('/get-users',requireAdmin, async (req,res) => {
  try{
    const users = await Login.find({}, {password: 0});

    // PROMETHEUS: update active users gauge here
    activeGauge.set(users.length);
    res.json(users);
  } catch(e){
    res.status(404).json({message: e});
  }
})

// Admin: bulk email endpoint
const { queueEmail } = require("./taskQueue");

app.post('/admin/bulk-email', requireAdmin, async (req, res) => {
  const { recipients, subject, message } = req.body;

  if (!subject || !message)
    return res.status(400).json({ message: 'Subject and message required' });

    const adminEmail =
    (req.session?.user?.email) ||
    process.env.ADMIN_EMAIL ||
    process.env.SMTP_USER;


  let recipientList = [];

  if (!recipients || recipients === 'all') {
    const users = await Login.find({}, { email: 1, _id: 0 });
    recipientList = users.map(u => u.email);
  } else if (Array.isArray(recipients)) {
    recipientList = recipients;
  }

  if (recipientList.length === 0)
    return res.status(400).json({ message: "No recipients" });

  recipientList.forEach(email => {
    queueEmail(
      email,
      subject,
      message.replace(/\n/g, "<br>"),
      adminEmail
    );
  });
  // Create an EmailHistory record (pending) so admin UI can show recent sends
  try {
    await EmailHistory.create({
      subject,
      recipients: recipientList.slice(0, 200), // store up to 200 addresses for reference
      recipientsCount: recipientList.length,
      status: 'sent',
      sentBy: req.session.user.username
    });
  } catch (e) {
    console.warn('Failed to record email history:', e?.message || e);
  }

  return res.json({ message: "Emails queued successfully (worker will send them)" });
});

// Return recent email history for admin UI
app.get('/admin/email-history', requireAdmin, async (req, res) => {
  try {
    const rows = await EmailHistory.find({}).sort({ sentAt: -1 }).limit(50).lean();
    res.json(rows);
  } catch (e) {
    res.status(500).json({ message: 'Unable to fetch email history', error: e.message });
  }
});

// Active usage: aggregate number of history actions per day (last 14 days)
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

    // Build continuous series for the last `days` days
    const labels = [];
    const counts = [];
    for (let i = 0; i < days; i++) {
      const d = new Date();
      d.setDate(d.getDate() - (days - 1 - i));
      const key = d.toISOString().slice(0,10);
      labels.push(key);
      const found = agg.find(a=>a._id === key);
      counts.push(found ? found.count : 0);
    }

    res.json({ labels, counts });
  } catch (e) {
    res.status(500).json({ message: 'Unable to compute active usage', error: e.message });
  }
});

// Prometheus metrics endpoint
app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', client.register.contentType);
    res.send(await client.register.metrics());
  } catch (err) {
    res.status(500).end(err.message);
  }
});

app.post("/delete-user",requireAdmin,async(req,res)=>{
  const {username, userId}=req.body;
  const query = userId ? { _id: userId } : { username };
  const user = await Login.findOne(query);
  if(!user) return res.status(404).json({message: "User not found"});
  await Login.deleteOne({ _id: user._id });
  return res.json({message:"user deleted successfully"})
});

app.post('/add-history', async (req, res) => {
  const { username, role, action, language } = req.body;
  try {
    const history = await User_history.create({ username, role, action, language });
    // PROMETHEUS: count admin history actions here
    adminHistoryCounter.inc({ action: action || 'create' });

    res.json({ message: `History saved for: ${username}`, history });
  } catch (e) {
    console.log(e);
    res.status(400).json({ message: "Problem occurred", error: e.message });
  }
});

app.get('/admin-history',requireAdmin, async(req,res)=>{
  try{
    const history = await User_history.find({});
    res.json(history);
  } catch (e){
    res.status(400).json({message: e});
  }
});

app.post('/user-history', requireLogin, async (req,res)=>{
  const username = req.session.user.username;
  try{
    const history = await User_history.find({ username });
    res.json(history);
  }catch(e){
    res.status(400).json({message: e});
  }
});


app.post("/api/explain", async (req, res) => {
  const { code, language } = req.body;

  if (!code || !code.trim()) {
    return res.status(400).json({ message: "Code snippet is required" });
  }

  const prompt = `
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
        temperature: 0.4,
        max_completion_tokens: 1500
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

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} 🚀`);
});
