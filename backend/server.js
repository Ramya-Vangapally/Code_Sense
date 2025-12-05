const connectDB = require("./db");
const express = require("express");
const cors = require("cors");
const axios = require("axios");
connectDB();
const Login = require("./models/User.js");
const User_history = require("./models/History.js");
const EmailHistory = require("./models/EmailHistory.js");
const client = require('prom-client');
// Prometheus counters for languages and user actions
const languageCounter = new client.Counter({
  name: 'app_language_requests_total',
  help: 'Total number of requests per language (from history)',
  labelNames: ['language']
});
const userActionsCounter = new client.Counter({
  name: 'app_user_actions_total',
  help: 'Total number of user actions recorded',
  labelNames: ['username']
});
const bcrypt = require("bcrypt");
require("dotenv").config();

const app = express();
app.use(express.json());
const nodemailer = require('nodemailer');

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
app.set("trust proxy", 1);  // <-- IMPORTANT for 127.0.0.1 to work

app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: "super-secret-key",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,          // because you're on http://localhost
    httpOnly: true,
    sameSite: "lax",        // or just remove this line (default is Lax)
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


app.post('/register', async (req, res) => {
  const { email, username, password } = req.body;
  
  if (!email || !username || !password) {
    return res.status(400).json({ message: "Email, username, and password are required" });
  }
  
  try {
    // Check if email or username already exists
    const existingUser = await Login.findOne({ 
      $or: [{ email: email.toLowerCase() }, { username }] 
    });
    if (existingUser) {
      return res.status(400).json({ message: "Email or username already registered" });
    }
    
    const hashed = await bcrypt.hash(password, 10);
    const user = await Login.create({ 
      email: email.toLowerCase(),
      username, 
      password: hashed, 
      role: "user" 
    });
    res.json({ message: "Account created successfully", user: { email: user.email, username: user.username, role: user.role } });
  } catch (e) {
    console.log(e);
    res.status(400).json({ message: "Unable to create account", error: e.message });
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
      password: hashed,
      role: role === "admin" ? "admin" : "user"
    });

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
    role: user.role
  };

  const token = generateToken(user); // NEW

  req.session.save(() => {
    return res.json({
      token,                      // NEW
      username: user.username,
      email: user.email,
      role: user.role
    });
  });
});



app.post('/logout', (req,res)=>{
  req.session.destroy(()=>{
    res.clearCookie('connect.sid');
    res.json({ message: "Logged out" });
  });
});

app.get('/me', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json(null);
  }
  return res.json(req.session.user); // { username, role }
});



app.get('/get-users',requireAdmin, async (req,res) => {
  try{
    const users = await Login.find({}, {password: 0});
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

// Prometheus metrics
client.collectDefaultMetrics();
app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', client.register.contentType);
    res.end(await client.register.metrics());
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
    // Update Prometheus counters
    try{
      const lang = (language || 'unknown').toString();
      languageCounter.inc({ language: lang }, 1);
      userActionsCounter.inc({ username: username }, 1);
    }catch(e){ console.warn('metric update failed', e); }

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
