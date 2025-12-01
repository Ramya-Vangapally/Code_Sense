const connectDB = require("./db");
const express = require("express");
const cors = require("cors");
const axios = require("axios");
connectDB();
const Login = require("./models/User.js");
const User_history = require("./models/History.js");
const bcrypt = require("bcrypt");
require("dotenv").config();

const app = express();
app.use(express.json());

// Redis Session
const session = require("express-session");
const RedisStore = require("connect-redis")(session);
const Redis = require("ioredis");
const redisClient = new Redis();

// app.set("trust proxy", 1);

// CORS — MUST come BEFORE routes
app.use(cors({
    origin: "http://localhost:5502",
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
  const { username, password, role } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  try {
    const user = await Login.create({ username, password: hashed, role });
    res.json({ message: "User created", user });
  } catch (e) {
    console.log(e);
    res.status(400).json({ message: "Problem occured", error: e.message });
  }
});

app.post('/login', async (req, res)=> {
  const { username, password } = req.body;
  const user = await Login.findOne({username});
  if(!user) return res.status(404).json({message: "User not found"});
  const isMatch = await bcrypt.compare(password, user.password);
  if(!isMatch) return res.status(400).json({message: "Wrong password"});
  req.session.user = {
    username: user.username,
    role: user.role
  };
  // Explicitly save session
  req.session.save((err) => {
    if (err) {
      return res.status(500).json({ message: "Session save failed" });
    }
    return res.status(200).json({
      username: user.username,
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

app.post("/delete-user",requireAdmin,async(req,res)=>{
  const {username}=req.body
  const user=await Login.findOne({username})
  if(!user) return res.status(404).json({message: "User not found"});
  await Login.deleteOne({username})
  return res.json({message:"user deleted successfully"})
});

app.post('/add-history', async (req, res) => {
  const { username, role, action, language } = req.body;
  try {
    const history = await User_history.create({ username, role, action, language });
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
