const connectDB=require("./db")
const express = require('express');
const cors = require('cors');
const axios = require('axios'); 
connectDB();
const Login = require('./models/User.js');
const bcrypt = require('bcrypt');
const { JsonWebTokenError } = require("jsonwebtoken");
const app = express();
require("dotenv").config();
const GROQ_KEY = process.env.GROQ_API_KEY;

app.use(express.json());
app.use(cors());

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
  return res.json({
    username: user.username,
    role: user.role
  });
});

app.get('/get-users', async (req,res) => {
  try{
    const users = await Login.find({}, {password: 0});
    res.json(users);
  } catch(e){
    res.status(404).json({message: e});
  }
})

app.post("/delete-user",async(req,res)=>{
  const {username}=req.body
  const user=await Login.findOne({username})
  if(!user) return res.status(404).json({message: "User not found"});
  await Login.deleteOne({username})
  return res.json({message:"user deleted successfully"})
});

app.post('/admin-history', async(req,res)=>{
  try{
    const history = await User_history.find({});
    res.json(history);
  } catch (e){
    res.status(400).json({message: e});
  }
});

app.post('/user-history', async(req,res)=>{
  const {username} = req.body;
  try{
    const history = await User_history.find({username});
    res.json(history);
  } catch (e){
    res.status(400).json({message: e});
  }
})

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
