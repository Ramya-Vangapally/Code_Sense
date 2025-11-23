const connectDB=require("./db")
const express = require('express');
const cors = require('cors');
connectDB();
const Login = require('./models/User.js');
const bcrypt = require('bcrypt');
const { JsonWebTokenError } = require("jsonwebtoken");
const app = express();
require("dotenv").config();
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
})
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} 🚀`);
});
