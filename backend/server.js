const connectDB=require("./db")
const express = require('express');
const cors = require('cors');
connectDB();
const User = require('./models/User.js');
const bcrypt = require('bcrypt');
const app = express();
app.use(express.json());
app.use(cors());

app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  try {
    const user = await User.create({ username, password: hashed, role });
    res.json({ message: "User created", user });
  } catch (e) {
    console.log(e);
    res.status(400).json({ message: "Problem occured", error: e.message });
  }
});

