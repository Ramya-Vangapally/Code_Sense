const connectDB=require("./db")
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
connectDB();
const app = express();
app.use(express.json());
app.use(cors());

