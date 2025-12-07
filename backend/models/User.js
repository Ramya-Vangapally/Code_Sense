const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  username: { type: String },
  displayName: { type: String },
  email: { 
    type: String, 
    required: true,
    unique: true, 
    lowercase: true,
    match: [/^\S+@\S+\.\S+$/, "Invalid email format"]
  },

  // Password only required for email-password users
  password: { type: String },

  preferredLanguage: { type: String, default: "Auto" },

  role: { type: String, default: "user" },

  // NEW FIELDS FOR GOOGLE USERS
  googleId: { type: String, unique: true, sparse: true },
  picture: { type: String }
});

module.exports = mongoose.model("Login", UserSchema, "login");
