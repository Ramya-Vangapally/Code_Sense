const mongoose = require('mongoose');

const ModelSettingsSchema = new mongoose.Schema({
  explanationLength: {
    type: String,
    enum: ['concise', 'medium', 'detailed'],
    default: 'concise'
  },
  temperature: {
    type: Number,
    min: 0,
    max: 1,
    default: 0.7
  },
  maxTokens: {
    type: Number,
    min: 50,
    max: 2000,
    default: 500
  },
  enableHighlighting: {
    type: Boolean,
    default: false
  },
  updatedBy: { type: String },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

module.exports = mongoose.model('ModelSettings', ModelSettingsSchema, 'modelSettings');
