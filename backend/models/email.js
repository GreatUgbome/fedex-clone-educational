const mongoose = require('mongoose');

const EmailSchema = new mongoose.Schema({
    recipient: String,
    subject: String,
    message: String,
    status: { type: String, enum: ['sent', 'draft'], default: 'sent' },
    timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Email', EmailSchema);
