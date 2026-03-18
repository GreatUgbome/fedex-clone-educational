const mongoose = require('mongoose');

const FeedbackSchema = new mongoose.Schema({
    rating: Number,
    comment: String,
    username: String,
    timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Feedback', FeedbackSchema);
