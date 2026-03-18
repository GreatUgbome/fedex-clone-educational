const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, unique: true, sparse: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' },
    resetToken: String,
    resetTokenExpiry: Date,
    isVerified: { type: Boolean, default: false },
    verificationToken: String
});

module.exports = mongoose.model('User', UserSchema);
