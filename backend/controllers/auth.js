const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const User = require('../models/user');
const { generateEmailTemplate, sendStatusEmail } = require('../utils/email');
const { logActivity } = require('../utils/activity');
const nodemailer = require('nodemailer');
require('dotenv').config();

const BASE_URL = process.env.BASE_URL || (process.env.RENDER ? 'https://fedex-37e89.web.app' : `http://localhost:5002`);

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});


const { validationResult } = require('express-validator');

const login = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        if (!user.isVerified) return res.status(403).json({ error: 'Please verify your email before logging in.' });
        await logActivity(user.username, 'Login', 'User logged in');
        res.json({ username: user.username, role: user.role, email: user.email, _id: user._id });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
};

const signup = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { username, password, email } = req.body;
    
    // Check if username already exists
    const existingUsername = await User.findOne({ username });
    if (existingUsername) {
        return res.status(400).json({ error: 'Username already exists' });
    }
    
    // Check if email already exists
    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
        return res.status(400).json({ error: 'Email already registered' });
    }

    // Require strong passwords
    if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9])(?=.{8,})/.test(password)) {
        return res.status(400).json({ error: 'Password must be at least 8 characters and contain uppercase, lowercase, numbers, and special characters.' });
    }
    
    const verificationToken = crypto.randomBytes(20).toString('hex');
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword, email, role: 'user', isVerified: false, verificationToken });
    await newUser.save();
    
    await logActivity(username, 'Signup', 'Account created');

    // Send Verification Email
    const verifyLink = `${BASE_URL}/?verifyToken=${verificationToken}`;
    const mailOptions = {
        from: '"Shipping App Support" <support@demo.local>',
        to: email,
        subject: 'Welcome! Please Verify Your Email',
        html: generateEmailTemplate(
            'Welcome to our Shipping App!',
            'Thank you for signing up. To start shipping and tracking packages, please verify your email address.',
            'Verify Email Address',
            verifyLink
        )
    };

    transporter.sendMail(mailOptions, (err) => {
        if (err) console.log('Email error:', err);
    });

    // Generate JWT-like token for signup response (simple base64 encoding of username+timestamp)
    const signupToken = Buffer.from(`${username}:${Date.now()}`).toString('base64');
    
    // Require verification before login, but provide feedback token for frontend use
    res.json({ 
        message: 'Signup successful! Please check your email to verify your account.',
        token: signupToken,
        requiresVerification: true
    });
};

const forgotPassword = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User with this email not found' });

    // Generate Token
    const token = crypto.randomBytes(20).toString('hex');
    user.resetToken = token;
    user.resetTokenExpiry = Date.now() + 3600000; // 1 hour
    await user.save();

    // Send Email
    const resetLink = `${BASE_URL}/?resetToken=${token}`;
    
    const mailOptions = {
        from: '"Shipping App Support" <support@demo.local>',
        to: user.email,
        subject: 'Password Reset Request',
        html: generateEmailTemplate(
            'Reset Your Password',
            'You requested a password reset. Click the button below to set a new password:',
            'Reset Password',
            resetLink,
            "If you didn't request this, please ignore this email."
        )
    };

    transporter.sendMail(mailOptions, (err) => {
        if (err) return res.status(500).json({ error: 'Error sending email' });
        res.json({ message: 'Reset link sent to your email' });
    });
};

const resetPassword = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { token, newPassword } = req.body;
    const user = await User.findOne({ resetToken: token, resetTokenExpiry: { $gt: Date.now() } });

    if (!user) return res.status(400).json({ error: 'Invalid or expired token' });

    // Require strong passwords
    if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9])(?=.{8,})/.test(newPassword)) {
        return res.status(400).json({ error: 'Password must be at least 8 characters and contain uppercase, lowercase, numbers, and special characters.' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    res.json({ message: 'Password reset successful. You can now log in.' });
};

const verifyEmail = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { token } = req.body;
    const user = await User.findOne({ verificationToken: token });
    if (!user) return res.status(400).json({ error: 'Invalid or expired token' });
    
    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();
    await logActivity(user.username, 'Verification', 'Email verified successfully');
    res.json({ 
        message: 'Email verified! You are now logged in.',
        user: { username: user.username, role: user.role, email: user.email, _id: user._id }
    });
};

const resendVerification = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.isVerified) return res.status(400).json({ error: 'Account already verified' });

    const verificationToken = crypto.randomBytes(20).toString('hex');
    user.verificationToken = verificationToken;
    await user.save();

    const verifyLink = `${BASE_URL}/?verifyToken=${verificationToken}`;
    const mailOptions = {
        from: '"Shipping App Support" <support@demo.local>',
        to: email,
        subject: 'Verify Your Email Address',
        html: generateEmailTemplate(
            'Verify Your Email',
            'We received a request to resend your verification link. Click the button below to verify your account:',
            'Verify Email Address',
            verifyLink,
            "If you didn't request this, please ignore this email."
        )
    };

    transporter.sendMail(mailOptions, (err) => {
        if (err) return res.status(500).json({ error: 'Error sending email' });
        res.json({ message: 'Verification email sent' });
    });
};


module.exports = {
    login,
    signup,
    forgotPassword,
    resetPassword,
    verifyEmail,
    resendVerification
};
