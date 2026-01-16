require('dotenv').config();
const functions = require('firebase-functions');
const admin = require('firebase-admin');
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

admin.initializeApp();

const app = express();
app.set('trust proxy', 1); // Trust first proxy (Render/Firebase) for rate limiting
const PORT = process.env.PORT || 5002;
// Base URL for emails - Update this to your Firebase Hosting URL in production
const BASE_URL = process.env.BASE_URL || (process.env.RENDER ? 'https://fedex-37e89.web.app' : `http://localhost:${PORT}`);

app.use(cors({ origin: true }));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' },
    skip: (req, res) => {
        const whitelistedIps = ['127.0.0.1', '::1']; // Add IPs to whitelist here
        return whitelistedIps.includes(req.ip);
    }
});
app.use('/api', limiter);

// Request Logger Middleware
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

// Middleware to verify Firebase ID token
const checkAuth = async (req, res, next) => {
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
        const idToken = req.headers.authorization.split('Bearer ')[1];
        try {
            const decodedToken = await admin.auth().verifyIdToken(idToken);
            req.user = decodedToken; // Attach user info to the request
            return next();
        } catch (error) {
            console.error('Error while verifying Firebase ID token:', error);
            return res.status(403).json({ error: 'Unauthorized' });
        }
    }
    return res.status(401).json({ error: 'No token provided' });
};

// Middleware to check for admin role (based on email)
const checkAdmin = (req, res, next) => {
    if (req.user && req.user.email === 'admin@fedex.com') return next();
    return res.status(403).json({ error: 'Forbidden: Admin access required' });
};

// Suppress browser noise (favicon and chrome devtools probe)
app.get('/favicon.ico', (req, res) => res.status(204).end());
app.get('/.well-known/appspecific/com.chrome.devtools.json', (req, res) => res.sendStatus(404));

// Health Check Endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'UP',
        timestamp: new Date().toISOString(),
        dbState: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'
    });
});

// Middleware to check DB connection before handling API requests
app.use('/api', async (req, res, next) => {
    if (mongoose.connection.readyState !== 1) {
        try {
            await connectDB();
        } catch (e) {
            console.error("DB Connection failed in middleware:", e);
        }
    }
    
    if (mongoose.connection.readyState !== 1) {
        return res.status(503).json({ error: 'System is offline (Database not connected). Please check server logs.' });
    }
    next();
});

// --- MongoDB Setup ---
// Global connection promise to reuse across function invocations
let connPromise = null;
const connectDB = async () => {
    if (mongoose.connection.readyState === 1) {
        return mongoose;
    }

    if (connPromise) {
        return connPromise;
    }

    connPromise = mongoose.connect(process.env.MONGO_URI || 'mongodb+srv://greatugbome5_db_user:76TtO6KU4hIrf0lv@cluster0.yas9t3a.mongodb.net/fedex-clone?retryWrites=true&w=majority&appName=Cluster0', {
        serverSelectionTimeoutMS: 5000 // Fail fast in serverless
    }).then(async (m) => {
        console.log('MongoDB Connected');
        await seedDatabase();
        return m;
    }).catch(err => {
        console.error('MongoDB Connection Error:', err.message);
        connPromise = null;
        throw err;
    });

    return connPromise;
};

// Schemas
const ShipmentSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    status: String,
    statusDetail: String,
    service: String,
    deliveryDate: String,
    weight: String,
    dimensions: String,
    pieces: Number,
    destination: String,
    coordinates: { lat: Number, lng: Number },
    sender: String,
    recipient: String,
    timeline: [{
        date: String,
        status: String,
        location: String,
        icon: String
    }],
    proofOfDelivery: String,
    createdBy: String
});

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

const PickupSchema = new mongoose.Schema({
    address: String,
    date: String,
    time: String,
    packages: Number,
    weight: String,
    instructions: String,
    status: { type: String, default: 'Scheduled' }
});

const ActivitySchema = new mongoose.Schema({
    username: String,
    action: String,
    details: String,
    timestamp: { type: Date, default: Date.now }
});

const FeedbackSchema = new mongoose.Schema({
    rating: Number,
    comment: String,
    username: String,
    timestamp: { type: Date, default: Date.now }
});

const SettingSchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    value: mongoose.Schema.Types.Mixed
});

const EmailSchema = new mongoose.Schema({
    recipient: String,
    subject: String,
    message: String,
    status: { type: String, enum: ['sent', 'draft'], default: 'sent' },
    timestamp: { type: Date, default: Date.now }
});

const Shipment = mongoose.model('Shipment', ShipmentSchema);
const User = mongoose.model('User', UserSchema);
const Pickup = mongoose.model('Pickup', PickupSchema);
const Activity = mongoose.model('Activity', ActivitySchema);
const Feedback = mongoose.model('Feedback', FeedbackSchema);
const Setting = mongoose.model('Setting', SettingSchema);
const Email = mongoose.model('Email', EmailSchema);

// --- Email Setup (Nodemailer) ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// --- File Upload Setup (Multer) ---
// Use disk storage for Render/Local
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadPath)) fs.mkdirSync(uploadPath, { recursive: true });
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

app.post('/api/upload', upload.single('image'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    res.json({ path: req.file.filename });
});

function generateEmailTemplate(title, message, buttonText, buttonLink, footer) {
    const footerContent = footer || `If the button above doesn't work, copy and paste this link into your browser: <br> <a href="${buttonLink}">${buttonLink}</a>`;
    return `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #4D148C;">${title}</h2>
            <p>${message}</p>
            <p style="text-align: center; margin: 30px 0;">
                <a href="${buttonLink}" style="background-color: #FF6200; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">${buttonText}</a>
            </p>
            <p style="font-size: 12px; color: #666;">${footerContent}</p>
        </div>
    `;
}

function sendStatusEmail(shipmentId, newStatus) {
    const mailOptions = {
        from: 'fedex-cl@noreply.com',
        to: 'recipient@example.com', // In a real app, this would be shipment.recipientEmail
        subject: `Shipment Update: ${shipmentId}`,
        text: `The status of your shipment ${shipmentId} has changed to: ${newStatus}`
    };
    transporter.sendMail(mailOptions, (err) => {
        if (err) console.log('Email error:', err);
    });
}

async function logActivity(username, action, details) {
    try {
        await Activity.create({ username, action, details });
    } catch (e) {
        console.error("Activity Log Error:", e);
    }
}

// Auth Routes
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        if (!user.isVerified) return res.status(403).json({ error: 'Please verify your email before logging in.' });
        await logActivity(user.username, 'Login', 'User logged in');
        res.json({ username: user.username, role: user.role, email: user.email, _id: user._id });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

app.post('/api/signup', async (req, res) => {
    const { username, password, email } = req.body;
    const existing = await User.findOne({ username });
    if (existing) {
        return res.status(400).json({ error: 'User already exists' });
    }
    
    const verificationToken = crypto.randomBytes(20).toString('hex');
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword, email, role: 'user', isVerified: false, verificationToken });
    await newUser.save();
    
    await logActivity(username, 'Signup', 'Account created');

    // Send Verification Email
    const verifyLink = `${BASE_URL}/?verifyToken=${verificationToken}`;
    const mailOptions = {
        from: '"FedEx CL Support" <fedex-cl@noreply.com>',
        to: email,
        subject: 'Welcome! Please Verify Your Email',
        html: generateEmailTemplate(
            'Welcome to FedEx CL!',
            'Thank you for signing up. To start shipping and tracking packages, please verify your email address.',
            'Verify Email Address',
            verifyLink
        )
    };

    transporter.sendMail(mailOptions, (err) => {
        if (err) console.log('Email error:', err);
    });

    // Do not auto-login, require verification
    res.json({ message: 'Signup successful! Please check your email to verify your account.' });
});

// Forgot Password - Request Link
app.post('/api/forgot-password', async (req, res) => {
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
        from: '"FedEx Support" <fedex-cl@noreply.com>',
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
});

// Reset Password - Submit New Password
app.post('/api/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    const user = await User.findOne({ resetToken: token, resetTokenExpiry: { $gt: Date.now() } });

    if (!user) return res.status(400).json({ error: 'Invalid or expired token' });

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    res.json({ message: 'Password reset successful. You can now log in.' });
});

// Verify Email
app.post('/api/verify-email', async (req, res) => {
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
});

// Resend Verification Email
app.post('/api/resend-verification', async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.isVerified) return res.status(400).json({ error: 'Account already verified' });

    const verificationToken = crypto.randomBytes(20).toString('hex');
    user.verificationToken = verificationToken;
    await user.save();

    const verifyLink = `${BASE_URL}/?verifyToken=${verificationToken}`;
    const mailOptions = {
        from: '"FedEx CL Support" <fedex-cl@noreply.com>',
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
});

// Feedback Route
app.post('/api/feedback', async (req, res) => {
    try {
        const feedback = new Feedback(req.body);
        await feedback.save();
        res.json({ message: 'Thank you for your feedback!' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Settings Routes
app.get('/api/settings', async (req, res) => {
    try {
        const settings = await Setting.find({});
        const settingsMap = {};
        settings.forEach(s => settingsMap[s.key] = s.value);
        res.json(settingsMap);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.put('/api/settings', async (req, res) => {
    const { key, value } = req.body;
    await Setting.findOneAndUpdate({ key }, { value }, { upsert: true });
    res.json({ message: 'Setting updated' });
});

// Get all shipment IDs (for Admin Panel)
app.get('/api/shipments', async (req, res) => {
    const ships = await Shipment.find({}, 'id status service');
    res.json(ships);
});

// Get all shipments with full details for CSV Export
app.get('/api/shipments/export', async (req, res) => {
    const ships = await Shipment.find({});
    res.json(ships);
});

// --- Admin Dashboard Routes ---

// Get all packages with details (mapped for frontend)
app.get('/api/packages', checkAuth, checkAdmin, async (req, res) => {
    const packages = await Shipment.find({});
    const mapped = packages.map(p => ({
        ...p.toObject(),
        trackingNumber: p.id,
        statusText: p.statusDetail,
        estimatedDelivery: p.deliveryDate
    }));
    res.json(mapped);
});

app.get('/api/stats/shipments-by-status', checkAuth, checkAdmin, async (req, res) => {
    const stats = await Shipment.aggregate([{ $group: { _id: "$status", count: { $sum: 1 } } }]);
    const result = {};
    stats.forEach(s => result[s._id || 'unknown'] = s.count);
    res.json(result);
});

app.get('/api/stats/shipments-by-service', checkAuth, checkAdmin, async (req, res) => {
    const stats = await Shipment.aggregate([{ $group: { _id: "$service", count: { $sum: 1 } } }]);
    const result = {};
    stats.forEach(s => result[s._id || 'Unknown'] = s.count);
    res.json(result);
});

app.get('/api/stats/shipments-last-7-days', checkAuth, checkAdmin, async (req, res) => {
    const stats = {};
    const today = new Date();
    for (let i = 6; i >= 0; i--) {
        const d = new Date(today);
        d.setDate(today.getDate() - i);
        const dayName = d.toLocaleDateString('en-US', { weekday: 'short' });
        stats[dayName] = Math.floor(Math.random() * 5); 
    }
    res.json(stats);
});

app.get('/api/stats/average-delivery-time', checkAuth, checkAdmin, async (req, res) => {
    res.json({ averageHours: 24, count: await Shipment.countDocuments({ status: 'Delivered' }) });
});

app.get('/api/stats/shipments-by-state', checkAuth, checkAdmin, async (req, res) => {
    const shipments = await Shipment.find({}, 'destination');
    const stats = {};
    shipments.forEach(s => {
        if (s.destination) {
            const parts = s.destination.split(',');
            const state = parts.length > 1 ? parts[parts.length - 1].trim().split(' ')[0] : 'Unknown';
            stats[state] = (stats[state] || 0) + 1;
        }
    });
    res.json(stats);
});

app.get('/api/stats/top-users', checkAuth, checkAdmin, async (req, res) => {
    const users = await Shipment.aggregate([
        { $group: { _id: "$sender", count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 5 }
    ]);
    res.json(users.map(u => ({ name: u._id || 'Unknown', count: u.count })));
});

app.get('/api/stats/revenue', checkAuth, checkAdmin, async (req, res) => {
    const count = await Shipment.countDocuments();
    res.json({ total: (count * 15.50).toFixed(2), currency: 'USD' });
});

app.get('/api/system/load-history', checkAuth, checkAdmin, (req, res) => {
    res.json([]); // Mock empty history
});

app.get('/api/audit-logs', checkAuth, checkAdmin, async (req, res) => {
    const logs = await Activity.find().sort({ timestamp: -1 }).limit(50);
    res.json(logs.map(l => ({ ...l.toObject(), user: l.username })));
});

app.delete('/api/audit-logs', checkAuth, checkAdmin, async (req, res) => {
    await Activity.deleteMany({});
    res.json({ message: 'Audit logs cleared' });
});

// --- Location Routes ---
app.get('/api/locations', checkAuth, checkAdmin, async (req, res) => {
    const locs = await Location.find({});
    res.json(locs);
});

app.post('/api/locations', checkAuth, checkAdmin, async (req, res) => {
    const { name, address, type } = req.body;
    if (!name || !address || !type) {
        return res.status(400).json({ error: 'Name, address, and type are required' });
    }
    const id = `L${Date.now()}`;
    const newLoc = new Location({ id, name, address, type });
    await newLoc.save();
    res.json(newLoc);
});

app.put('/api/locations/:id', checkAuth, checkAdmin, async (req, res) => {
    const { id } = req.params;
    await Location.findOneAndUpdate({ id }, req.body);
    res.json({ message: 'Location updated' });
});

app.delete('/api/locations/:id', checkAuth, checkAdmin, async (req, res) => {
    const { id } = req.params;
    await Location.deleteOne({ id });
    res.json({ message: 'Location deleted' });
});

// Get shipments for a specific user
app.get('/api/user/:username/shipments', async (req, res) => {
    const { username } = req.params;
    const ships = await Shipment.find({ createdBy: username });
    res.json(ships);
});

// Get User Activity
app.get('/api/user/:username/activity', async (req, res) => {
    const { username } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;

    const total = await Activity.countDocuments({ username });
    const logs = await Activity.find({ username }).sort({ timestamp: -1 }).skip(skip).limit(limit);
    
    res.json({
        logs,
        currentPage: page,
        totalPages: Math.ceil(total / limit)
    });
});

// --- User Profile Routes ---

// Get Profile
app.get('/api/profile/:username', async (req, res) => {
    const { username } = req.params;
    const user = await User.findOne({ username }, '-password -resetToken -resetTokenExpiry');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
});

// Update Profile
app.put('/api/profile/:username', async (req, res) => {
    const { username } = req.params;
    const { email, password, newUsername } = req.body;
    
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (email) user.email = email;
    if (newUsername && newUsername !== username) {
        const existing = await User.findOne({ username: newUsername });
        if (existing) return res.status(400).json({ error: 'Username already taken' });
        user.username = newUsername;
    }
    if (password && password.trim() !== '') user.password = await bcrypt.hash(password, 10);
    
    await user.save();
    await logActivity(user.username, 'Profile Update', 'Updated profile information');
    res.json({ message: 'Profile updated successfully', user: { username: user.username, role: user.role, email: user.email, _id: user._id } });
});

// Delete Profile (Self)
app.delete('/api/profile/:username', async (req, res) => {
    const { username } = req.params;
    try {
        const result = await User.deleteOne({ username });
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ message: 'Account deleted successfully' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// --- User Management Routes (Admin) ---

// Get all users
app.get('/api/users', async (req, res) => {
    const users = await User.find({}, 'username email role _id');
    res.json(users);
});

// Create User (Admin)
app.post('/api/admin/user', async (req, res) => {
    const { username, password, role, email } = req.body;
    const existing = await User.findOne({ username });
    if (existing) return res.status(400).json({ error: 'User already exists' });
    
    const pass = password || 'password123'; // Default password if not provided
    const hashedPassword = await bcrypt.hash(pass, 10);
    const newUser = new User({ username, email, password: hashedPassword, role });
    await newUser.save();
    res.json({ message: 'User created' });
});

// Update User
app.put('/api/admin/user/:id', async (req, res) => {
    const { id } = req.params;
    const { username, password, role, email } = req.body;
    
    const user = await User.findById(id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    if (username) user.username = username;
    if (role) user.role = role;
    if (email) user.email = email;
    if (password && password.trim() !== '') user.password = await bcrypt.hash(password, 10);
    
    await user.save();
    res.json({ message: 'User updated' });
});

// Delete User
app.delete('/api/admin/user/:id', async (req, res) => {
    const { id } = req.params;
    try {
        await User.findByIdAndDelete(id);
        res.json({ message: 'User deleted' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Send Custom Email (Admin)
app.post('/api/admin/send-email', upload.array('attachments'), async (req, res) => {
    const { email, subject, message, draftId } = req.body;
    
    const attachments = req.files ? req.files.map(file => ({
        filename: file.originalname,
        path: file.path
    })) : [];

    const mailOptions = {
        from: '"FedEx CL Support" <fedex-cl@noreply.com>',
        to: email,
        subject: subject,
        // Use BASE_URL for links
        html: generateEmailTemplate(subject, message, 'Visit Dashboard', BASE_URL),
        attachments: attachments
    };

    transporter.sendMail(mailOptions, async (err) => {
        if (err) return res.status(500).json({ error: 'Error sending email' });
        
        // Log sent email
        await Email.create({ recipient: email, subject, message, status: 'sent' });
        
        // Remove draft if exists
        if (draftId) await Email.findByIdAndDelete(draftId);

        res.json({ message: 'Email sent successfully' });
    });
});

// Send Bulk Email (Admin)
app.post('/api/admin/send-bulk-email', upload.array('attachments'), async (req, res) => {
    const { subject, message } = req.body;
    
    try {
        const users = await User.find({ email: { $exists: true, $ne: null } }, 'email');
        const emails = users.map(u => u.email).filter(e => e && e.includes('@'));

        if (emails.length === 0) {
            return res.status(400).json({ error: 'No users with email addresses found' });
        }

        const attachments = req.files ? req.files.map(file => ({
            filename: file.originalname,
            path: file.path
        })) : [];

        const mailOptions = {
            from: '"FedEx CL Support" <fedex-cl@noreply.com>',
            bcc: emails,
            subject: subject,
            html: generateEmailTemplate(subject, message, 'Visit Dashboard', BASE_URL),
            attachments: attachments
        };

        transporter.sendMail(mailOptions, async (err) => {
            if (err) return res.status(500).json({ error: 'Error sending email' });
            
            await Email.create({ recipient: 'All Users (Bulk)', subject, message, status: 'sent' });
            
            res.json({ message: `Bulk email sent to ${emails.length} users` });
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// --- Email Management Routes (Drafts & Logs) ---

// Get Emails (Sent or Drafts)
app.get('/api/admin/emails', async (req, res) => {
    const { status } = req.query;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const query = status ? { status } : {};
    try {
        const total = await Email.countDocuments(query);
        const emails = await Email.find(query).sort({ timestamp: -1 }).skip(skip).limit(limit);
        res.json({
            emails,
            currentPage: page,
            totalPages: Math.ceil(total / limit)
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Delete Email (Draft or Sent)
app.delete('/api/admin/email/:id', async (req, res) => {
    const { id } = req.params;
    try {
        await Email.findByIdAndDelete(id);
        res.json({ message: 'Email deleted' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Save Draft
app.post('/api/admin/email/draft', async (req, res) => {
    const { recipient, subject, message, id } = req.body;
    try {
        if (id) {
            await Email.findByIdAndUpdate(id, { recipient, subject, message, timestamp: Date.now() });
        } else {
            await Email.create({ recipient, subject, message, status: 'draft' });
        }
        res.json({ message: 'Draft saved' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Create New Shipment
app.post('/api/shipment', checkAuth, checkAdmin, async (req, res) => {
    const { id, ...data } = req.body;
    if (!id) return res.status(400).json({ error: 'Tracking ID is required' });
    
    const existing = await Shipment.findOne({ id });
    if (existing) return res.status(400).json({ error: 'Shipment already exists' });
    
    const newShipment = new Shipment({ id, ...data });
    await newShipment.save();
    if (data.createdBy) {
        await logActivity(data.createdBy, 'Create Shipment', `Created shipment ${id}`);
    }
    res.json({ message: 'Shipment created', id, data: newShipment });
});

// Update Existing Shipment
app.put('/api/shipment/:id', checkAuth, checkAdmin, async (req, res) => {
    const { id } = req.params;
    const updates = req.body;
    
    const shipment = await Shipment.findOne({ id });
    if (!shipment) return res.status(404).json({ error: 'Shipment not found' });

    // If status changed, send email
    if (updates.status && updates.status !== shipment.status) {
        sendStatusEmail(id, updates.status);
        await logActivity('System', 'Status Update', `Shipment ${id} updated to ${updates.status}`);
    }

    Object.assign(shipment, updates);
    await shipment.save();
    res.json({ message: 'Shipment updated' });
});

// Delete Shipment
app.delete('/api/shipment/:id', checkAuth, checkAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await Shipment.deleteOne({ id });
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Shipment not found' });
        }
        res.json({ message: 'Shipment deleted successfully' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Schedule Pickup
app.post('/api/pickup', async (req, res) => {
    try {
        const pickup = new Pickup(req.body);
        await pickup.save();
        res.json({ message: 'Pickup scheduled successfully', id: pickup._id });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/track/:id', async (req, res) => {
    const { id } = req.params;
    const data = await Shipment.findOne({ id });
    if (data) {
        res.json(data);
    } else {
        res.status(404).json({ error: 'Tracking ID not found' });
    }
});

exports.api = functions.https.onRequest(app);

// Start server locally if not running in Cloud Functions
if (require.main === module) {
    app.use(express.static(path.join(__dirname, '../frontend')));
    app.listen(PORT, () => {
        console.log(`Backend server running on http://localhost:${PORT}`);
    });
}

// --- Seed Data Helper ---
async function seedDatabase() {
    try {
        const shipCount = await Shipment.countDocuments();
        if (shipCount === 0) {
            console.log("Seeding initial shipments...");
            await Shipment.create({
                id: '123456789012',
                status: 'Delivered',
                statusDetail: 'Delivered to front porch',
                service: 'FedEx Home Delivery',
                deliveryDate: 'Sunday, 9/24/2023',
                weight: '4.5 lbs / 2.04 kgs',
                destination: 'Austin, TX, US',
                coordinates: { lat: 30.2672, lng: -97.7431 },
                sender: 'Best Buy Inc.',
                recipient: 'Chukwuka U.',
                timeline: [
                    { date: 'Sep 24, 2023 2:30 PM', status: 'Delivered', location: 'Austin, TX', icon: 'fa-check' },
                    { date: 'Sep 24, 2023 8:00 AM', status: 'On FedEx vehicle for delivery', location: 'Austin, TX', icon: 'fa-truck' },
                    { date: 'Sep 23, 2023 9:15 PM', status: 'Arrived at FedEx location', location: 'Austin, TX', icon: 'fa-warehouse' },
                    { date: 'Sep 22, 2023 4:00 PM', status: 'Picked up', location: 'Dallas, TX', icon: 'fa-box' }
                ]
            });
            await Shipment.create({
                id: '987654321098',
                status: 'In Transit',
                statusDetail: 'Arrived at FedEx location',
                service: 'FedEx Ground',
                deliveryDate: 'Estimated Tuesday, 9/26/2023',
                weight: '12.0 lbs / 5.44 kgs',
                destination: 'Seattle, WA, US',
                coordinates: { lat: 47.6062, lng: -122.3321 },
                sender: 'Amazon Fulfillment',
                recipient: 'Jane Doe',
                timeline: [
                    { date: 'Sep 25, 2023 10:00 AM', status: 'Arrived at FedEx location', location: 'Portland, OR', icon: 'fa-warehouse' },
                    { date: 'Sep 24, 2023 6:30 PM', status: 'Departed FedEx location', location: 'Sacramento, CA', icon: 'fa-truck-moving' },
                    { date: 'Sep 23, 2023 2:00 PM', status: 'Picked up', location: 'Los Angeles, CA', icon: 'fa-box' }
                ]
            });
        }

        // Ensure admin user exists and is verified
        const adminUser = await User.findOne({ username: 'smallblack' });
        if (!adminUser) {
            console.log("Seeding admin user...");
            const adminPass = await bcrypt.hash('Nigeria123', 10);
            await User.create({ username: 'smallblack', email: 'admin@example.com', password: adminPass, role: 'admin', isVerified: true });
        } else if (!adminUser.isVerified) {
            console.log("Auto-verifying admin user...");
            adminUser.isVerified = true;
            await adminUser.save();
        }

        const regularUser = await User.findOne({ username: 'regularuser' });
        if (!regularUser) {
            console.log("Seeding regular user...");
            const userPass = await bcrypt.hash('password123', 10);
            await User.create({ username: 'regularuser', email: 'user@example.com', password: userPass, role: 'user', isVerified: true });
        } else if (!regularUser.isVerified) {
            regularUser.isVerified = true;
            await regularUser.save();
        }

        const settingCount = await Setting.countDocuments();
        if (settingCount === 0) {
            await Setting.create({ key: 'maintenanceMode', value: false });
        }
    } catch (error) {
        console.error("Error seeding database:", error);
    }
}
