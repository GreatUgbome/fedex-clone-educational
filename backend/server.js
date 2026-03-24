require('dotenv').config();
const functions = require('firebase-functions');
const admin = require('firebase-admin');
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

// Import Models
const Shipment = require('./models/shipment');
const Setting = require('./models/setting');
const auditLogger = require('./middleware/auditLogger');

// Initialize Firebase Admin
try {
    admin.initializeApp();
    console.log('✅ Firebase Admin initialized');
} catch (error) {
    console.log('⚠️ Firebase already initialized or not available');
}

const app = express();
app.set('trust proxy', 1); // Trust proxy for rate limiting
const PORT = process.env.PORT || 5002;

// Determine environment and base URL (K_SERVICE is the standard for Node 20+ on GCP)
const isProduction = process.env.NODE_ENV === 'production' || process.env.FUNCTION_NAME || process.env.K_SERVICE;
const BASE_URL = process.env.BASE_URL || (isProduction ? 'https://fedex-37e89.web.app' : `http://localhost:${PORT}`);

console.log('🌍 Environment:', isProduction ? 'Production (Firebase)' : 'Development');
console.log('🔗 Base URL:', BASE_URL);

// Security Headers Middleware
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});

app.use(cors({ 
    // Prevents cross-origin attacks by failing closed if environment variable is missing in prod
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : (isProduction ? BASE_URL : '*'),
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Helper to skip rate limiting for specific IPs (like localhost or your dev IP)
const skipWhitelisted = (req) => {
    const whitelistedIps = ['127.0.0.1', '::1', '::ffff:127.0.0.1'];
    if (process.env.WHITELIST_IP) {
        whitelistedIps.push(...process.env.WHITELIST_IP.split(',').map(ip => ip.trim()));
    }
    return whitelistedIps.includes(req.ip);
};

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' },
    skip: skipWhitelisted
});
app.use('/api', limiter);

// Strict Rate Limiting for Login
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 login requests per 15 minutes
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many login attempts from this IP, please try again after 15 minutes.' },
    skip: skipWhitelisted
});
app.use('/api/auth/login', loginLimiter);

// Strict Rate Limiting for Account Creation & Recovery
const authActionLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 requests per 15 minutes
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests for this action from this IP, please try again after 15 minutes.' },
    skip: skipWhitelisted
});
app.use(['/api/auth/signup', '/api/auth/forgot-password', '/api/auth/reset-password', '/api/auth/resend-verification'], authActionLimiter);

// --- MongoDB Connection ---
const connectDatabase = async () => {
    if (mongoose.connection.readyState === 1) {
        console.log('MongoDB already connected');
        return;
    }
    
    const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/fedex-clone';
    
    try {
        await mongoose.connect(mongoUri, {
            serverSelectionTimeoutMS: 5000,
        });
        console.log('✅ MongoDB connected successfully');
        await seedDatabase();
    } catch (error) {
        console.error('❌ MongoDB connection error:', error.message);
        console.log('⚠️  Continuing without database - seeding will be skipped');
        console.log('💡 To fix: Update MONGO_URI in .env with valid MongoDB credentials');
        if (require.main === module) {
            // Continue running even if DB connection fails (useful for testing)
            console.log('ℹ️  Server will run without database persistence');
        }
    }
};

// Connect on startup
connectDatabase();

// Request Logger Middleware
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

// Automatically log non-GET API interactions
app.use('/api', auditLogger);

// Health Check Endpoint
app.get('/health', (req, res) => {
    const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    res.json({ 
        status: 'ok',
        database: dbStatus,
        timestamp: new Date().toISOString()
    });
});

// --- Avatar Upload Endpoint ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const dir = path.join(__dirname, 'uploads', 'avatars');
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        cb(null, `${req.params.username}-${Date.now()}${path.extname(file.originalname)}`);
    }
});
const upload = multer({ storage: storage });

app.post('/api/profile/:username/avatar', upload.single('avatar'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    const avatarUrl = `${BASE_URL}/uploads/avatars/${req.file.filename}`;
    res.json({ message: 'Avatar uploaded successfully', avatarUrl });
});

app.get('/api/profile/:username/avatar', async (req, res) => {
    // Mock response to prevent frontend errors if no DB integration exists yet
    res.json({ avatarUrl: null });
});

const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');
const mainRoutes = require('./routes/main');
const shipmentRoutes = require('./routes/shipment');
const userRoutes = require('./routes/user');

app.use('/api/auth', authRoutes);
app.use('/api', adminRoutes);
app.use('/api', mainRoutes);
app.use('/api', shipmentRoutes);
app.use('/api', userRoutes);

exports.api = functions.https.onRequest(app);
exports.app = app; // Export app for testing

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
        if (mongoose.connection.readyState !== 1) {
            console.log('Skipping seed: Database not connected');
            return;
        }

        const shipCount = await Shipment.countDocuments();
        if (shipCount === 0) {
            console.log("Seeding initial shipments...");
            await Shipment.create({
                id: '123456789012',
                status: 'Delivered',
                statusDetail: 'Delivered to front porch',
            service: 'Standard Home Delivery',
                deliveryDate: 'Sunday, 9/24/2023',
                weight: '4.5 lbs / 2.04 kgs',
                destination: 'Austin, TX, US',
                coordinates: { lat: 30.2672, lng: -97.7431 },
                sender: 'Best Buy Inc.',
                recipient: 'Chukwuka U.',
                timeline: [
                    { date: 'Sep 24, 2023 2:30 PM', status: 'Delivered', location: 'Austin, TX', icon: 'fa-check' },
                { date: 'Sep 24, 2023 8:00 AM', status: 'On vehicle for delivery', location: 'Austin, TX', icon: 'fa-truck' },
                { date: 'Sep 23, 2023 9:15 PM', status: 'Arrived at sort facility', location: 'Austin, TX', icon: 'fa-warehouse' },
                    { date: 'Sep 22, 2023 4:00 PM', status: 'Picked up', location: 'Dallas, TX', icon: 'fa-box' }
                ]
            });
            await Shipment.create({
                id: '987654321098',
                status: 'In Transit',
            statusDetail: 'Arrived at sort facility',
            service: 'Ground Shipping',
                deliveryDate: 'Estimated Tuesday, 9/26/2023',
                weight: '12.0 lbs / 5.44 kgs',
                destination: 'Seattle, WA, US',
                coordinates: { lat: 47.6062, lng: -122.3321 },
                sender: 'Amazon Fulfillment',
                recipient: 'Jane Doe',
                timeline: [
                { date: 'Sep 25, 2023 10:00 AM', status: 'Arrived at sort facility', location: 'Portland, OR', icon: 'fa-warehouse' },
                { date: 'Sep 24, 2023 6:30 PM', status: 'Departed sort facility', location: 'Sacramento, CA', icon: 'fa-truck-moving' },
                    { date: 'Sep 23, 2023 2:00 PM', status: 'Picked up', location: 'Los Angeles, CA', icon: 'fa-box' }
                ]
            });
            console.log("Shipments seeded successfully");
        }

        const settingCount = await Setting.countDocuments();
        if (settingCount === 0) {
            await Setting.create({ 
                key: 'maintenanceMode',
                value: false 
            });
            await Setting.create({
                key: 'systemStatus',
                value: 'operational'
            });
            console.log("Settings seeded successfully");
        }
    } catch (error) {
        console.error("Error seeding database:", error.message);
    }
}
