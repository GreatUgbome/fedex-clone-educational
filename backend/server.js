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

// Import Models
const Shipment = require('./models/shipment');
const Setting = require('./models/setting');

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

// Determine environment and base URL
const isProduction = process.env.NODE_ENV === 'production' || process.env.FUNCTION_NAME;
const BASE_URL = process.env.BASE_URL || (isProduction ? 'https://fedex-37e89.web.app' : `http://localhost:${PORT}`);

console.log('🌍 Environment:', isProduction ? 'Production (Firebase)' : 'Development');
console.log('🔗 Base URL:', BASE_URL);

app.use(cors({ 
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*'
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
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

// --- MongoDB Connection ---
const connectDatabase = async () => {
    if (mongoose.connection.readyState === 1) {
        console.log('MongoDB already connected');
        return;
    }
    
    const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/fedex-clone';
    
    try {
        await mongoose.connect(mongoUri, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
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

// Health Check Endpoint
app.get('/health', (req, res) => {
    const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    res.json({ 
        status: 'ok',
        database: dbStatus,
        timestamp: new Date().toISOString()
    });
});

const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');
const mainRoutes = require('./routes/main');
const shipmentRoutes = require('./routes/shipment');
const userRoutes = require('./routes/user');

app.use('/api', authRoutes);
app.use('/api', adminRoutes);
app.use('/api', mainRoutes);
app.use('/api', shipmentRoutes);
app.use('/api', userRoutes);

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
