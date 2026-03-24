const admin = require('firebase-admin');
const User = require('../models/user');

const checkAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Unauthorized: No token provided' });
        }

        const token = authHeader.split(' ')[1];
        
        // Verify the token with Firebase Admin
        const decodedToken = await admin.auth().verifyIdToken(token);
        
        // Attach the decoded token (which includes .email and .uid) to req.user
        req.user = decodedToken;
        next();
    } catch (error) {
        console.error('Authentication Error:', error.message);
        return res.status(401).json({ error: 'Unauthorized: Invalid or expired token' });
    }
};

const checkAdmin = async (req, res, next) => {
    // If they aren't authenticated at all, reject immediately
    if (!req.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    // Check Firebase Custom Claims first
    if (req.user.admin === true) {
        return next();
    }

    // Fallback: Check MongoDB User Role
    try {
        const dbUser = await User.findOne({ email: req.user.email });
        if (dbUser && (dbUser.role === 'admin' || dbUser.role === 'Admin')) {
            return next();
        }
    } catch (error) {}

    return res.status(403).json({ error: 'Forbidden: Admin access required' });
};

module.exports = { checkAuth, checkAdmin };