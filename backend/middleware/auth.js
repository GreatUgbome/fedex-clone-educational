const admin = require('firebase-admin');

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

// TODO: Replace this with a proper Role-Based Access Control (RBAC) system.
const checkAdmin = (req, res, next) => {
    if (req.user && req.user.email === 'admin@fedex.com') return next();
    return res.status(403).json({ error: 'Forbidden: Admin access required' });
};

module.exports = {
    checkAuth,
    checkAdmin
};
