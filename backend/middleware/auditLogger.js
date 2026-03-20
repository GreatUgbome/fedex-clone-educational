const AuditLog = require('../models/auditLog');

const auditLogger = async (req, res, next) => {
    // We use the "finish" event so we can capture the final status code
    // and guarantee the logging doesn't slow down the response to the client
    res.on('finish', async () => {
        // Optional: Filter out standard GET requests to prevent database bloat
        if (req.method !== 'GET') {
            try {
                const logEntry = new AuditLog({
                    action: `${req.method} ${req.originalUrl}`,
                    // Assumes checkAuth attaches 'req.user', fallback to System/Anonymous
                    user: req.user ? req.user.email : 'System/Anonymous',
                    target: `HTTP ${res.statusCode}`,
                    details: {
                        ip: req.ip,
                        userAgent: req.get('user-agent')
                    }
                });
                await logEntry.save();
            } catch (error) {
                console.error('Failed to save audit log:', error.message);
            }
        }
    });
    next();
};

module.exports = auditLogger;