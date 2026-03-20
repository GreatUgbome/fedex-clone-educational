const express = require('express');
const router = express.Router();
const {
    getPackages,
    getShipmentsByStatus,
    getShipmentsByService,
    getShipmentsLast7Days,
    getAverageDeliveryTime,
    getShipmentsByState,
    getTopUsers,
    getRevenue,
    getSystemLoadHistory,
    getAuditLogs,
    clearAuditLogs,
    getLocations,
    createLocation,
    updateLocation,
    deleteLocation,
    getUsers,
    createUser,
    updateUser,
    deleteUser,
    sendEmail,
    sendBulkEmail,
    getEmails,
    deleteEmail,
    saveDraft
} = require('../controllers/admin');
const { exportAuditLogsToCSV } = require('../controllers/audit');
const { checkAuth, checkAdmin } = require('../middleware/auth');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { body, param, validationResult } = require('express-validator');

// --- File Upload Setup (Multer) ---
// Use disk storage for Render/Local
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, '../uploads');
        if (!fs.existsSync(uploadPath)) fs.mkdirSync(uploadPath, { recursive: true });
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

router.get('/packages', checkAuth, checkAdmin, getPackages);
router.get('/stats/shipments-by-status', checkAuth, checkAdmin, getShipmentsByStatus);
router.get('/stats/shipments-by-service', checkAuth, checkAdmin, getShipmentsByService);
router.get('/stats/shipments-last-7-days', checkAuth, checkAdmin, getShipmentsLast7Days);
router.get('/stats/average-delivery-time', checkAuth, checkAdmin, getAverageDeliveryTime);
router.get('/stats/shipments-by-state', checkAuth, checkAdmin, getShipmentsByState);
router.get('/stats/top-users', checkAuth, checkAdmin, getTopUsers);
router.get('/stats/revenue', checkAuth, checkAdmin, getRevenue);
router.get('/system/load-history', checkAuth, checkAdmin, getSystemLoadHistory);
router.get('/audit-logs', checkAuth, checkAdmin, getAuditLogs);
router.get('/audit-logs/export', checkAuth, checkAdmin, exportAuditLogsToCSV);
router.delete('/audit-logs', checkAuth, checkAdmin, clearAuditLogs);
router.get('/locations', checkAuth, checkAdmin, getLocations);
router.post('/locations',
    checkAuth,
    checkAdmin,
    body('name').notEmpty().withMessage('Name is required'),
    body('address').notEmpty().withMessage('Address is required'),
    body('type').notEmpty().withMessage('Type is required'),
    createLocation
);
router.put('/locations/:id',
    checkAuth,
    checkAdmin,
    param('id').notEmpty().withMessage('Location ID is required'),
    updateLocation
);
router.delete('/locations/:id', checkAuth, checkAdmin, deleteLocation);
router.get('/users', checkAuth, checkAdmin, getUsers);
router.post('/admin/user',
    checkAuth,
    checkAdmin,
    body('username').isLength({ min: 3 }).withMessage('Username must be at least 3 characters long'),
    body('email').isEmail().withMessage('Please provide a valid email address'),
    body('role').notEmpty().withMessage('Role is required'),
    createUser
);
router.put('/admin/user/:id',
    checkAuth,
    checkAdmin,
    param('id').notEmpty().withMessage('User ID is required'),
    body('username').optional().isLength({ min: 3 }).withMessage('Username must be at least 3 characters long'),
    body('email').optional().isEmail().withMessage('Please provide a valid email address'),
    body('role').optional().notEmpty().withMessage('Role is required'),
    updateUser
);
router.delete('/admin/user/:id', checkAuth, checkAdmin, deleteUser);
router.post('/admin/send-email',
    checkAuth,
    checkAdmin,
    upload.array('attachments'),
    body('email').isEmail().withMessage('Please provide a valid email address'),
    body('subject').notEmpty().withMessage('Subject is required'),
    body('message').notEmpty().withMessage('Message is required'),
    sendEmail
);
router.post('/admin/send-bulk-email',
    checkAuth,
    checkAdmin,
    upload.array('attachments'),
    body('subject').notEmpty().withMessage('Subject is required'),
    body('message').notEmpty().withMessage('Message is required'),
    sendBulkEmail
);
router.get('/admin/emails', checkAuth, checkAdmin, getEmails);
router.delete('/admin/email/:id', checkAuth, checkAdmin, deleteEmail);
router.post('/admin/email/draft',
    checkAuth,
    checkAdmin,
    body('subject').notEmpty().withMessage('Subject is required'),
    body('message').notEmpty().withMessage('Message is required'),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
        next();
    },
    saveDraft
);
router.post('/upload', upload.single('image'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    res.json({ path: req.file.filename });
});


module.exports = router;
