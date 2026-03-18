const express = require('express');
const router = express.Router();
const { login, signup, forgotPassword, resetPassword, verifyEmail, resendVerification } = require('../controllers/auth');
const { body } = require('express-validator');

router.post('/login',
    body('username').notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required'),
    login
);
router.post('/signup',
    body('username').isLength({ min: 3 }).withMessage('Username must be at least 3 characters long'),
    body('email').isEmail().withMessage('Please provide a valid email address'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    signup
);
router.post('/forgot-password',
    body('email').isEmail().withMessage('Please provide a valid email address'),
    forgotPassword
);
router.post('/reset-password',
    body('token').notEmpty().withMessage('Token is required'),
    body('newPassword').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    resetPassword
);
router.post('/verify-email',
    body('token').notEmpty().withMessage('Token is required'),
    verifyEmail
);
router.post('/resend-verification',
    body('email').isEmail().withMessage('Please provide a valid email address'),
    resendVerification
);

module.exports = router;
