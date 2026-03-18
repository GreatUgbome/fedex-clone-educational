const express = require('express');
const router = express.Router();
const { getProfile, updateProfile, deleteProfile, getUserShipments, getUserActivity } = require('../controllers/user');
const { checkAuth } = require('../middleware/auth');
const { body } = require('express-validator');

router.get('/profile/:username', checkAuth, getProfile);
router.put('/profile/:username',
    checkAuth,
    body('email').optional().isEmail().withMessage('Please provide a valid email address'),
    body('newUsername').optional().isLength({ min: 3 }).withMessage('Username must be at least 3 characters long'),
    body('password').optional().isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    updateProfile
);
router.delete('/profile/:username', checkAuth, deleteProfile);
router.get('/user/:username/shipments', checkAuth, getUserShipments);
router.get('/user/:username/activity', checkAuth, getUserActivity);

module.exports = router;
