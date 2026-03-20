const express = require('express');
const router = express.Router();
const { getProfile, updateProfile, deleteProfile, getUserShipments, getUserActivity } = require('../controllers/user');
const { checkAuth } = require('../middleware/auth');
const { body } = require('express-validator');
const multer = require('multer');
const { uploadImageToStorage } = require('../utils/firebaseStorage');
const User = require('../models/user'); // Make sure this path matches your project

const upload = multer({ storage: multer.memoryStorage() });

router.get('/profile/:username', checkAuth, getProfile);

router.post('/profile/:username/avatar', checkAuth, upload.single('avatar'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No image uploaded' });
        }
        const avatarUrl = await uploadImageToStorage(req.file);
        
        // Save the new avatar URL to the database
        await User.findOneAndUpdate(
            { username: req.params.username },
            { avatarUrl },
            { new: true }
        );
        
        res.status(200).json({ message: 'Avatar uploaded successfully', avatarUrl });
    } catch (error) {
        res.status(500).json({ error: 'Failed to upload avatar' });
    }
});

// Fetch a user's avatar
router.get('/profile/:username/avatar', checkAuth, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.username });
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.status(200).json({ avatarUrl: user.avatarUrl });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch avatar' });
    }
});

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
