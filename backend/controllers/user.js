const User = require('../models/user');
const Shipment = require('../models/shipment');
const Activity = require('../models/activity');
const bcrypt = require('bcrypt');
const { logActivity } = require('../utils/activity');

const getProfile = async (req, res) => {
    const { username } = req.params;
    const user = await User.findOne({ username }, '-password -resetToken -resetTokenExpiry');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
};

const { validationResult } = require('express-validator');

const updateProfile = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
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
};

const deleteProfile = async (req, res) => {
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
};

const getUserShipments = async (req, res) => {
    const { username } = req.params;
    const ships = await Shipment.find({ createdBy: username });
    res.json(ships);
};

const getUserActivity = async (req, res) => {
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
};

module.exports = {
    getProfile,
    updateProfile,
    deleteProfile,
    getUserShipments,
    getUserActivity
};
