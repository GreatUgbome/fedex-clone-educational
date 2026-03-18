const Shipment = require('../models/shipment');
const User = require('../models/user');
const Activity = require('../models/activity');
const Email = require('../models/email');
const Location = require('../models/location');
const { generateEmailTemplate, transporter } = require('../utils/email');
const bcrypt = require('bcrypt');
require('dotenv').config();

const BASE_URL = process.env.BASE_URL || (process.env.RENDER ? 'https://fedex-37e89.web.app' : `http://localhost:5002}`);

const getPackages = async (req, res) => {
    const packages = await Shipment.find({});
    const mapped = packages.map(p => ({
        ...p.toObject(),
        trackingNumber: p.id,
        statusText: p.statusDetail,
        estimatedDelivery: p.deliveryDate
    }));
    res.json(mapped);
};

const getShipmentsByStatus = async (req, res) => {
    const stats = await Shipment.aggregate([{ $group: { _id: "$status", count: { $sum: 1 } } }]);
    const result = {};
    stats.forEach(s => result[s._id || 'unknown'] = s.count);
    res.json(result);
};

const getShipmentsByService = async (req, res) => {
    const stats = await Shipment.aggregate([{ $group: { _id: "$service", count: { $sum: 1 } } }]);
    const result = {};
    stats.forEach(s => result[s._id || 'Unknown'] = s.count);
    res.json(result);
};

const getShipmentsLast7Days = async (req, res) => {
    const stats = {};
    const today = new Date();
    for (let i = 6; i >= 0; i--) {
        const d = new Date(today);
        d.setDate(today.getDate() - i);
        const dayName = d.toLocaleDateString('en-US', { weekday: 'short' });
        //TODO: This is mock data. Replace with real data.
        stats[dayName] = Math.floor(Math.random() * 5); 
    }
    res.json(stats);
};

const getAverageDeliveryTime = async (req, res) => {
    //TODO: This is mock data. Replace with real data.
    res.json({ averageHours: 24, count: await Shipment.countDocuments({ status: 'Delivered' }) });
};

const getShipmentsByState = async (req, res) => {
    const shipments = await Shipment.find({}, 'destination');
    const stats = {};
    shipments.forEach(s => {
        if (s.destination) {
            const parts = s.destination.split(',');
            const state = parts.length > 1 ? parts[parts.length - 1].trim().split(' ')[0] : 'Unknown';
            stats[state] = (stats[state] || 0) + 1;
        }
    });
    res.json(stats);
};

const getTopUsers = async (req, res) => {
    const users = await Shipment.aggregate([
        { $group: { _id: "$sender", count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 5 }
    ]);
    res.json(users.map(u => ({ name: u._id || 'Unknown', count: u.count })));
};

const getRevenue = async (req, res) => {
    const count = await Shipment.countDocuments();
    //TODO: This is mock data. Replace with real data.
    res.json({ total: (count * 15.50).toFixed(2), currency: 'USD' });
};

const getSystemLoadHistory = (req, res) => {
    //TODO: This is mock data. Replace with real data.
    res.json([]); // Mock empty history
};

const getAuditLogs = async (req, res) => {
    const logs = await Activity.find().sort({ timestamp: -1 }).limit(50);
    res.json(logs.map(l => ({ ...l.toObject(), user: l.username })));
};

const clearAuditLogs = async (req, res) => {
    await Activity.deleteMany({});
    res.json({ message: 'Audit logs cleared' });
};

const getLocations = async (req, res) => {
    const locs = await Location.find({});
    res.json(locs);
};

const { validationResult } = require('express-validator');

const createLocation = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { name, address, type } = req.body;
    const id = `L${Date.now()}`;
    const newLoc = new Location({ id, name, address, type });
    await newLoc.save();
    res.json(newLoc);
};

const updateLocation = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { id } = req.params;
    await Location.findOneAndUpdate({ id }, req.body);
    res.json({ message: 'Location updated' });
};

const deleteLocation = async (req, res) => {
    const { id } = req.params;
    await Location.deleteOne({ id });
    res.json({ message: 'Location deleted' });
};

const getUsers = async (req, res) => {
    const users = await User.find({}, 'username email role _id');
    res.json(users);
};

const createUser = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { username, password, role, email } = req.body;
    const existing = await User.findOne({ username });
    if (existing) return res.status(400).json({ error: 'User already exists' });
    
    const pass = password || 'password123'; // Default password if not provided
    const hashedPassword = await bcrypt.hash(pass, 10);
    const newUser = new User({ username, email, password: hashedPassword, role });
    await newUser.save();
    res.json({ message: 'User created' });
};

const updateUser = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { id } = req.params;
    const { username, password, role, email } = req.body;
    
    const user = await User.findById(id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    if (username) user.username = username;
    if (role) user.role = role;
    if (email) user.email = email;
    if (password && password.trim() !== '') user.password = await bcrypt.hash(password, 10);
    
    await user.save();
    res.json({ message: 'User updated' });
};

const deleteUser = async (req, res) => {
    const { id } = req.params;
    try {
        await User.findByIdAndDelete(id);
        res.json({ message: 'User deleted' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
};

const sendEmail = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { email, subject, message, draftId } = req.body;
    
    const attachments = req.files ? req.files.map(file => ({
        filename: file.originalname,
        path: file.path
    })) : [];

    const mailOptions = {
        from: '"FedEx CL Support" <fedex-cl@noreply.com>',
        to: email,
        subject: subject,
        // Use BASE_URL for links
        html: generateEmailTemplate(subject, message, 'Visit Dashboard', BASE_URL),
        attachments: attachments
    };

    transporter.sendMail(mailOptions, async (err) => {
        if (err) return res.status(500).json({ error: 'Error sending email' });
        
        // Log sent email
        await Email.create({ recipient: email, subject, message, status: 'sent' });
        
        // Remove draft if exists
        if (draftId) await Email.findByIdAndDelete(draftId);

        res.json({ message: 'Email sent successfully' });
    });
};

const sendBulkEmail = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { subject, message } = req.body;
    
    try {
        const users = await User.find({ email: { $exists: true, $ne: null } }, 'email');
        const emails = users.map(u => u.email).filter(e => e && e.includes('@'));

        if (emails.length === 0) {
            return res.status(400).json({ error: 'No users with email addresses found' });
        }

        const attachments = req.files ? req.files.map(file => ({
            filename: file.originalname,
            path: file.path
        })) : [];

        const mailOptions = {
            from: '"FedEx CL Support" <fedex-cl@noreply.com>',
            bcc: emails,
            subject: subject,
            html: generateEmailTemplate(subject, message, 'Visit Dashboard', BASE_URL),
            attachments: attachments
        };

        transporter.sendMail(mailOptions, async (err) => {
            if (err) return res.status(500).json({ error: 'Error sending email' });
            
            await Email.create({ recipient: 'All Users (Bulk)', subject, message, status: 'sent' });
            
            res.json({ message: `Bulk email sent to ${emails.length} users` });
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
};

const getEmails = async (req, res) => {
    const { status } = req.query;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const query = status ? { status } : {};
    try {
        const total = await Email.countDocuments(query);
        const emails = await Email.find(query).sort({ timestamp: -1 }).skip(skip).limit(limit);
        res.json({
            emails,
            currentPage: page,
            totalPages: Math.ceil(total / limit)
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
};

const deleteEmail = async (req, res) => {
    const { id } = req.params;
    try {
        await Email.findByIdAndDelete(id);
        res.json({ message: 'Email deleted' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
};

const saveDraft = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { recipient, subject, message, id } = req.body;
    try {
        if (id) {
            await Email.findByIdAndUpdate(id, { recipient, subject, message, timestamp: Date.now() });
        } else {
            await Email.create({ recipient, subject, message, status: 'draft' });
        }
        res.json({ message: 'Draft saved' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
};

module.exports = {
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
};
