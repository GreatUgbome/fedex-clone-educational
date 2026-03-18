const Shipment = require('../models/shipment');
const { logActivity } = require('../utils/activity');
const { sendStatusEmail } = require('../utils/email');

const { validationResult } = require('express-validator');

const createShipment = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { id, ...data } = req.body;
    
    const existing = await Shipment.findOne({ id });
    if (existing) return res.status(400).json({ error: 'Shipment already exists' });
    
    const newShipment = new Shipment({ id, ...data });
    await newShipment.save();
    if (data.createdBy) {
        await logActivity(data.createdBy, 'Create Shipment', `Created shipment ${id}`);
    }
    res.json({ message: 'Shipment created', id, data: newShipment });
};

const updateShipment = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { id } = req.params;
    const updates = req.body;
    
    const shipment = await Shipment.findOne({ id });
    if (!shipment) return res.status(404).json({ error: 'Shipment not found' });

    // If status changed, send email
    if (updates.status && updates.status !== shipment.status) {
        sendStatusEmail(id, updates.status);
        await logActivity('System', 'Status Update', `Shipment ${id} updated to ${updates.status}`);
    }

    Object.assign(shipment, updates);
    await shipment.save();
    res.json({ message: 'Shipment updated' });
};

const deleteShipment = async (req, res) => {
    const { id } = req.params;
    try {
        const result = await Shipment.deleteOne({ id });
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Shipment not found' });
        }
        res.json({ message: 'Shipment deleted successfully' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
};

const trackShipment = async (req, res) => {
    const { id } = req.params;
    const data = await Shipment.findOne({ id });
    if (data) {
        res.json(data);
    } else {
        res.status(404).json({ error: 'Tracking ID not found' });
    }
};

const getAllShipments = async (req, res) => {
    const ships = await Shipment.find({}, 'id status service');
    res.json(ships);
};

const exportShipments = async (req, res) => {
    const ships = await Shipment.find({});
    res.json(ships);
};

module.exports = {
    createShipment,
    updateShipment,
    deleteShipment,
    trackShipment,
    getAllShipments,
    exportShipments
};
