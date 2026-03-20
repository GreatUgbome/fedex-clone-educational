const express = require('express');
const router = express.Router();
const { createShipment, updateShipment, deleteShipment, trackShipment, exportShipments } = require('../controllers/shipment');
const Shipment = require('../models/shipment'); // Added Model import
const { checkAuth, checkAdmin } = require('../middleware/auth');
const { body, param } = require('express-validator');

router.post('/shipment',
    checkAuth,
    checkAdmin,
    body('id').notEmpty().withMessage('Tracking ID is required'),
    body('status').notEmpty().withMessage('Status is required'),
    body('service').notEmpty().withMessage('Service is required'),
    body('destination').notEmpty().withMessage('Destination is required'),
    createShipment
);

router.put('/shipment/:id',
    checkAuth,
    checkAdmin,
    param('id').notEmpty().withMessage('Shipment ID is required'),
    updateShipment
);

router.delete('/shipment/:id', checkAuth, checkAdmin, deleteShipment);
router.get('/track/:id', trackShipment);

// Bulk delete shipments
router.delete('/shipments/bulk', checkAuth, checkAdmin, async (req, res) => {
    try {
        const { ids } = req.body;
        
        if (!ids || !Array.isArray(ids) || ids.length === 0) {
            return res.status(400).json({ error: 'No shipment IDs provided for deletion' });
        }

        const result = await Shipment.deleteMany({ id: { $in: ids } });
        
        res.status(200).json({ message: `Successfully deleted ${result.deletedCount} shipment(s)` });
    } catch (error) {
        console.error('Bulk delete error:', error);
        res.status(500).json({ error: 'Server error during bulk deletion' });
    }
});

// Bulk update shipments status
router.put('/shipments/bulk-status', checkAuth, checkAdmin, async (req, res) => {
    try {
        const { ids, status } = req.body;
        
        if (!ids || !Array.isArray(ids) || ids.length === 0) {
            return res.status(400).json({ error: 'No shipment IDs provided for update' });
        }
        if (!status) {
            return res.status(400).json({ error: 'Status is required' });
        }

        const result = await Shipment.updateMany({ id: { $in: ids } }, { $set: { status: status } });
        
        res.status(200).json({ message: `Successfully updated ${result.modifiedCount} shipment(s)` });
    } catch (error) {
        console.error('Bulk status update error:', error);
        res.status(500).json({ error: 'Server error during bulk status update' });
    }
});

// Server-side pagination and search for shipments
router.get('/shipments', checkAuth, checkAdmin, async (req, res) => {
    try {
        const page = parseInt(req.query.page, 10) || 1;
        const limit = parseInt(req.query.limit, 10) || 10;
        const search = req.query.search || '';
        const sortBy = req.query.sortBy || 'createdAt';
        const order = req.query.order === 'asc' ? 1 : -1;
        
        const query = {};
        if (search) {
            query.$or = [
                { id: { $regex: search, $options: 'i' } },
                { status: { $regex: search, $options: 'i' } },
                { recipient: { $regex: search, $options: 'i' } }
            ];
        }

        const sortQuery = { [sortBy]: order };
        const skip = (page - 1) * limit;
        const total = await Shipment.countDocuments(query);
        const shipments = await Shipment.find(query).skip(skip).limit(limit).sort(sortQuery);

        res.status(200).json({ shipments, currentPage: page, totalPages: Math.ceil(total / limit) || 1, totalShipments: total });
    } catch (error) {
        res.status(500).json({ error: 'Server error fetching shipments' });
    }
});
router.get('/shipments/export', checkAuth, checkAdmin, exportShipments);

module.exports = router;
