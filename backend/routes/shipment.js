const express = require('express');
const router = express.Router();
const { createShipment, updateShipment, deleteShipment, trackShipment, getAllShipments, exportShipments } = require('../controllers/shipment');
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
router.get('/shipments', checkAuth, checkAdmin, getAllShipments);
router.get('/shipments/export', checkAuth, checkAdmin, exportShipments);

module.exports = router;
