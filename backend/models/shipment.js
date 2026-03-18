const mongoose = require('mongoose');

const ShipmentSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    status: String,
    statusDetail: String,
    service: String,
    deliveryDate: String,
    weight: String,
    dimensions: String,
    pieces: Number,
    destination: String,
    coordinates: { lat: Number, lng: Number },
    sender: String,
    recipient: String,
    timeline: [{
        date: String,
        status: String,
        location: String,
        icon: String
    }],
    proofOfDelivery: String,
    createdBy: String
});

module.exports = mongoose.model('Shipment', ShipmentSchema);
