const mongoose = require('mongoose');

const PickupSchema = new mongoose.Schema({
    address: String,
    date: String,
    time: String,
    packages: Number,
    weight: String,
    instructions: String,
    status: { type: String, default: 'Scheduled' }
});

module.exports = mongoose.model('Pickup', PickupSchema);
