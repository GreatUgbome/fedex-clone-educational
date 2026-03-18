const mongoose = require('mongoose');

const LocationSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    name: String,
    address: String,
    type: String,
});

module.exports = mongoose.model('Location', LocationSchema);
