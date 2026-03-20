const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
    action: { type: String, required: true },
    user: { type: String, required: true, default: 'System' },
    target: { type: String },
    details: { type: mongoose.Schema.Types.Mixed } // Allows flexible logging details
}, {
    timestamps: true
});

module.exports = mongoose.model('AuditLog', auditLogSchema);