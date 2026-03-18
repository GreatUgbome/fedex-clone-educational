const Activity = require('../models/activity');

async function logActivity(username, action, details) {
    try {
        await Activity.create({ username, action, details });
    } catch (e) {
        console.error("Activity Log Error:", e);
    }
}

module.exports = {
    logActivity
};
