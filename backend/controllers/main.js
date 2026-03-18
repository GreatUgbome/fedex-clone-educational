const Feedback = require('../models/feedback');
const Setting = require('../models/setting');
const Pickup = require('../models/pickup');

const submitFeedback = async (req, res) => {
    try {
        const feedback = new Feedback(req.body);
        await feedback.save();
        res.json({ message: 'Thank you for your feedback!' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
};

const getSettings = async (req, res) => {
    try {
        const settings = await Setting.find({});
        const settingsMap = {};
        settings.forEach(s => settingsMap[s.key] = s.value);
        res.json(settingsMap);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
};

const updateSettings = async (req, res) => {
    const { key, value } = req.body;
    await Setting.findOneAndUpdate({ key }, { value }, { upsert: true });
    res.json({ message: 'Setting updated' });
};

const schedulePickup = async (req, res) => {
    try {
        const pickup = new Pickup(req.body);
        await pickup.save();
        res.json({ message: 'Pickup scheduled successfully', id: pickup._id });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
};

module.exports = {
    submitFeedback,
    getSettings,
    updateSettings,
    schedulePickup
};
