const express = require('express');
const router = express.Router();
const { submitFeedback, getSettings, updateSettings, schedulePickup } = require('../controllers/main');

router.post('/feedback', submitFeedback);
router.get('/settings', getSettings);
router.put('/settings', updateSettings);
router.post('/pickup', schedulePickup);

module.exports = router;
