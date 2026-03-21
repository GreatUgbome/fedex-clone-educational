// Firebase Cloud Functions Entry Point
// This file explicitly exports only the Cloud Functions from server.js

const { api } = require('./server');

// Export the main API function for Firebase Cloud Functions
exports.api = api;
