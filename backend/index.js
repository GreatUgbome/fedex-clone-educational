// Firebase Cloud Functions Entry Point
// This file exports all Cloud Functions from server.js

const { api, app } = require('./server');

// Export the main API function for Firebase Cloud Functions
exports.api = api;

// Export app for testing
exports.app = app;
