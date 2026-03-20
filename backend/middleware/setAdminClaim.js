require('dotenv').config();
const admin = require('firebase-admin');

// Initialize Firebase Admin (ensure your FIREBASE_APPLICATION_CREDENTIALS or default config is available)
if (!admin.apps.length) {
    admin.initializeApp();
}

const makeAdmin = async (email) => {
    try {
        const user = await admin.auth().getUserByEmail(email);
        await admin.auth().setCustomUserClaims(user.uid, { admin: true });
        console.log(`✅ Success! The admin claim has been granted to: ${email}`);
        console.log('Note: The user must log out and log back in to refresh their token.');
        process.exit(0);
    } catch (error) {
        console.error('❌ Error setting admin claim:', error.message);
        process.exit(1);
    }
};

const targetEmail = process.argv[2];
if (!targetEmail) {
    console.log('Usage: node scripts/setAdminClaim.js <user@example.com>');
    process.exit(1);
}

makeAdmin(targetEmail);