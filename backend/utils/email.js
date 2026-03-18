const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

function generateEmailTemplate(title, message, buttonText, buttonLink, footer) {
    const footerContent = footer || `If the button above doesn't work, copy and paste this link into your browser: <br> <a href="${buttonLink}">${buttonLink}</a>`;
    return `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #4D148C;">${title}</h2>
            <p>${message}</p>
            <p style="text-align: center; margin: 30px 0;">
                <a href="${buttonLink}" style="background-color: #FF6200; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">${buttonText}</a>
            </p>
            <p style="font-size: 12px; color: #666;">${footerContent}</p>
        </div>
    `;
}

function sendStatusEmail(shipmentId, newStatus) {
    const mailOptions = {
        from: 'fedex-cl@noreply.com',
        to: 'recipient@example.com', // In a real app, this would be shipment.recipientEmail
        subject: `Shipment Update: ${shipmentId}`,
        text: `The status of your shipment ${shipmentId} has changed to: ${newStatus}`
    };
    transporter.sendMail(mailOptions, (err) => {
        if (err) console.log('Email error:', err);
    });
}

module.exports = {
    generateEmailTemplate,
    sendStatusEmail,
    transporter
};
