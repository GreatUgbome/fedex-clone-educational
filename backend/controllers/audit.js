// Adjust this path if your model is named differently
const AuditLog = require('../models/auditLog'); 

/**
 * Fetches all audit logs and returns them as a downloadable CSV file
 */
const exportAuditLogsToCSV = async (req, res) => {
    try {
        // Fetch all logs from the database, newest first
        // Using .lean() makes the query faster by returning plain objects
        const logs = await AuditLog.find().sort({ createdAt: -1 }).lean();

        // Set appropriate headers to force the browser to trigger a download
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="audit_logs.csv"');

        // 1. Generate the CSV Header row
        const csvHeaders = ['Log ID', 'Action', 'User', 'Target', 'Date'];
        let csvContent = csvHeaders.join(',') + '\n';

        // 2. Iterate through logs and append them as rows
        logs.forEach(log => {
            const row = [
                `"${log._id || ''}"`,
                `"${log.action || ''}"`,
                `"${log.user || 'System'}"`, // Escaping with quotes in case strings contain commas
                `"${log.target || 'N/A'}"`,
                `"${new Date(log.createdAt).toISOString()}"`
            ];
            csvContent += row.join(',') + '\n';
        });

        return res.status(200).send(csvContent);
    } catch (error) {
        console.error('CSV Export Error:', error);
        return res.status(500).json({ error: 'Failed to export audit logs to CSV' });
    }
};

module.exports = {
    exportAuditLogsToCSV
};