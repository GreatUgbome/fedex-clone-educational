const request = require('supertest');
const express = require('express');
const { exportAuditLogsToCSV } = require('./controllers/audit');

// Mock Mongoose AuditLog Model so we don't hit the real DB
jest.mock('./models/auditLog', () => ({
    find: jest.fn().mockReturnThis(),
    sort: jest.fn().mockReturnThis(),
    lean: jest.fn().mockResolvedValue([
        {
            _id: 'log_123',
            action: 'DELETE /api/users/1',
            user: 'admin@fedex.com',
            target: 'User1',
            createdAt: '2023-10-31T12:00:00.000Z'
        }
    ])
}));

const app = express();
app.get('/api/audit-logs/export', exportAuditLogsToCSV);

describe('Audit Logs Export API', () => {
    test('GET /api/audit-logs/export - should return a correct CSV structure', async () => {
        const res = await request(app).get('/api/audit-logs/export');

        // Validate basic HTTP constraints
        expect(res.statusCode).toBe(200);
        expect(res.headers['content-type']).toContain('text/csv');
        expect(res.headers['content-disposition']).toBe('attachment; filename="audit_logs.csv"');

        // Validate CSV content headers and rows
        const csvContent = res.text;
        expect(csvContent).toContain('Log ID,Action,User,Target,Date');
        expect(csvContent).toContain('"log_123"');
        expect(csvContent).toContain('"DELETE /api/users/1"');
        expect(csvContent).toContain('"admin@fedex.com"');
        expect(csvContent).toContain('"User1"');
        expect(csvContent).toContain('"2023-10-31T12:00:00.000Z"'); // Expect parsed ISO string
    });
});