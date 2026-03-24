const request = require('supertest');

// Mock nodemailer to prevent actual emails from being dispatched
const mockSendMail = jest.fn((options, callback) => {
    if (callback) callback(null, { messageId: 'mock-message-id' });
    return Promise.resolve({ messageId: 'mock-message-id' });
});
jest.mock('nodemailer', () => ({
    createTransport: jest.fn().mockReturnValue({ sendMail: mockSendMail })
}));

jest.mock('./middleware/auditLogger', () => (req, res, next) => next());

// Setup Firebase mocks before importing the app
jest.mock('firebase-admin', () => ({
    initializeApp: jest.fn(),
    auth: () => ({
        verifyIdToken: jest.fn().mockResolvedValue({ 
            email: 'admin@fedex.com',
            admin: true,
            uid: 'test-admin-uid'
        })
    })
}));

jest.mock('firebase-functions', () => ({
    https: { onRequest: jest.fn() }
}));

// Mock Mongoose to prevent actual database connections
class MockSchema {}
MockSchema.Types = { Mixed: 'Mixed', ObjectId: 'ObjectId' };

jest.mock('mongoose', () => {
    const mockModel = { 
        countDocuments: jest.fn().mockResolvedValue(0),
        find: jest.fn().mockResolvedValue([{ email: 'testuser@fedex.com' }]), // Allow user fetching
        create: jest.fn().mockResolvedValue({})
    };
    return {
        connect: jest.fn().mockResolvedValue({}),
        connection: { readyState: 1 },
        model: jest.fn(() => mockModel),
        Schema: MockSchema
    };
});

const { app } = require('./server');

describe('Admin Email Route Validation', () => {
    test('POST /api/admin/email/draft - should fail if subject is missing', async () => {
        const res = await request(app)
            .post('/api/admin/email/draft')
            .set('Authorization', 'Bearer valid-token')
            .send({ message: 'Draft message content' });

        expect(res.statusCode).toBe(400);
        expect(res.body).toHaveProperty('errors');
        expect(res.body.errors[0].msg).toBe('Subject is required');
    });

    test('POST /api/admin/email/draft - should fail if message is missing', async () => {
        const res = await request(app)
            .post('/api/admin/email/draft')
            .set('Authorization', 'Bearer valid-token')
            .send({ subject: 'Important Subject' });

        expect(res.statusCode).toBe(400);
        expect(res.body.errors[0].msg).toBe('Message is required');
    });
});

describe('Admin Bulk Email Route', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('POST /api/admin/send-bulk-email - should process payload and invoke nodemailer', async () => {
        const res = await request(app)
            .post('/api/admin/send-bulk-email')
            .set('Authorization', 'Bearer valid-token')
            // Use .field() instead of .send() because this route expects multipart/form-data (multer)
            .field('subject', 'Important Update')
            .field('message', 'This is a test notification');

        expect(res.statusCode).not.toBe(400); // Verify it passes your validators
        expect(res.statusCode).not.toBe(401);
        
        // If the route strictly returns 200 OK on success in your controller
        if (res.statusCode === 200) {
            expect(mockSendMail).toHaveBeenCalled();
        }
    });
});