const request = require('supertest');

jest.mock('./middleware/auditLogger', () => (req, res, next) => next());

// --- Mocks Setup ---
jest.mock('firebase-admin', () => ({
    initializeApp: jest.fn(),
}));

jest.mock('firebase-functions', () => ({
    https: { onRequest: jest.fn() }
}));

// Mock Mongoose Models to prevent database errors during tests
class MockSchema {}
MockSchema.Types = { Mixed: 'Mixed', ObjectId: 'ObjectId' };

jest.mock('mongoose', () => ({
    connect: jest.fn().mockResolvedValue({}),
    connection: { readyState: 1 },
    model: jest.fn(() => {
        return class MockModel {
            constructor() {}
            save() { return Promise.resolve(); }
            static findOne() { return Promise.resolve(null); }
        };
    }),
    Schema: MockSchema
}));

const { app } = require('./server');

describe('Strict Rate Limiters', () => {
    const targetUrl = '/api/auth/login';

    test('should block requests after 5 attempts from the same IP', async () => {
        const spoofedIp = '198.51.100.1'; // Fake IP Address

        // Send 5 initial requests (should not be rate limited)
        for (let i = 0; i < 5; i++) {
            const res = await request(app)
                .post(targetUrl)
                .set('X-Forwarded-For', spoofedIp)
                .send({ username: 'testuser', password: 'password' });
            
            // Expect validation or auth failure (400/401), NOT 429
            expect(res.statusCode).not.toBe(429);
        }

        // The 6th request should hit the rate limiter
        const rateLimitedRes = await request(app)
            .post(targetUrl)
            .set('X-Forwarded-For', spoofedIp)
            .send({ username: 'testuser', password: 'password' });

        expect(rateLimitedRes.statusCode).toBe(429);
        expect(rateLimitedRes.body.error).toContain('Too many login attempts');
    });

    test('should NOT block whitelisted IPs even after 5 attempts', async () => {
        const whitelistedIp = '127.0.0.1'; // Part of the default whitelist

        // Send 6 requests using the whitelisted IP
        for (let i = 0; i < 6; i++) {
            const res = await request(app)
                .post(targetUrl)
                .set('X-Forwarded-For', whitelistedIp)
                .send({ username: 'testuser', password: 'password' });
            
            expect(res.statusCode).not.toBe(429);
        }
    });
});