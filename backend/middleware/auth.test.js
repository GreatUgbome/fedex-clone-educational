const { checkAuth, checkAdmin } = require('./auth');
const admin = require('firebase-admin');

// Mock Firebase Admin
jest.mock('firebase-admin', () => ({
    auth: () => ({
        verifyIdToken: jest.fn()
    })
}));

describe('Authentication Middleware', () => {
    let req, res, next;

    beforeEach(() => {
        req = { headers: {} };
        res = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn()
        };
        next = jest.fn();
        jest.clearAllMocks();
    });

    describe('checkAuth', () => {
        test('should return 401 if no authorization header is provided', async () => {
            await checkAuth(req, res, next);
            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: expect.stringContaining('No token provided') }));
            expect(next).not.toHaveBeenCalled();
        });

        test('should return 401 if authorization header is improperly formatted', async () => {
            req.headers.authorization = 'Basic somerandomtoken';
            await checkAuth(req, res, next);
            expect(res.status).toHaveBeenCalledWith(401);
            expect(next).not.toHaveBeenCalled();
        });

        test('should set req.user and call next if token is valid', async () => {
            req.headers.authorization = 'Bearer valid-firebase-token';
            const mockDecodedToken = { uid: '12345', email: 'test@fedex.com' };
            admin.auth().verifyIdToken.mockResolvedValue(mockDecodedToken);
            
            await checkAuth(req, res, next);
            
            expect(req.user).toEqual(mockDecodedToken);
            expect(next).toHaveBeenCalled();
        });

        test('should return 401 if token verification fails', async () => {
            req.headers.authorization = 'Bearer invalid-token';
            admin.auth().verifyIdToken.mockRejectedValue(new Error('Token expired'));
            
            await checkAuth(req, res, next);
            expect(res.status).toHaveBeenCalledWith(401);
            expect(next).not.toHaveBeenCalled();
        });
    });

    describe('checkAdmin', () => {
        test('should return 401 if user is completely unauthenticated (no req.user)', async () => {
            await checkAdmin(req, res, next);
            expect(res.status).toHaveBeenCalledWith(401);
        });

        test('should return 403 if user lacks admin claim', async () => {
            req.user = { email: 'user@fedex.com', admin: false };
            await checkAdmin(req, res, next);
            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: expect.stringContaining('Forbidden') }));
        });

        test('should call next if user has admin claim', async () => {
            req.user = { email: 'admin@fedex.com', admin: true };
            await checkAdmin(req, res, next);
            expect(next).toHaveBeenCalled();
        });
    });
});