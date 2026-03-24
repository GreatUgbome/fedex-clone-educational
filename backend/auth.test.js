const request = require('supertest');
const bcrypt = require('bcryptjs');

// --- Mocks Setup ---

jest.mock('./middleware/auditLogger', () => (req, res, next) => next());

// Mock nodemailer to prevent real emails from being sent and hanging Jest
jest.mock('nodemailer', () => ({
    createTransport: jest.fn().mockReturnValue({
        sendMail: jest.fn((options, callback) => {
            if (callback) callback(null, { messageId: 'mock-message-id' });
            return Promise.resolve({ messageId: 'mock-message-id' });
        })
    })
}));

// Mock Firebase Admin
jest.mock('firebase-admin', () => ({
  initializeApp: jest.fn(),
  auth: () => ({
    verifyIdToken: jest.fn().mockResolvedValue({ 
      email: 'admin@fedex.com',
      uid: 'test-admin-uid'
    })
  }),
  storage: jest.fn()
}));

// Mock Firebase Functions
jest.mock('firebase-functions', () => ({
  https: { onRequest: jest.fn() }
}));

// Mock Mongoose Models
const mockSave = jest.fn();
const mockFindOne = jest.fn();

class MockUser {
  constructor(data) { Object.assign(this, data); }
  save() { return mockSave(); }
  static findOne = mockFindOne;
  static create = jest.fn().mockResolvedValue({});
}

jest.mock('mongoose', () => {
  const original = jest.requireActual('mongoose');
  return {
    ...original,
    connect: jest.fn().mockResolvedValue({}),
    connection: { readyState: 1 },
    model: jest.fn(() => MockUser),
    Schema: original.Schema
  };
});

const { app } = require('./server');

describe('Authentication API', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('POST /api/auth/signup - should create a new user successfully', async () => {
    mockFindOne.mockResolvedValue(null); // Simulate user does not exist
    mockSave.mockResolvedValue(true);    // Simulate successful DB save

    const res = await request(app)
      .post('/api/auth/signup')
      .send({
        email: 'test@fedex.com',
        password: 'SecurePassword123!',
        username: 'testuser'
      });

    expect(res.statusCode).toBe(200); // Controller returns 200 OK
    expect(res.body).toHaveProperty('message');
  });

  test('POST /api/auth/login - should authenticate user and return token', async () => {
    // Simulate finding a user with a hashed password
    const hashedPassword = await bcrypt.hash('SecurePassword123!', 10);
    mockFindOne.mockResolvedValue({
      username: 'testuser',
      password: hashedPassword,
      isVerified: true
    });

    const res = await request(app)
      .post('/api/auth/login')
      .send({
        username: 'testuser',
        password: 'SecurePassword123!'
      });

    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('username', 'testuser');
  });

  test('POST /api/auth/login - should fail with incorrect credentials', async () => {
    mockFindOne.mockResolvedValue(null); // Simulate user not found

    const res = await request(app)
      .post('/api/auth/login')
      .send({
        username: 'wronguser',
        password: 'WrongPassword123!'
      });

    expect(res.statusCode).toBe(401);
  });
});