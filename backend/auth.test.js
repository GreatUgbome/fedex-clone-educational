const request = require('supertest');
const bcrypt = require('bcrypt');

// --- Mocks Setup ---

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

  test('POST /api/register - should create a new user successfully', async () => {
    mockFindOne.mockResolvedValue(null); // Simulate user does not exist
    mockSave.mockResolvedValue(true);    // Simulate successful DB save

    const res = await request(app)
      .post('/api/register')
      .send({
        email: 'test@fedex.com',
        password: 'securepassword123',
        name: 'Test User'
      });

    expect(res.statusCode).toBe(201); // Assuming 201 Created is used
    expect(res.body).toHaveProperty('message');
  });

  test('POST /api/login - should authenticate user and return token', async () => {
    // Simulate finding a user with a hashed password
    const hashedPassword = await bcrypt.hash('securepassword123', 10);
    mockFindOne.mockResolvedValue({
      email: 'test@fedex.com',
      password: hashedPassword
    });

    const res = await request(app)
      .post('/api/login')
      .send({
        email: 'test@fedex.com',
        password: 'securepassword123'
      });

    // If your app issues JWT tokens or custom auth tokens
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('token');
  });

  test('POST /api/login - should fail with incorrect credentials', async () => {
    mockFindOne.mockResolvedValue(null); // Simulate user not found

    const res = await request(app)
      .post('/api/login')
      .send({
        email: 'wrong@fedex.com',
        password: 'wrongpassword'
      });

    expect(res.statusCode).toBe(401);
  });
});