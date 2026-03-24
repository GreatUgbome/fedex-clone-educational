const request = require('supertest');

// --- Mocks Setup ---
// Must be defined before requiring the server

jest.mock('./middleware/auth', () => ({
    checkAuth: (req, res, next) => {
        req.user = { uid: '12345', email: 'admin@demo.com', role: 'admin' };
        next();
    },
    checkAdmin: (req, res, next) => next()
}));

jest.mock('./middleware/auditLogger', () => (req, res, next) => next());

// Mock Firebase Admin
jest.mock('firebase-admin', () => ({
  initializeApp: jest.fn(),
  auth: () => ({
    verifyIdToken: jest.fn().mockResolvedValue({ 
      email: 'admin@fedex.com', // Simulate Admin
      uid: 'test-admin-uid'
    })
  })
}));

// Mock Firebase Functions
jest.mock('firebase-functions', () => ({
  https: { onRequest: jest.fn() }
}));

// Mock Mongoose Models
const mockSave = jest.fn();
const mockFindOne = jest.fn();
const mockDeleteOne = jest.fn();
const mockSort = jest.fn().mockReturnThis();
const mockLimit = jest.fn().mockReturnValue({ sort: mockSort });
const mockSkip = jest.fn().mockReturnValue({ limit: mockLimit });
const mockFind = jest.fn().mockReturnValue({ skip: mockSkip });

class MockModel {
  constructor(data) { Object.assign(this, data); }
  save() { return mockSave(); }
  static findOne = mockFindOne;
  static deleteOne = mockDeleteOne;
  static countDocuments = jest.fn();
  static find = mockFind;
  static create = jest.fn().mockResolvedValue({});
  // Add other methods as needed
}

jest.mock('mongoose', () => {
  const original = jest.requireActual('mongoose');
  return {
    ...original,
    connect: jest.fn().mockResolvedValue({}),
    connection: { readyState: 1 }, // Simulate connected DB
    model: jest.fn(() => MockModel),
    Schema: original.Schema
  };
});

// Import app after mocks
const { app } = require('./server');

describe('Shipment API', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('POST /api/shipment - should create a new shipment', async () => {
    // Arrange
    mockFindOne.mockResolvedValue(null); // No existing shipment found
    mockSave.mockResolvedValue(true);    // Save successful

    const newShipment = {
      id: 'TEST123456',
      status: 'created',
      service: 'FedEx Ground',
      destination: 'New York, NY'
    };

    // Act
    const res = await request(app)
      .post('/api/shipment')
      .set('Authorization', 'Bearer mock-token') // Header triggers checkAuth
      .send(newShipment);

    // Assert
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('message', 'Shipment created');
    expect(res.body).toHaveProperty('id', 'TEST123456');
  });

  test('POST /api/shipment - should fail if ID is missing', async () => {
    const res = await request(app)
      .post('/api/shipment')
      .set('Authorization', 'Bearer mock-token')
      .send({ status: 'created' }); // No ID

    expect(res.statusCode).toBe(400);
    expect(res.body.errors[0]).toHaveProperty('msg', 'Tracking ID is required');
  });

  test('GET /api/track/:id - should return shipment details if found', async () => {
    const mockShipment = {
      id: '123456789012',
      status: 'delivered',
      service: 'FedEx Home Delivery'
    };
    mockFindOne.mockResolvedValue(mockShipment);

    const res = await request(app).get('/api/track/123456789012');

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual(mockShipment);
  });

  test('GET /api/track/:id - should return 404 if not found', async () => {
    mockFindOne.mockResolvedValue(null);

    const res = await request(app).get('/api/track/nonexistent');

    expect(res.statusCode).toBe(404);
    expect(res.body).toHaveProperty('error');
  });

  test('GET /api/shipments - should return paginated list for admin with search params', async () => {
    MockModel.countDocuments.mockResolvedValue(1);
    mockSort.mockResolvedValue([{ id: '123456789012', status: 'Delivered' }]);

    const res = await request(app)
      .get('/api/shipments?page=1&limit=10&search=123&sortBy=createdAt&order=desc')
      .set('Authorization', 'Bearer mock-token'); // Simulates valid admin token

    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('shipments');
    expect(res.body.shipments).toHaveLength(1);
    expect(res.body.currentPage).toBe(1);
    expect(res.body.totalPages).toBe(1);
    expect(res.body.totalShipments).toBe(1);
    
    // Verify find was called (handling the search logic)
    expect(mockFind).toHaveBeenCalled();
  });
});