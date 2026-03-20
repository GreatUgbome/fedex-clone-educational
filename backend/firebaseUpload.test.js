const request = require('supertest');
const express = require('express');
const multer = require('multer');

// 1. Mock the custom Firebase Storage utility
jest.mock('./utils/firebaseStorage', () => ({
    uploadImageToStorage: jest.fn().mockResolvedValue('https://mocked-firebase-storage-url.com/image.png')
}));

const { uploadImageToStorage } = require('./utils/firebaseStorage');

// 2. Setup a dummy Express app and route to test the implementation
const app = express();
const upload = multer({ storage: multer.memoryStorage() }); // Use memory storage for testing

app.post('/api/upload-avatar', upload.single('image'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
        const imageUrl = await uploadImageToStorage(req.file);
        res.status(200).json({ url: imageUrl });
    } catch (error) {
        res.status(500).json({ error: 'Upload failed' });
    }
});

describe('Image Upload Endpoint', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('POST /api/upload-avatar - should upload file and return Firebase URL', async () => {
        // Create a dummy buffer to simulate an image file
        const buffer = Buffer.from('dummy image content');

        const res = await request(app)
            .post('/api/upload-avatar')
            .attach('image', buffer, 'avatar.png'); // Supertest's method to simulate file uploads

        expect(res.statusCode).toBe(200);
        expect(res.body.url).toBe('https://mocked-firebase-storage-url.com/image.png');
        expect(uploadImageToStorage).toHaveBeenCalled();
    });
});