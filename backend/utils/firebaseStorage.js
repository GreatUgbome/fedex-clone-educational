const admin = require('firebase-admin');
const crypto = require('crypto');
const path = require('path');

/**
 * Uploads a file buffer to Firebase Cloud Storage
 * @param {Object} file - The file object from multer (must use memoryStorage)
 * @returns {Promise<string>} - The public URL of the uploaded file
 */
const uploadImageToStorage = async (file) => {
  if (!file) return null;

  // Replace with your actual Firebase Storage bucket name if not using the default
  const bucketName = process.env.FIREBASE_STORAGE_BUCKET || 'fedex-37e89.appspot.com';
  const bucket = admin.storage().bucket(bucketName);
  
  const randomName = crypto.randomBytes(16).toString('hex');
  const extension = path.extname(file.originalname);
  const filename = `uploads/${randomName}${extension}`;
  
  const fileUpload = bucket.file(filename);

  const blobStream = fileUpload.createWriteStream({
    metadata: {
      contentType: file.mimetype
    }
  });

  return new Promise((resolve, reject) => {
    blobStream.on('error', (error) => {
      reject(error);
    });

    blobStream.on('finish', async () => {
      await fileUpload.makePublic();
      resolve(`https://storage.googleapis.com/${bucket.name}/${fileUpload.name}`);
    });

    blobStream.end(file.buffer);
  });
};

module.exports = { uploadImageToStorage };