

const MongoClient = require('mongodb').MongoClient;
const mongoose = require('mongoose');
const crypto = require('crypto');

// Mock MongoDB connection
const client = new MongoClient('mongodb://localhost:27017/', { useNewUrlParser: true, useUnifiedTopology: true });
const db = client.db();

// Define a schema for encrypted data
const encryptedDataSchema = new mongoose.Schema({
  sensitiveData: {
    type: String,
    // Mock encryption using a simple hash for demonstration purposes
    set: (value) => crypto.createHash('sha256').update(value).digest('hex'),
  },
});

// Create a model for encrypted data
const EncryptedData = mongoose.model('EncryptedData', encryptedDataSchema);

// Example data to encrypt
const dataToEncrypt = 'Sensitive information';

// Encrypt the data
const encryptedData = new EncryptedData({ sensitiveData: dataToEncrypt });
encryptedData.save((err, doc) => {
  if (err) {
    console.error(err);
  } else {
    console.log('Data encrypted and saved:', doc);
  }
});


