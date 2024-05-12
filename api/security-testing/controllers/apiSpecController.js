
const express = require('express');
const MongoClient = require('mongodb').MongoClient;
const app = express();

// MongoDB connection details
const url = 'mongodb://localhost:27017';
const dbName = 'securityScanDB';
const collectionName = 'vulnerabilities';

// API endpoint to retrieve vulnerability data
app.get('/api/vulnerabilities', async (req, res) => {
  try {
    // Establish MongoDB connection
    const client = new MongoClient(url);
    await client.connect();
    const db = client.db(dbName);
    const collection = db.collection(collectionName);

    // Parse query parameters
    const scanType = req.query.scanType;
    const severity = req.query.severity;
    const dateRange = req.query.dateRange;
    const project = req.query.project;

    // Validate dateRange parameter
    if (dateRange && (!Array.isArray(dateRange) || dateRange.length !== 2)) {
      return res.status(400).json({ error: 'Invalid dateRange parameter' });
    }

    // Build query object
    const query = {};
    if (scanType) query.scanType = scanType;
    if (severity) query.severity = severity;
    if (dateRange) query.date = { $gte: dateRange[0], $lte: dateRange[1] };
    if (project) query.project = project;

    // Retrieve and aggregate data
    const data = await collection.find(query).toArray();
    const aggregatedData = aggregateData(data);

    // Format data into JSON structure
    const response = {
      vulnerabilities: aggregatedData,
    };

    res.json(response);

    // Close MongoDB connection
    await client.close();
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Helper function to aggregate data
function aggregateData(data) {
  // Implement aggregation logic here
  // For example, count vulnerabilities by severity
  const aggregatedData = {};
  data.forEach((item) => {
    if (!item.severity) {
      console.warn('Item does not have a severity property:', item);
      return;
    }
    if (!aggregatedData[item.severity]) aggregatedData[item.severity] = 0;
    aggregatedData[item.severity]++;
  });
  return aggregatedData;
}

app.listen(3000, () => {
  console.log('API endpoint listening on port 3000');
});




