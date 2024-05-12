
const express = require('express');
const apiServer = require('./api-server');

const app = express();

app.use(express.json());
app.use('/api', apiServer);

app.listen(3000, () => {
  console.log('API Gateway listening on port 3000');
});


