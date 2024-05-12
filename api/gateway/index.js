
const express = require('express');
const app = express();
const rateLimit = require('express-rate-limit');
const authenticate = require('./authenticate');

app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  delayMs: 0 // disable delaying - full speed until the max limit is reached
}));

app.use(authenticate);

app.use('/api', require('./api-backend'));

app.listen(3000, () => {
  console.log('API gateway listening on port 3000');
});
