
const express = require('express');
const promClient = require('prom-client');

const app = express();

const register = new promClient.Registry();
const counter = new promClient.Counter({
  name: 'api_requests_total',
  help: 'Total API requests',
  labelNames: ['method', 'endpoint']
});

register.registerMetric(counter);

app.use(express.json());

app.post('/users', (req, res) => {
  // Process API request
  const startTime = Date.now();
  const endTime = Date.now();
  const latency = endTime - startTime;
  counter.inc({ method: 'POST', endpoint: '/users' });
  res.json({ message: 'User created successfully' });
});

app.get('/metrics', (req, res) => {
  res.set('Content-Type', 'text/plain; charset=utf-8');
  res.send(register.metrics());
});

app.listen(3001, () => {
  console.log('API Server listening on port 3001');
});


