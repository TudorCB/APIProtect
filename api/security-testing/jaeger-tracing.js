
const { initTracer } = require('jaeger-client');

// Initialize Jaeger tracer
const tracer = initTracer('my-service', {
  sampler: {
    type: 'const',
    param: 1, // sample every request
  },
  reporter: {
    collectorEndpoint: 'http://jaeger-collector:14250/api/traces',
  },
});

// Create a middleware to start a new trace for each incoming request
const jaegerMiddleware = (req, res, next) => {
  const span = tracer.startSpan('http_request', {
    tags: {
      'http.method': req.method,
      'http.url': req.url,
    },
  });

  res.on('finish', () => {
    span.finish();
  });

  next();
};

// Example usage:
const express = require('express');
const app = express();

app.use(jaegerMiddleware);

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(3000, () => {
  console.log('Server listening on port 3000');
});


