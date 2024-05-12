
Code:
const axios = require('axios');
const prometheus = require('prom-client');

// Istio Prometheus endpoint
const prometheusUrl = 'http://istio-prometheus:9090';

// Istio client library
const istio = require('istio-client')({
  url: 'http://istio-pilot:15010',
});

// Example: Retrieve metrics for a specific service
async function getServiceMetrics(serviceName) {
  const response = await axios.get(`${prometheusUrl}/api/v1/query`, {
    params: {
      query: `istio_requests_total{service="${serviceName}"}`,
    },
  });

  const metrics = response.data.data.result;
  console.log(`Metrics for ${serviceName}:`, metrics);
}

// Example: Retrieve metrics for all services
async function getAllServiceMetrics() {
  const response = await axios.get(`${prometheusUrl}/api/v1/query`, {
    params: {
      query: 'istio_requests_total',
    },
  });

  const metrics = response.data.data.result;
  console.log('All service metrics:', metrics);
}

// Example: Use Istio client library to retrieve metrics
async function getServiceMetricsUsingIstioClient(serviceName) {
  const response = await istio.metrics.getServiceMetrics(serviceName);
  console.log(`Metrics for ${serviceName}:`, response);
}

// Call the functions
getServiceMetrics('my-service');
getAllServiceMetrics();
getServiceMetricsUsingIstioClient('my-service');


