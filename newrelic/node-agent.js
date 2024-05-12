

const newrelic = require('newrelic');

newrelic.instrument({
  // Your New Relic license key
  licenseKey: 'YOUR_LICENSE_KEY',
  // Your application name
  appName: 'API Performance Monitoring System',
  // Your transaction name
  transactionName: 'API Request',
  // Enable or disable error collection
  errorCollector: {
    enabled: true
  }
});

