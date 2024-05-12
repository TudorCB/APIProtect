


const express = require('express');
const app = express();
const reportGenerationEngine = require('./compliance-reporting/services/report-generation-engine');

app.use(express.json());

app.post('/generate-report', (req, res) => {
  const complianceStandard = req.body.complianceStandard;
  reportGenerationEngine(complianceStandard)
    .then((report) => {
      res.send(report);
    })
    .catch((error) => {
      console.error(error);
      res.status(500).send('Error generating report');
    });
});

app.listen(3000, () => {
  console.log('Server listening on port 3000');
});



