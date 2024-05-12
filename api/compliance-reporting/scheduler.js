

const nodeSchedule = require('node-schedule');
const reportGenerator = require('./report-generator');

nodeSchedule.scheduleJob('0 0 * * *', async () => {
  try {
    const pdfDoc = await reportGenerator('PCI DSS');
    // Store the generated report in a database or file system
    console.log('Report generated successfully!');
  } catch (error) {
    console.error('Error generating report:', error);
  }
});


