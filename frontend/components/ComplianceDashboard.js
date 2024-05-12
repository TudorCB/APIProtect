

import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts';
import axios from 'axios';

function ComplianceDashboard() {
  const [complianceData, setComplianceData] = useState({});

  useEffect(() => {
    axios.get('/api/compliance-data')
      .then((response) => {
        setComplianceData(response.data);
      })
      .catch((error) => {
        console.error('Error fetching compliance data:', error);
      });
  }, []);

  return (
    <div>
      <h1>Compliance Dashboard</h1>
      <LineChart width={500} height={300} data={complianceData.trends}>
        <Line type="monotone" dataKey="complianceScore" stroke="#8884d8" />
        <XAxis dataKey="date" />
        <YAxis />
        <CartesianGrid stroke="#ccc" strokeDasharray="5 5" />
        <Tooltip />
      </LineChart>
      <ul>
        {complianceData.controls.map((control) => (
          <li key={control._id}>
            <span>{control.name}</span>
            <span>{control.status}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default ComplianceDashboard;


