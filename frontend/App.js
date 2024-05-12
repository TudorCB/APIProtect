

import React, { useState, useEffect } from 'react';
import axios from 'axios';

function App() {
  const [user, setUser] = useState(null);
  const [roles, setRoles] = useState([]);

  useEffect(() => {
    // Attach token to headers if available
    const token = localStorage.getItem('authToken');
    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;

    axios.get('/api/v1/users/me')
      .then(response => {
        setUser(response.data);
      })
      .catch(error => {
        console.error(error);
      });
  }, []);

  // ... similar effect for roles

  if (!user) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      <h1>Welcome, {user.username}!</h1>
      <ul>
        {roles.map(role => (
          <li key={role._id}>{role.name}</li>
        ))}
      </ul>
      {user.roles.includes('admin') && (
        <button onClick={() => console.log('Admin button clicked!')}>
          Admin Button
        </button>
      )}
    </div>
  );
}

export default App;


