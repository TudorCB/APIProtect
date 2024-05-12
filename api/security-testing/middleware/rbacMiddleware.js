
const express = require('express');
const app = express();

// Mock user role retrieval
const getUserRole = (req) => {
  // Assume req.user.role is set by authentication middleware
  return req.user.role;
};

// RBAC middleware
const rbac = (req, res, next) => {
  const userRole = getUserRole(req);
  const requiredRole = req.route.role;

  if (!requiredRole || userRole === requiredRole) {
    return next();
  }

  return res.status(403).json({ error: 'Forbidden' });
};

// Example API endpoint with RBAC
app.get('/admin-only', rbac, (req, res) => {
  res.json({ message: 'Admin-only endpoint' });
});

app.route('/admin-only').role = 'admin';

app.listen(3000, () => {
  console.log('Server listening on port 3000');
});


