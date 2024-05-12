

const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const app = express();

// OAuth 2.0 configuration
const clientId = process.env.GOOGLE_CLIENT_ID;
const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
const callbackURL = '/auth/google/callback';

// Passport.js configuration
passport.use(new GoogleStrategy({
  clientID: clientId,
  clientSecret: clientSecret,
  callbackURL: callbackURL,
}, (accessToken, refreshToken, profile, cb) => {
  // Retrieve user information from Google
  const user = {
    id: profile.id,
    name: profile.displayName,
    email: profile.emails[0].value,
  };

  // Create or update user account in your system
  // ...

  return cb(null, user);
}));

// Authentication routes
app.get('/auth/google', passport.authenticate('google', {
  scope: ['profile', 'email'],
}));

app.get('/auth/google/callback', passport.authenticate('google', {
  failureRedirect: '/login',
}), (req, res) => {
  res.redirect('/protected');
});

// Protected route
app.get('/protected', (req, res) => {
  res.send(`Hello, ${req.user.name}!`);
});

app.listen(3000, () => {
  console.log('Server listening on port 3000');
});


