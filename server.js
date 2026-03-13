const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const PRIVATE_KEY_PATH = path.join(__dirname, 'private.key');
const PUBLIC_KEY_PATH = path.join(__dirname, 'public.key');

let PRIVATE_KEY;
let PUBLIC_KEY;
try {
  PRIVATE_KEY = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
  PUBLIC_KEY = fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
  console.log('Using RS256 JWT keys from private.key/public.key');
} catch (err) {
  console.warn('RSA key pair not found; falling back to HS256 JWT');
}

const useRS256 = !!(PRIVATE_KEY && PUBLIC_KEY);

const signJwt = (payload) => {
  const options = { expiresIn: '1h' };
  if (useRS256) {
    return jwt.sign(payload, PRIVATE_KEY, { ...options, algorithm: 'RS256' });
  }
  return jwt.sign(payload, JWT_SECRET, options);
};

const signResetToken = (payload) => {
  const options = { expiresIn: '15m' }; // reset token short-lived
  if (useRS256) {
    return jwt.sign(payload, PRIVATE_KEY, { ...options, algorithm: 'RS256' });
  }
  return jwt.sign(payload, JWT_SECRET, options);
};

const verifyJwt = (token) => {
  if (useRS256) {
    return jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });
  }
  return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
};

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// In-memory users for demo (replace with DB later)
let users = [
  {
    id: 1,
    email: 'test@gmail.com',
    password: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // hash of 'password'
    name: 'An'
  }
];

// In-memory reset tokens for demo (replace with DB later)
let resetTokens = [];

// Auth Middleware
const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = verifyJwt(token);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Routes
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/views/index.html');
});

// Register API (for testing)
app.post('/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword, name });
    await user.save();
    res.json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Login API
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);

    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid password' });
    }

    const token = signJwt({ id: user.id, email: user.email });
    res.json({ token, algo: useRS256 ? 'RS256' : 'HS256' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// /me API
app.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = users.find(u => u.id === req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    const { password, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Change Password API
app.post('/changepassword', authMiddleware, async (req, res) => {
  try {
    const { oldpassword, newpassword } = req.body;

    if (!oldpassword || !newpassword) {
      return res.status(400).json({ message: 'oldpassword and newpassword are required' });
    }

    // Basic password validation (adjust as needed)
    const isValidPassword = (pwd) => {
      const minLength = 8;
      const hasUpper = /[A-Z]/.test(pwd);
      const hasLower = /[a-z]/.test(pwd);
      const hasDigit = /[0-9]/.test(pwd);
      const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(pwd);
      return pwd.length >= minLength && hasUpper && hasLower && hasDigit && hasSpecial;
    };

    if (!isValidPassword(newpassword)) {
      return res.status(400).json({
        message:
          'newpassword must be at least 8 characters and include upper, lower, number, and special character'
      });
    }

    const user = users.find((u) => u.id === req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isMatch = await bcrypt.compare(oldpassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Old password is incorrect' });
    }

    user.password = await bcrypt.hash(newpassword, 10);
    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Forgot Password API
app.post('/forgotpassword', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }

    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    // Generate reset token
    const resetToken = signResetToken({ id: user.id, email: user.email });
    resetTokens.push({ token: resetToken, userId: user.id, expires: Date.now() + 15 * 60 * 1000 }); // 15 min

    console.log('forgotpassword: generated resetToken', resetToken);
    console.log('forgotpassword: active resetTokens count', resetTokens.length);

    // In real app, send email with resetToken
    res.json({ message: 'Reset token generated', resetToken }); // For demo, return token directly
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Reset Password API
app.post('/resetpassword', async (req, res) => {
  try {
    const { resetToken, newpassword } = req.body;

    if (!resetToken || !newpassword) {
      return res.status(400).json({ message: 'resetToken and newpassword are required' });
    }

    // Basic password validation (same as changepassword)
    const isValidPassword = (pwd) => {
      const minLength = 8;
      const hasUpper = /[A-Z]/.test(pwd);
      const hasLower = /[a-z]/.test(pwd);
      const hasDigit = /[0-9]/.test(pwd);
      const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(pwd);
      return pwd.length >= minLength && hasUpper && hasLower && hasDigit && hasSpecial;
    };

    if (!isValidPassword(newpassword)) {
      return res.status(400).json({
        message: 'newpassword must be at least 8 characters and include upper, lower, number, and special character'
      });
    }

    // Verify reset token
    let decoded;
    try {
      decoded = verifyJwt(resetToken);
    } catch (error) {
      return res.status(400).json({ message: 'Invalid or expired reset token' });
    }

    const tokenEntry = resetTokens.find(t => t.token === resetToken && t.userId === decoded.id);
    console.log('resetpassword: provided resetToken', resetToken);
    console.log('resetpassword: found tokenEntry', tokenEntry);
    console.log('resetpassword: active resetTokens count', resetTokens.length);
    if (!tokenEntry || tokenEntry.expires < Date.now()) {
      return res.status(400).json({ message: 'Invalid or expired reset token' });
    }

    const user = users.find(u => u.id === decoded.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.password = await bcrypt.hash(newpassword, 10);
    // Remove used token
    resetTokens = resetTokens.filter(t => t.token !== resetToken);

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
