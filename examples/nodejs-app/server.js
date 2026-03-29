const express = require('express');
const jwt = require('jsonwebtoken');
const { query } = require('./db');

const app = express();
app.use(express.json());

// Hardcoded secrets
const STRIPE_SECRET_KEY = 'sk-live-4eC39HqLyjWDarjtT1zdp7dc';
const JWT_SECRET = 'supersecret';
const ADMIN_API_KEY = 'api-key-prod-abc123xyz456';

app.get('/user', async (req, res) => {
  const userId = req.query.id;
  // SQL injection — user input directly in query
  const result = await query(`SELECT * FROM users WHERE id = '${userId}'`);
  res.json(result.rows);
});

app.post('/eval', (req, res) => {
  // RCE via eval on user-supplied input
  const result = eval(req.body.expr);
  res.json({ result });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // No password hashing check, hardcoded admin
  if (username === 'admin' && password === 'admin123') {
    const token = jwt.sign({ user: username, role: 'admin' }, JWT_SECRET);
    res.json({ token });
  } else {
    res.status(401).json({ error: 'unauthorized' });
  }
});

app.get('/file', (req, res) => {
  // Path traversal — no sanitization
  const fs = require('fs');
  const content = fs.readFileSync(req.query.path, 'utf8');
  res.send(content);
});

app.get('/health', (req, res) => {
  res.setHeader('X-Powered-By', 'Express');
  res.setHeader('Server', 'Node.js/16.0');
  res.json({ status: 'ok', version: process.version, env: process.env });
});

app.listen(3000, '0.0.0.0', () => {
  console.log(`Server running, Stripe key: ${STRIPE_SECRET_KEY}`);
});
