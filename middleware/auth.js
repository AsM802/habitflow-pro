const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'habitflow-super-secret-key-365days-persist';

function generateToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '365d' });
}

function requireAuth(req, res, next) {
  let token = req.cookies ? req.cookies.token : null;
  if (!token && req.headers.authorization) {
    const parts = req.headers.authorization.split(' ');
    if (parts.length === 2 && parts[0] === 'Bearer') {
      token = parts[1];
    }
  }
  if (!token && req.headers['x-auth-token']) {
    token = req.headers['x-auth-token'];
  }

  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

module.exports = { generateToken, requireAuth, JWT_SECRET };

