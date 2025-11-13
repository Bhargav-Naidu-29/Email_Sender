const jwt = require('jsonwebtoken');
const User = require('../models/User');

const JWT_SECRET = process.env.SECRET_KEY || (process.env.NODE_ENV !== 'production' ? 'dev_secret_change_me' : undefined);

const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'No authentication token provided' });
    }
    if (!JWT_SECRET) {
      return res.status(500).json({ success: false, message: 'Server missing SECRET_KEY configuration' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded._id || decoded.userId;
    const user = await User.findById(userId);

    if (!user) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }

    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    res.status(401).json({ success: false, message: 'Authentication failed', error: error.message });
  }
};

module.exports = auth; 