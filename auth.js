const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];

  if (!token) return res.status(403).send({ message: 'No token provided.' });

  jwt.verify(token, 'rafirafi', (err, decoded) => {
    if (err) return res.status(500).send({ message: 'Failed to authenticate token.' });

    req.userId = decoded.id;
    req.role = decoded.role;
    next();
  });
};

const verifyRole = (role) => (req, res, next) => {
  if (req.role !== role) {
    return res.status(403).send({ message: 'Unauthorized role.' });
  }
  next();
};

module.exports = {
  verifyToken,
  verifyRole
};
