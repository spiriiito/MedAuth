const express = require('express');
const { register, login, passwordUpgrade, me } = require('../controllers/authController');
const { authRequired } = require('../middleware/auth');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/password-upgrade', passwordUpgrade);
router.get('/me', authRequired, me);

module.exports = router;
