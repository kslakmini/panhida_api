const express = require('express');
const { Audit } = require('../models/index');

const router = express.Router();
const checkAuth = require('../middleware/auth');
const db = require('../models/index');

router.get('/', checkAuth, async (req, res) => {
  try {
    const isUserValid = await db.User.findById(res.user.id);
    let data = [];
    if (isUserValid.role === 'admin') {
      data = await Audit.find();
    }
    if (isUserValid.role === 'partner') {
      data = await Audit.find();
    }

    res.status(200).json(data);
  } catch (error) {
    res.sendStatus(500);
  }
});

module.exports = router;
