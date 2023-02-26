const express = require('express');

const router = express.Router();
const User = require('../models/User'); // import relevant model from models
// const JobRole = require('../models/JobRole'); // import relevant model from models
const { SysVar } = require('../models/index');
const jobRolesList = require('../assets/jobroles.json');
const list = require('../utils/systemVariables');
// const Company = require("../models/Company");
const mongoose = require('mongoose');
// const Job = require('../models/Job');

router.get('/admin', async (req, res) => {
  try {
    const NewUser = new User({
      firstName: 'Sachintha',
      lastName: 'Lakmini',
      email: 'sachintha.lakmini.k@gmail.com',
      password: '$2a$10$l0rofJeJ93lEWVDFGijnVOyndYrFP9N/6wSg/TgW1krxiAQtLqD2e',
      role: 'admin',
    });

    await NewUser.save();

    res.sendStatus(200);
  } catch (error) {
    res.sendStatus(500);
  }
});




module.exports = router;
