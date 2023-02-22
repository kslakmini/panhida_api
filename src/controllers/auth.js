const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const User = require('../models/User');
const { getToken, verifyToken } = require('../utils/getToken');
const { validateInput } = require('../utils/common-functions');
const { sendMail } = require('../utils/common-functions');
const { validationEmailSchema } = require('../validations/UserRegValidation');

const router = express.Router();
const checkAuth = require('../middleware/auth');

router.post('/forgot-password', async (req, res) => {
  try {
    const ValidUserData = validateInput(validationEmailSchema, req.body);
    if (!ValidUserData.value) {
      return res.status(403).json(ValidUserData);
    }
    const { email } = ValidUserData.value;
    const validUser = await User.findOne({ email, status: 'active' });

    if (!validUser) {
      return res.sendStatus(401);
    }
    const verifyTokens = verifyToken();

    const userData = {
      verificationTokenTimeStamp: verifyTokens.verificationTokenTimeStamp,
      verificationToken: verifyTokens.verificationToken,
    };
    await User.findByIdAndUpdate(validUser.id, userData);

    const isOpenEndpoint = false;

    const link = `${process.env.CLIENT_URL}/set-password/${email}/${verifyTokens.verificationToken}/${isOpenEndpoint}`;
    const templateData = {
      name: `${validUser.firstName} ${validUser.lastName}`,
      link,
    };
    sendMail(email, 'd-55c6b0ca85654dcabf59e708df2c5dad', templateData);
    return res.sendStatus(200);
  } catch (error) {
    return res.sendStatus(500);
  }
});

router.get('/me', checkAuth, async (req, res) => {
  try {
    const data = await User.findOne(
      { id: req.user.id, status: 'active' },
      'title firstName lastName fullName role'
    );
    return res.status(200).json(data);
  } catch (error) {
    return res.sendStatus(500);
  }
});

// Account Activated by email
router.post('/verify-email', async (req, res) => {
  try {
    const ValidUser = validateInput(validationEmailSchema, req.body);
    if (!ValidUser.value) {
      return res.status(403).json(ValidUser);
    }
    const { verificationToken, email, isOpenEndpoint, password } =
      ValidUser.value;

    const user = await User.findOne({ email, verificationToken });

    if (!user) {
      return res.sendStatus(401);
    }
    const currentDate = new Date();
    const currentTime = currentDate.getTime();
    const timeDifference = currentTime - user.verificationTokenTimeStamp;
    const remindedTime = Math.floor(timeDifference / 1000 / 60 / 60);

    if (remindedTime > 12) {
      return res.sendStatus(408); // retested timeout
    }

    if (isOpenEndpoint) {
      const userData = {
        verificationTokenTimeStamp: null,
        verificationToken: null,
        status: 'active',
      };
      await User.findByIdAndUpdate(user.id, userData);
      return res.sendStatus(200);
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const userData = {
      verificationTokenTimeStamp: null,
      verificationToken: null,
      status: 'active',
      password: hashedPassword,
    };
    await User.findByIdAndUpdate(user.id, userData);
    return res.sendStatus(200);
  } catch (error) {
    return res.sendStatus(500);
  }
});

// Create new access token using refresh token
router.post('/access-token', async (req, res) => {
  try {
    const rToken = req.body.token;

    if (!rToken) {
      // cloud not found way to find and access value from array
      return res.sendStatus(403);
    }

    const validUser = await jwt.verify(rToken, process.env.REFRESH_KEY);
    if (validUser) {
      // Create access JWT
      const accessToken = getToken(
        validUser.userId,
        process.env.JWT_KEY,
        '30m'
      );

      // delete the old refreshToken send new refresh token
      // delete old refresh token

      const userData = await User.findById(validUser.userId);
      userData.refreshTokens.pop();
      await userData.save();

      // create refresh JWT
      const refreshToken = getToken(
        userData.id,
        process.env.REFRESH_KEY,
        '90d'
      );

      // save this in db
      userData.refreshTokens.push(refreshToken);
      await userData.save();

      return res.status(201).json({
        accessToken,
        refreshToken,
      });
    }
    return res.sendStatus(401);
  } catch (error) {
    return res.sendStatus(500);
  }
});
module.exports = router;
