const express = require("express");
const mongoose = require("mongoose");

const router = express.Router();
const bcrypt = require("bcryptjs");
const User = require("../models/User"); // import relevant model from models
const {
  userRegSchema,
  LoginSchema,
  openUserValidation,
  jobStatusUpdateSchema,
} = require("../validations/UserRegValidation");
const checkAuth = require("../middleware/auth");
const { getToken, verifyToken } = require("../utils/getToken");
const { validateInput } = require("../utils/common-functions");
const { sendMail } = require("../utils/common-functions");

router.post("/register", async (req, res) => {
  try {
    const openValidUser = validateInput(openUserValidation, req.body);
    if (!openValidUser.value) {
      return res.status(403).json(openValidUser);
    }

    const { title, firstName, lastName, email, password, role } =
      openValidUser.value;
    const openUser = await User.findOne({ email });

    if (openUser) {
      return res.sendStatus(403);
    }
    if (role === "candidate" || role === "companyAdmin") {
      // set verificationToken, verificationTokenTimeStamp

      const verifyTokens = verifyToken();
      const isOpenEndpoint = true;

      const NewUser = new User({
        title,
        firstName,
        lastName,
        email,
        password,
        role,
      });

      const salt = await bcrypt.genSalt(10);
      NewUser.password = await bcrypt.hash(password, salt);
      NewUser.verificationToken = verifyTokens.verificationToken;
      NewUser.verificationTokenTimeStamp =
        verifyTokens.verificationTokenTimeStamp;
      NewUser.lastLoginDate = null;
      await NewUser.save();
      // send welcome email sendEmail(verificationToken,email)
      const link = `${process.env.CLIENT_URL}/verify-account/${email}/${verifyTokens.verificationToken}/${isOpenEndpoint}`;
      const templateData = { name: `${title} ${firstName} ${lastName}`, link };
      await sendMail(email, "d-05704cbed3c544728619bd6920dd5e54", templateData);
      return res.sendStatus(200);
    }
    return res.sendStatus(401);
  } catch (error) {
    return res.sendStatus(500);
  }
});

router.post("/", checkAuth, async (req, res) => {
  try {
    const validUser = validateInput(userRegSchema, req.body);

    if (!validUser.value) {
      return res.status(403).json(validUser);
    }

    const authUser = await User.findById(req.user.userId);

    const { title, firstName, lastName, email, role, contactNumber, country } =
      validUser.value;

    // check if there is a user with the same email
    const existsUser = await User.findOne({ email });
    if (existsUser) {
      return res.status(401).json("Email already exists!");
    }
    // set verificationToken, verificationTokenTimeStamp
    const verifyTokens = verifyToken();
    const isOpenEndpoint = false;

    if (["admin", "companyAdmin"].includes(authUser.role)) {
      // create a new user
      const NewUser = new User({
        title,
        firstName,
        lastName,
        email,
        role,
        password: null,
        contactNumber,
        country,
      });
      // account active by email and set password
      NewUser.verificationToken = verifyTokens.verificationToken;
      NewUser.verificationTokenTimeStamp =
        verifyTokens.verificationTokenTimeStamp;
      await NewUser.save();

      // send welcome email sendEmail(verificationToken,email)
      const link = `${process.env.CLIENT_URL}/set-password/${email}/${verifyTokens.verificationToken}/${isOpenEndpoint}`;
      const templateData = { title, name: `${firstName} ${lastName}`, link };
      sendMail(email, "d-28eec08c35ac487281b40399cb6079ea", templateData);
      return res.sendStatus(200);
    }
    return res.sendStatus(401);
  } catch (error) {
    return res.sendStatus(500);
  }
});

router.post("/login", async (req, res) => {
  try {
    const checkValidation = validateInput(LoginSchema, req.body);
    if (!checkValidation.value) {
      return res.status(403).json("Please check your email and password");
    }
    const validUser = await User.findOne({
      email: checkValidation.value.email,
    });

    if (!validUser) {
      return res.sendStatus(401);
    }
    if (!validUser.status) {
      return res
        .status(503)
        .json("User status not set, please contact administrator");
    }
    if (validUser.email && validUser.status === "tempBlock") {
      return res
        .status(503)
        .json("You are temporary block, please contact administrator");
    }

    if (validUser.email && validUser.status === "pending") {
      return res
        .status(422)
        .json("You are status not active yet, please contact administrator");
    }
    if (validUser.email && validUser.status === "inactive") {
      return res
        .status(422)
        .json("You are status inactive yet, please contact administrator");
    }
    if (!validUser.password) {
      return res
        .status(422)
        .json("Your password is not set, please contact administrator");
    }
    // check Password
    const validPassword = await bcrypt.compare(
      checkValidation.value.password,
      validUser.password
    );
    if (!validPassword) {
      // Prevent login
      await User.updateOne(
        { email: validUser.email },
        {
          $inc: {
            totalFailedLoginAttempts: 1,
            continuesfailedLoginAttempts: 1,
          },
        }
      );
      if (validUser.continuesfailedLoginAttempts > 3) {
        validUser.status = "tempBlock";
        // Inform user by email
        const templateData = {
          name: `${validUser.firstName} ${validUser.lastName}`,
        };
        const subject = "Your account is blocked";
        sendMail(
          validUser.email,
          "d-ebc78cd1c63f4b4c9b293ccfe407c211",
          subject,
          templateData
        );
        await validUser.save();
        return res
          .status(401)
          .json("You are temporary block, please contact administrator");
      }
      return res.sendStatus(401);
    }

    // Create access JWT
    const accessToken = getToken(validUser.id, process.env.JWT_KEY, "8h");

    // create refresh JWT
    const refreshToken = getToken(validUser.id, process.env.REFRESH_KEY, "90d");

    // save this in db
    validUser.refreshTokens.push(refreshToken);

    // set last login date
    User.findOneAndUpdate({
      email: validUser.email,
      lastLoginDate: Date.now(),
      new: true,
    });

    await validUser.save();

    return res.status(200).json({
      accessToken,
      refreshToken,
      fullName: validUser.fullName,
      role: validUser.role,
    });
  } catch (error) {
    return res.sendStatus(500);
  }
});

router.put("/update-status", checkAuth, async (req, res) => {
  try {
    const ValidUser = validateInput(jobStatusUpdateSchema, req.body);
    if (!ValidUser.value) {
      return res.status(403).json(ValidUser);
    }

    const authUser = await User.findById(req.user.userId);
    const { status } = ValidUser.value;

    if (!["active", "inactive"].includes(status)) {
      return res.status(401).json("status not matched");
    }
    if (!["admin", "companyAdmin"].includes(authUser.role)) {
      // changed admin to companyAdmin
      ValidUser.value.id = req.user.userId;
      return res.status(401).json("User role is not matched");
    }

    await User.findByIdAndUpdate(ValidUser.value.id, { status });
    return res.sendStatus(200);
  } catch (error) {
    return res.sendStatus(500);
  }
});

router.put("/:id", checkAuth, async (req, res) => {
  try {
    const ValidUser = validateInput(openUserValidation, req.body);
    if (!ValidUser.value) {
      return res.status(403).json(ValidUser);
    }
    const AuthUserData = await User.findById(req.user.userId); // Get logged user data
    const userId = req.params.id;
    const validUser = await User.findById(userId);

    const emailDuplicate = await User.findOne({
      email: new RegExp(`^${validUser.email}$`, "i"),
      _id: { $ne: mongoose.Types.ObjectId(userId) },
    });

    if (emailDuplicate) {
      return res.sendStatus(403);
    }
    const { role, title, firstName, lastName, status, country, contactNumber } =
      ValidUser.value;
    const userUpdate = {
      role,
      title,
      firstName,
      lastName,
      status,
      country,
      contactNumber,
    };
    if (!["admin", "companyAdmin"].includes(AuthUserData.role)) {
      // changed admin to companyAdmin
      delete userUpdate.role;
      userId.id = req.user.userId; // avoid access of other users to behave like admin
    }
    await User.findByIdAndUpdate(userId, userUpdate);
    return res.sendStatus(200);
  } catch (error) {
    return res.sendStatus(500);
  }
});

router.get("/:id", checkAuth, async (req, res) => {
  try {
    const AuthUserData = await User.findById(req.user.userId);
    if (AuthUserData.role !== "admin") {
      // changed admin to companyAdmin
      req.params.id = req.user.userId;
    }
    const data = await User.findById(req.params.id);
    return res.status(200).json(data);
  } catch (error) {
    return res.sendStatus(500);
  }
});

router.get("/", checkAuth, async (req, res) => {
  try {
    const AuthUserData = await User.findById(req.user.userId);
    
    if (AuthUserData.role === "admin") {
      // changed admin to companyAdmin
      const data = await User.find(
        { role: { $ne: "candidate" } },
        "title firstName lastName fullName status email role id"
      );
      return res.status(200).json(data);
    }
    return res.sendStatus(401);
  } catch (error) {
    return res.sendStatus(500);
  }
});

router.delete("/delete/:email", checkAuth, async (req, res) => {
  try {
    const AuthUserData = await User.findById(req.user.userId);
    if (AuthUserData.role === "admin") {
      // changed admin to companyAdmin
      await User.deleteOne({ email: req.params.email });

      return res.sendStatus(200);
    }
    return res.sendStatus(401);
  } catch (error) {
    return res.sendStatus(500);
  }
});

module.exports = router;
