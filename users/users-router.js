const express = require("express");
const bcrypt = require("bcryptjs");
const usersModel = require("./users-model");
const restricted = require("../middleware/restricted");
const jwt = require("jsonwebtoken");

const router = express.Router();

// Get a list of users
router.get("/users", restricted, async (req, res, next) => {
  try {
    res.json(await usersModel.find());
  } catch (err) {
    next(err);
  }
});

// Create new user
router.post("/register", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const user = await usersModel.findBy({ username }).first();

    if (user) {
      return res.status(409).json({ message: "Username must be unique" });
    }

    const newUser = await usersModel.add({
      username,
      // Hash the password with a time complexity of 14
      password: await bcrypt.hash(password, 14),
    });

    res.status(201).json(newUser);
  } catch (err) {
    next(err);
  }
});

// Login existing user
router.post("/login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const user = await usersModel.findBy({ username }).first();

    if (!user) {
      return res.status(401).json({
        message: "Invalid Credentials",
      });
    }

    // hash the password again and see if it matches what we have in the database
    const passwordValid = await bcrypt.compare(password, user.password);

    if (!passwordValid) {
      return res.status(401).json({
        message: "Invalid Credentials",
      });
    }

    // Create web token
    const token = jwt.sign(
      {
        userID: user.id,
      },
      process.env.JWT_SECRET
    );

    // Sets up cookie
    res.cookie("token", token);

    res.json({
      message: `Welcome ${user.username}!`,
    });
  } catch (err) {
    next(err);
  }
});

// Logs user out
router.get("/logout", async (req, res, next) => {
  try {
    req.session.destroy((err) => {
      if (err) {
        next(err);
      } else {
        res.status(204).end();
      }
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
