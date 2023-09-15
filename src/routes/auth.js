const express = require("express");
const authRouter = express.Router();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const userData = require("../models/user");
// 1st route for registring user
authRouter.post("/register", async (req, res) => {
  try {
    let { username, email, password } = req.body;
    if (username && email && password) {
      let user = await userData.findOne({ email: email });
      if (!user) {
        let salt = await bcrypt.genSalt(10);
        let hashPass = await bcrypt.hash(password, salt);
        const newUser = new userData({
          username,
          email,
          password: hashPass,
        });
        await newUser.save();
        return res.json(newUser);
      } else {
        return res.status(409).send("Email or Username Already exist");
      }
    } else {
      return res.status(401).send("All fields required");
    }
  } catch (err) {
    return res.status(500).json(err.message);
  }
});

// 2nd route for login user
authRouter.post("/login", async (req, res) => {
  let { username, email, password } = req.body;
  if (password && (username || email)) {
    let user = await userData.findOne({ $or: [{ username }, { email }] });
    if (user) {
      let match = await bcrypt.compare(password, user.password);
      if (match) {
        let data = {
          id: user.id,
          isAdmin: user.isAdmin,
        };
        const jwtToken = jwt.sign(data,process.env.SECRET_KEY);
        const { password, ...others } = user._doc;
        // console.log(user._doc);
        return res
          .status(200)
          .json({ message: "login succesfull", jwtToken, ...others });
      } else {
        return res.status(401).json("Invalid password");
      }
    } else {
      return res.status(401).json("Invalid credintals");
    }
  } else {
    return res.status(409).send("Email and Password must not be empty");
  }
});

module.exports = authRouter;
