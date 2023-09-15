const express = require("express");
const userRouter = express.Router();
const bcrypt = require("bcryptjs");
const User = require("../models/user");
const { verifyToken, authorization, admin } = require("../middleware/authentication");


userRouter.put('/:id', authorization, async (req, res) => {
  if (req.body.password) {
    let salt = await bcrypt.genSalt(10);
    let hashPass = await bcrypt.hash(req.body.password, salt);
    req.body.password = hashPass 
  }
  const updatedUser = await User.findByIdAndUpdate(
    req.params.id,
    { $set: req.body },
    { new: true }   
  );
  res.status(200).json(updatedUser)
});
userRouter.delete('/:id', admin, async(req,res) => {
  try {
    const id = req.params.id
      const deleteUser = await User.findByIdAndDelete(id)
      res.status(200).json({msg : "user deleted", deleteUser})
  } catch (err) {
    console.log(err.message);
  }
})
 
userRouter.get("/find/:id", admin, async (req, res) => {
  try {
    const id = req.params.id;
    const findUser = await User.findById(id);
    const {password , ...others} = findUser._doc
    console.log(findUser._doc);
    res.status(200).json({others});
  } catch (err) {
    console.log(err.message);
  }
});
  
userRouter.get("/find", admin, async (req, res) => {
  try {
    const user = await User.find().sort({'_id': -1})
    res.status(200).json({ user });
  } catch (err) {
    console.log(err.message);
  }
});
  


module.exports = userRouter
