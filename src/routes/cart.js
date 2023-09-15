const express = require("express");
const CartData = require('../models/cart')
const cartRouter = express.Router();
const {
  admin,
  authorization,
  verifyToken,
} = require("../middleware/authentication");

//  creating cart
cartRouter.post("/", authorization, async (req, res) => {
  try {
    const cart = await new CartData(req.body)
    await cart.save();
    res.json({ cart });
  } catch (err) {
    res.status(500).json(err.message);
  }
});


//  Updating Cart Detail
cartRouter.put("/:id", authorization, async (req, res) => {
  try {
    const id = req.params.id;
    const updatedCart = await CartData.findByIdAndUpdate(
      id,
      { $set: req.body },
      { new: true }
    );
    res.status(200).json(updatedCart);
  } catch (err) {
    res.status(500).send("Internal Server Error");
  }
});

// Get cart Product
cartRouter.get("/:id",authorization, async(req,res) => {
    try {
        const cartProduct = await CartData.find();
        res.json(cartProduct)
    } catch (err) {
        res.status(500).send('Internal Server Error')
    }
})


cartRouter.delete("/:id", authorization, async (req, res) => {
  try {
    const deleteCart = await CartData.findByIdAndDelete(req.params.id);
    res.status(200).json(deleteCart);
  } catch (err) {
    res.status(500).json(err.message);
  }
});


module.exports = cartRouter;
