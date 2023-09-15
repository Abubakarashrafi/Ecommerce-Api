const express = require("express");
const orderRouter = express.Router();
const OrderData = require("../models/order");
const {
  admin,
  authorization,
  verifyToken,
} = require("../middleware/authentication");

// create order
orderRouter.post("/", authorization, async (req, res) => {
  try {
    const createOrder = await new OrderData.create(req.body);
    createOrder.save();
    res.status(200).json(createOrder);
  } catch (err) {
    res.status(500).json(err.message);
  }
});
// delete order
orderRouter.put("/:id", admin, async (req, res) => {
  try {
    const updateOrder = await OrderData.findByIdAndUpdate(
      req.params.id,
      { $set: req.body },
      { new: true }
    );
    res.status(200).json(updateOrder);
  } catch (err) {
    res.status(500).json("Internal Server error");
  }
});
// fetch user order
orderRouter.get("/find", admin, async (req, res) => {
  const order = await OrderData.find();
  res.status(200).json(order);
});
// fetch all orders
orderRouter.get("/:id", authorization, async (req, res) => {
  const order = await OrderData.findById(req.params.id);
  res.status(200).json(order);
});
// Income detail 
orderRouter.get("/income", admin, async (req, res) => {
  const date = new Date();
  const lastMonth = new Date(date.setMonth(date.getMonth() - 1));
  const previousMonth = new Date(new Date().setMonth(lastMonth.getMonth() - 1));
  const income = await OrderData.aggregiate([
    { $match: { createdAt: { $gte: previousMonth } } },
    {
      $project: {
        month: { $month: "$createdAt" },
        sales : '$amount',
      },
    },
      {
        $group :{
            id : '$month',
            total : {$sum : 'sales'},
        },
      },     
  ])
  res.status(200).send(income)
})

module.exports = orderRouter;
