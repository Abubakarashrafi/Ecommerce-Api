const express = require("express");
const ProductData = require("../models/product");
const productRouter = express.Router();
const {
  admin,
  authorization,
  verifyToken,
} = require("../middleware/authentication");

//  creating product
productRouter.post("/", admin, async (req, res) => {
  const { title, desc, size, color, price, categories } = req.body;
  try {
    const product = await new ProductData({
      title,
      desc,
      color,
      price,
      categories,
      size,
    });
    await product.save();
    res.json({ product });
  } catch (err) {
    res.status(500).json(err.message);
  }
});

//  getting all products
try {
  productRouter.get("/find", async (req, res) => {
    let qNew = req.query.new;
    let qCategory = req.query.category;
    if (qNew) {
      product = await ProductData.find().sort({ createdAt: -1 }).limit(1);
    } else if (qCategory) {
      product = await ProductData.find({ categories: {$in: [qCategory]} });
    } else {
      product = await ProductData.find();
    }
    res.status(200).json({ product });
  });
} catch (err) {
  res.status(500).send("Internal server error");
}

//  Updating Product Detail
productRouter.put("/:id", admin, async (req, res) => {
  try {
    const id = req.params.id;
    const { title, desc, size, color, price, categories } = req.body;
    const updatedProduct = await ProductData.findByIdAndUpdate(
      id,
      { $set: req.body },
      { new: true }
    );
    res.status(200).json(updatedProduct);
  } catch (err) {
    res.status(500).send("Internal Server Error");
  }
});

// Get Single Product
productRouter.get("/:id", async (req, res) => {
  const product = await ProductData.findById(req.params.id);
  res.status(200).json(product);
});

// Deleting product 
productRouter.delete('/:id',admin,async(req,res) => {
  try {
    const deleteProduct = await ProductData.findByIdAndDelete(req.params.id)
    res.status(200).json(deleteProduct)

  } catch (err) {
    res.status(500).json(err.message)
  }
})

module.exports = productRouter;
