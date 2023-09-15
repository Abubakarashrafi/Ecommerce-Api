const mongoose = require("mongoose");

const CartSchema = mongoose.Schema(
  {
    userID : {
        type : String,
        required : true
    },
    products : [
        {
        productID : {
            type : String,
            required : true
        },
        quantity : {
            type : String,
            default : 1
        }, 
    }
    ]
  },
  { timestamps: true }
);

module.exports = mongoose.model("Cart", CartSchema);
