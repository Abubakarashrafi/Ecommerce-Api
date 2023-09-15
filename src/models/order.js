const mongoose = require("mongoose");

const OrderSchema = mongoose.Schema(
  {
    userID: {
      type: String,
      required: true,
    },
    products: [
      {
        productID: {
          type: String,
          required: true,
        },
        quantity: {
          type: String,
          default: 1,
        },
      },
    ],
    amount : {
        type : Number,
        required : true
    },
    status : {
        type : String,
        default : 'Pending'
    },
    address : {
        type : Object,
        required : true
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("Order", OrderSchema);
