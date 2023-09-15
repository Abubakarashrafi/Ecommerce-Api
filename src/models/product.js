const mongoose = require('mongoose');

const ProductSchema = mongoose.Schema({
    title : {
        type : String,
        required : true
    },
    desc : {
        type : String,
        required : true
    },
    size : {
        type : String
    },
    color : {
        type : String
    },
    price : {
        type : String,
        required : true
    },
    categories : {
        type : Array,
    },
  
},
    {timestamps : true}
)

module.exports = mongoose.model("product",ProductSchema)