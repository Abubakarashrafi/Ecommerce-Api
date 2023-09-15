const mongoose = require("mongoose");

const connectDB = () => {
  return mongoose.connect(
process.env.MONGODB_URL,
    {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    }
  );
};
module.exports = connectDB;
