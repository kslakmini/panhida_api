const mongoose = require('mongoose');

const { Schema } = mongoose;

const counterSchema = new Schema(
  {
    _id: String,
    seq: Number,
  },
  { timestamps: true },
);

module.exports = mongoose.model('Counter', counterSchema);
