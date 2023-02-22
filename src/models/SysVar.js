const mongoose = require('mongoose');

const { Schema } = mongoose;

const model = new Schema(
  {
    text: { type: String, unique: true },
    label: { type: String },
    value: { type: String },
  },
  { timestamps: true },
);

module.exports = mongoose.model('SysVar', model);
