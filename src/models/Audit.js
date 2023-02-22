const mongoose = require('mongoose');

const { ObjectId } = mongoose.Schema.Types;
const { Schema } = mongoose;

const auditSchema = new Schema({
  user: ObjectId,
  description: String,
  oldValues: Object,
  newValues: Object,

}, { timestamps: true });

module.exports = mongoose.model('Audit', auditSchema);
