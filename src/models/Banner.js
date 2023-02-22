const mongoose = require('mongoose');
const moment = require('moment');

const { Schema } = mongoose;

const bannerSchema = new Schema(
  {
    imageURL: String,
    placement: {
      type: [String],
      enum: ['front', 'back', 'super'],
    },
    link: String,
    liveDates: Date,
    status: {
      type: String,
      enum: ['pending', 'active', 'expired', 'rejected'],
      default: 'pending',
    },
    amountPaid: {
      type: Number,
      default: 0,
    },
    postedBy: {
      type: Schema.ObjectId,
      ref: 'User',
    },
    postedCompany: {
      type: Schema.ObjectId,
      ref: 'Company',
    },
  },
  {
    timestamps: true,
    toObject: {
      virtuals: true,
    },
    toJSON: {
      virtuals: true,
    },
  },
);

bannerSchema
  .virtual('joined')
  .get(() => moment(this.createdAt).format('YYYY-MM-DD hh:mm:ss A'));

module.exports = mongoose.model('Banner', bannerSchema);
