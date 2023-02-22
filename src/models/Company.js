const mongoose = require('mongoose');
const moment = require('moment');

const { Schema } = mongoose;

const companySchema = new Schema(
  {
    name: String,
    tagline: String,
    founded: String,
    description: String,
    websiteURL: String,
    email: String,
    size: {
      type: String,
      enum: ['01-20', '20-50', '50-100', '100-500', '500+', '1000+'],
    },
    companyFunction: {
      type: [String],
      enum: ['product', 'service','non-it'],
    },
    location: [
      {
        description: String,
        name: String,
        placeId: String,
      },
    ],

    logo: String,
    photos: [String],
    status: {
      type: String,
      enum: ['active', 'pending', 'inactive', 'initial'],
      default: 'initial',
    },
    credits: {
      type: Number,
      default: 0,
    },

    createdBy: {
      type: Schema.ObjectId,
      ref: 'User',
    }, // reference,

    admins: [
      {
        type: Schema.ObjectId,
        ref: 'User',
      },
    ],

    staff: [
      {
        type: Schema.ObjectId,
        ref: 'User',
      },
    ],
    urlPortion:{
      type:String,
      unique:true
    }
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

companySchema
  .virtual('joined')
  .get(() => moment(this.createdAt).format('YYYY-MM-DD hh:mm:ss A'));

module.exports = mongoose.model('Company', companySchema);
