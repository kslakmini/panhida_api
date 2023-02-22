const mongoose = require('mongoose');
const moment = require('moment');

const { Schema } = mongoose;

const UserSchema = new Schema(
  {
    title: {
      type: String,
      enum: ['Ms', 'Mrs', 'Mr', 'Dr'],
      default: 'Mr',
    },
    firstName: String,
    lastName: String,
    email: String,
    password: String,
    verified: Boolean,
    country: String,
    contactNumber: String,
    refreshTokens: [String],
    resetLink: {
      data: String,
      default: '',
    },
    status: {
      type: String,
      enum: ['active', 'pending', 'inactive', 'tempBlock'],
      default: 'active',
    },
    dp: String,
    lastSeen: Date,
    passwordLastUpdate: Date,
    role: {
      type: String,
      enum: [
        'candidate',
        'admin',
        'moderator',
        'companyAdmin',
        'companyStaff',
        'salesExecutive',
        'batchRef',
      ],
      default: 'candidate',
    },
    permissions: [String],
    continuesfailedLoginAttempts: Number,
    totalFailedLoginAttempts: { type: Number, default: 0 },
    verificationToken: String,
    verificationTokenTimeStamp: { type: Number, default: 0 },
    lastLoginDate: Date,
  },
  {
    timestamps: true,
    toObject: {
      virtuals: true,
    },
    toJSON: {
      virtuals: true,
    },
  }
);

function getFullName() {
  return `${this.title} ${this.firstName} ${this.lastName}`;
}

function convertDate() {
  return moment(this.createdAt).format('YYYY-MM-DD hh:mm:ss A');
}

UserSchema.virtual('fullName').get(getFullName);

UserSchema.virtual('joined').get(convertDate);

module.exports = mongoose.model('User', UserSchema);
