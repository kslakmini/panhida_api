const mongoose = require('mongoose');
const moment = require('moment');

const { Schema } = mongoose;
const { ObjectId } = Schema;

const applyJobsSchema = new Schema(
  {
    digitalCVJson: String,
    status: {
      type: String,
      enum: [
        'pending',
        'approved',
        'rejected',
        'filteredOut',
        'selected',
        'offered',
        'notOffered',
      ],
      default: 'pending',
    },

    userId: {
      type: Schema.ObjectId,
      ref: 'User',
    },
    jobId: {
      type: Schema.ObjectId,
      ref: 'Job',
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

applyJobsSchema
  .virtual('joined')
  .get(() => moment(this.createdAt).format('YYYY-MM-DD hh:mm:ss A'));

module.exports = mongoose.model('ApplyJobs', applyJobsSchema);
