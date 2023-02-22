const Joi = require('joi');
Joi.objectId = require('joi-objectid')(Joi);

const SaveJobsSchema = (data) => {
  Schema = Joi.object({
    userId: Joi.objectId(),

    jobId: Joi.objectId(),
  }).unknown();

  return Schema.validate(data);
};

module.exports = { SaveJobsSchema };
