const Joi = require('joi');

const UniversitySchema = (data) => {
  const Schema = Joi.object({
    name: Joi.string().trim().min(3).max(30).required(),

    itemType: Joi.string().required(),
  }).unknown();

  return Schema.validate(data);
};

module.exports = { UniversitySchema };
