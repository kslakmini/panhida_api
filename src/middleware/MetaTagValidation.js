const Joi = require('joi');

const metaTagSchema = (data) => {
  const Schema = Joi.object({

    name: Joi
      .string()
      .trim()
      .min(3)
      .max(30)
      .required(),

    tagType: Joi
      .string()
      .trim()
      .required(),

  }).unknown();

  return Schema.validate(data);
};

module.exports = { metaTagSchema };
