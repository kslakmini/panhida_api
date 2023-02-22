const Joi = require('joi');

//change to your schema name
//change validation body
const PakageSchema = (data) => {
  const Schema = Joi.object({
    pakageName: Joi.string().required(),
    duration: Joi.string().required(),
    amount: Joi.number().required(),
    discount: Joi.number().required(),
  }).unknown();

  return Schema.validate(data);
};

module.exports = { PakageSchema };