const Joi = require('joi');
Joi.objectId = require('joi-objectid')(Joi);

const placementEnum = ['front', 'back', 'super'];

const bannerSchema = (data) => {
  const Schema = Joi.object({
    imageURL: Joi.string().regex(
      // eslint-disable-next-line
      /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/
    ),
    placement: Joi.array().items(
      Joi.string()
        .trim()
        .valid(...Object.values(placementEnum)),
    ),

    link: Joi.string()
      .regex(
        // eslint-disable-next-line
        /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/
      )
      .allow(''),

    postedCompany: Joi.objectId(),
  }).unknown();

  return Schema.validate(data);
};

const bannerStateUpdateSchema = (data) => {
  const statusEnum = ['pending', 'active', 'expired', 'rejected'];
  const Schema = Joi.object({
    id: Joi.objectId(),
    status: Joi.string()
      .trim()
      .valid(...Object.values(statusEnum)),

    postedCompany: Joi.objectId(),
  }).unknown();

  return Schema.validate(data);
};

module.exports = {
  bannerSchema,
  bannerStateUpdateSchema,
};
