const Joi = require("joi");
Joi.objectId = require("joi-objectid")(Joi);
const moment = require("moment");

const userRegSchema = (data) => {
  const enumTitle = ["Ms", "Mrs", "Mr", "Dr"];
  const enumRole = [
    "candidate",
    "admin",
    "moderator",
    "companyAdmin",
    "companyStaff",
    "salesExecutive",
    "batchRef",
  ];
  const Schema = Joi.object({
    title: Joi.string()
      .trim()
      .valid(...Object.values(enumTitle))
      .required(),

    firstName: Joi.string().trim().min(3).max(15).required(),

    lastName: Joi.string().trim().min(3).max(15).required(),
    country: Joi.string().trim().min(2).max(60),

    contactNumber: Joi.string().trim(),

    email: Joi.string().trim().lowercase().email(),

    role: Joi.string()
      .trim()
      .valid(...Object.values(enumRole))
      .required(),
  }).unknown();

  return Schema.validate(data);
};

const LoginSchema = (data) => {
  const Schema = Joi.object({
    email: Joi.string().trim().lowercase().email(),

    password: Joi.string().pattern(
      new RegExp(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/)
    ),
  }).unknown();

  return Schema.validate(data);
};

const openUserValidation = (data) => {
  const enumTitle = ["Ms", "Mrs", "Mr", "Dr"];
  const enumRole = [
    "candidate",
    "admin",
    "moderator",
    "companyAdmin",
    "companyStaff",
  ];
  const Schema = Joi.object({
    title: Joi.string()
      .trim()
      .valid(...Object.values(enumTitle))
      .required(),
    role: Joi.string()
      .trim()
      .valid(...Object.values(enumRole))
      .required(),

    firstName: Joi.string().trim().min(3).max(15).required(),

    lastName: Joi.string().trim().min(3).max(15).required(),

    email: Joi.string().trim().lowercase().email(),
  }).unknown();

  return Schema.validate(data);
};

const validationEmailSchema = (data) => {
  const enumStatus = ["active", "pending", "inactive"];
  const Schema = Joi.object({
    verificationToken: Joi.string().min(512).max(512),
    email: Joi.string().trim().lowercase().email().required(),

    password: Joi.string().pattern(
      new RegExp(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/)
    ),

    status: Joi.string()
      .trim()
      .valid(...Object.values(enumStatus)),

    id: Joi.objectId(),

    isOpenEndpoint: Joi.boolean(),
  }).unknown();

  return Schema.validate(data);
};

const jobRoleSchema = (data) => {
  const Schema = Joi.object({
    name: Joi.string().trim().min(3).max(30).required(),
  }).unknown();

  return Schema.validate(data);
};

const jobSchema = (data) => {
  const experienceLevelEnums = [
    "InternShip",
    "0-1",
    "1-2",
    "2-3",
    "3-4",
    "4-5",
    "5-6",
    "6-7",
    "8-10",
    "10+",
  ];
  const statusEnums = ["initial", "draft"];

  const Schema = Joi.object({
    name: Joi.string().trim().min(3).max(35).required(),
    company: Joi.objectId().required(),

    roles: Joi.array()
      .items(Joi.object().keys({ id: Joi.objectId(), name: Joi.string() }))
      .min(1)
      .max(5),

    experienceLevel: Joi.string()
      .trim()
      .valid(...Object.values(experienceLevelEnums))
      .required(),

    jobTypes: Joi.array(),

    minSalary: Joi.number().integer().min(15000),

    maxSalary: Joi.number().integer(),

    showSalary: Joi.boolean(),

    locationOptions: Joi.object().keys({
      inOffice: {
        allow: Joi.boolean(),
        visa: Joi.boolean(),
        citizensOnly: Joi.boolean(),
      },

      remote: {
        allow: Joi.boolean(),
        citizensOnly: Joi.boolean(),
        allOverTheWorld: Joi.boolean(),
      },
    }),

    tech: Joi.array()
      .items(
        Joi.object().keys({
          id: Joi.objectId(),
          level: Joi.number().integer().min(1).max(5),
          name: Joi.string(),
          _id: Joi.objectId(),
        })
      )
      .min(3)
      .max(12),

    description: Joi.string().trim().optional().allow("").max(2000),

    country: Joi.string().trim().optional().allow("").max(300),

    contactNumber: Joi.string().trim().optional().allow("").max(300),

    createdBy: Joi.objectId(),

    status: Joi.string()
      .trim()
      .valid(...Object.values(statusEnums)),

    noOfVacancies: Joi.number().integer().min(1).max(15),

    from: Joi.date().min(moment()),

    to: Joi.date().min(moment()),

    countryCode: Joi.string().trim().optional().allow(""),

    numberOfViews: Joi.number().integer(),

    price: Joi.number().integer().min(0),

    niceToHave: Joi.array()
      .items(
        Joi.object().keys({
          id: Joi.objectId(),
          name: Joi.string(),
          _id: Joi.objectId(),
        })
      )
      .max(8),
  }).unknown();

  return Schema.validate(data);
};

const jobStatusUpdateSchema = (data) => {
  const statusEnums = ["active", "inactive"];
  const Schema = Joi.object({
    id: Joi.objectId(),

    status: Joi.string()
      .trim()
      .valid(...Object.values(statusEnums)),
  }).unknown();

  return Schema.validate(data);
};

module.exports = {
  userRegSchema,
  LoginSchema,
  openUserValidation,
  validationEmailSchema,
  jobRoleSchema,
  jobSchema,
  jobStatusUpdateSchema,
};
