const express = require('express');

const router = express.Router();
const moment = require('moment');

const { validateInput } = require('../utils/common-functions');
const {
  bannerSchema,
  bannerStateUpdateSchema,
} = require('../validations/BannerValidation');
const checkAuth = require('../middleware/auth');
const User = require('../models/User');
const Banner = require('../models/Banner');
const Company = require('../models/Company');
const SysVar = require('../models/SysVar');
/* eslint-disable consistent-return */
/* eslint-disable no-restricted-syntax */
/* eslint-disable no-await-in-loop */
router.post('/banner', checkAuth, async (req, res) => {
  try {
    const validBanner = validateInput(bannerSchema, req.body);
    if (!validBanner.value) {
      return res.status(403).json(validBanner);
    }

    const [pricePerBanner, validUser] = await Promise.all([
      SysVar.findOne({ text: 'PRICE_PER_BANNER' }),
      User.findById(req.user.userId),
    ]);

    const {
      imageURL, placement, link, postedCompany,
    } = validBanner.value;
    const postedBy = req.user.userId;
    const liveDateList = req.body.Dates;

    let alreadyExists = [];
    const Dates = [];
    let allow = [];
    const start = liveDateList.from;
    const end = liveDateList.to;

    // Get day list between from - to
    const getDaysArray = (Start, End) => {
      let arr;
      let dt;
      for (
        arr = [], dt = new Date(Start);
        dt <= End;
        dt.setDate(dt.getDate() + 1)
      ) {
        arr.push(new Date(dt));
      }
      return arr;
    };

    const dayList = getDaysArray(new Date(start), new Date(end));
    dayList.map((v) => v.toISOString().slice(0, 10)).join('');

    // check is is exists day
    for (const lists of dayList) {
      const existsDates = await Banner.find({
        liveDates: lists,
        placement,
      }).select('liveDates');

      if (existsDates !== null) {
        Dates.push(existsDates);
      }
    }

    const mapped = Dates.map((ele) => ele.map((e) => e.liveDates));
    // eslint-disable-next-line
    let duplicatesArray = [].concat.apply([], mapped);

    alreadyExists = duplicatesArray
      .map((date) => date.getTime())
      .filter((date, i, array) => array.indexOf(date) === i)
      .map((time) => new Date(time));

    allow = dayList.filter(
      (e) => !alreadyExists.some((ele) => e.getTime() === ele.getTime()),
    );

    let bannerPrice = 1000;

    if (pricePerBanner && pricePerBanner.value) {
      bannerPrice = pricePerBanner.value;
    }

    const manyBanners = [];
    let i;
    /* eslint-disable no-plusplus */
    for (i = 0; i < allow.length; i++) {
      const newBanner = new Banner({
        imageURL,
        placement,
        link,
        postedBy,
        postedCompany,
        liveDates: allow[i],
        amountPaid: bannerPrice,
      });

      if (!['admin', 'moderator'].includes(validUser.role)) {
        newBanner.status = 'pending';
      }
      newBanner.status = 'active';

      manyBanners.push(newBanner);

      const numberOfDate = allow.length;
      const totalAmountPaid = numberOfDate * bannerPrice;

      const companyCredit = await Company.findById(postedCompany).select(
        'credits',
      );
      // if (companyCredit.credits < newBanner.amountPaid) {
      //   return res.sendStatus(401);
      // }

      await Company.updateOne(
        { _id: postedCompany },
        { $inc: { credits: -newBanner.amountPaid } },
      );

      await Banner.insertMany(manyBanners);
      return res.status(200).send({
        status: `Charged amount: ${totalAmountPaid}`,
        message: `Your banner will be showed on these days : ${allow} , already booked : ${alreadyExists}`,
      });
    }
  } catch (error) {
    return res.sendStatus(500);
  }
});

router.get('/banner', checkAuth, async (req, res) => {
  try {
    const validUser = await User.findById(req.user.userId);

    if (['admin', 'moderator'].includes(validUser.role)) {
      const bannerData = await Banner.find().limit(100).sort({ $natural: -1 });
      return res.status(200).json(bannerData);
    }

    if (['companyAdmin'].includes(validUser.role)) {
      const CompanyId = await Company.aggregate([
        {
          $match: { admins: { $exists: true, $in: [req.user.userId] } },
        },
      ]).select('_id');

      const BannerImg = await Banner.find({ postedCompany: CompanyId }).select(
        'imageURL',
      );

      return res.status(200).json(BannerImg);
    }

    if (['companyStaff'].includes(validUser.role)) {
      const CompanyId = await Company.aggregate([
        {
          $match: { staff: { $exists: true, $in: [req.user.userId] } },
        },
      ]).select('_id');

      const BannerImg = await Banner.find({ postedCompany: CompanyId }).select(
        'imageURL',
      );

      return res.status(200).json(BannerImg);
    }
  } catch (error) {
    return res.sendStatus(500);
  }
});

router.put('/banner/:id', checkAuth, async (req, res) => {
  try {
    const validBanner = validateInput(bannerSchema, req.body);
    if (!validBanner.value) {
      return res.status(403).json(validBanner);
    }
    const {
      imageURL, placement, link, liveDate, postedCompany,
    } = validBanner.value;
    const validUser = await User.findById(req.user.userId);

    if (!['admin', 'moderator'].includes(validUser.role)) {
      return res.sendStatus(401);
    }

    const bannerData = {
      imageURL,
      placement,
      link,
      liveDate,
      postedCompany,
    };

    await Banner.findByIdAndUpdate(req.params.id, bannerData);
    return res.sendStatus(200);
  } catch (error) {
    return res.sendStatus(500);
  }
});

router.put('/banner-status', checkAuth, async (req, res) => {
  try {
    const validBanner = validateInput(bannerStateUpdateSchema, req.body);
    if (!validBanner.value) {
      return res.status(403).json(validBanner);
    }
    const validUser = await User.findById(req.user.userId);
    const { id, status } = validBanner.value;

    if (!['admin', 'moderator'].includes(validUser.role)) {
      return res.sendStatus(401);
    }

    await Banner.findByIdAndUpdate(id, { status });
    return res.sendStatus(200);
  } catch (error) {
    return res.sendStatus(500);
  }
});

router.get('/banner-live', async (req, res) => {
  try {
    const todayDate = moment();
    const aliveBanner = await Banner.find({
      status: 'active',
      liveDate: todayDate,
    });
    return res.status(200).json(aliveBanner);
  } catch (error) {
    return res.sendStatus(500);
  }
});

router.get('/banner/:id', async (req, res) => {
  try {
    const BannerData = await Banner.findById(req.params.id).populate(
      'postedCompany',
    );
    return res.status(200).json(BannerData);
  } catch (error) {
    return res.sendStatus(500);
  }
});

module.exports = router;
