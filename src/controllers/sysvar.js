const express = require('express');
const { SysVar } = require('../models/index');

const router = express.Router();

router.get('/', async (req, res) => {
  try {
    const data = await SysVar.find();
    res.status(200).json(data);
  } catch (error) {
    res.sendStatus(500);
  }
});

router.get('/:id', async (req, res) => {
  try {
    const data = await SysVar.findOne({ _id: req.params.id });
    res.status(200).json(data);
  } catch (error) {
    res.sendStatus(500);
  }
});

router.put('/:id', async (req, res) => {
  try {
    const { label, value } = req.body;

    const filter = { _id: req.params.id };

    const update = {
      label,
      value,
    };

    await SysVar.findOneAndUpdate(filter, update);
    return res.sendStatus(200);
  } catch (error) {
    return res.sendStatus(500);
  }
});

module.exports = router;
