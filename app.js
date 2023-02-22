const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const helmet = require('helmet');
// const { CronJob } = require('cron');
// const cronJob = require('./src/utils/common-functions');
var morgan = require('morgan');
const app = express();

const corsOptions = {
  origin: ['https://ictjobs.app/'],
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  preflightContinue: false,
  optionsSuccessStatus: 204,
};
app.use(morgan('dev'));
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(helmet());
const routes = require('./src/controllers/index');

routes.forEach(([name, handler]) => app.use(`/${name}`, handler));

const port = process.env.PORT;
const connectionURI = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.jrlgx.mongodb.net/${process.env.DB_NAME}?retryWrites=true&w=majority`;

mongoose.connect(connectionURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
  useFindAndModify: false,
});

// const job = new CronJob(
//   '* * * 1 * *',
//   cronJob.ScheduleTask(),
//   null,
//   true,
//   'Asia/Colombo',
// );
// job.start();

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => {
  console.log('We are connected!');
});

app.listen(port, () => {
  console.log(`Process ${process.pid}, ${port} ${process.env.NODE_ENV}`);
});
