const fs = require('fs');
const path = require('path');

const basename = path.basename(__filename);
// generate [[name, handler]] pairs

module.exports = fs
  .readdirSync(__dirname)
  .filter((file) => file !== basename)
  /* eslint-disable global-require */
  .map((file) => [path.basename(file, '.js'), require(`./${file}`)]); // eslint-disable-line import/no-dynamic-require
