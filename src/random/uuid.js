const { faker } = require('@faker-js/faker');

const generateUuid = (req, res) => {
  const uuid = faker.string.uuid();

  res.json({
    uuid: uuid
  });
};

module.exports = generateUuid;
