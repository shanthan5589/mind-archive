const { handleRequest } = require("../server");

module.exports = async function handler(req, res) {
  await handleRequest(req, res);
};
