const { verifyAll } = require('./blockchainController');

function verifyLedger(req, res) {
  req.legacyLedgerAlias = true;
  return verifyAll(req, res);
}

module.exports = {
  verifyLedger,
};
