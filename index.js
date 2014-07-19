module.exports = (function() {
  var firewall = require('./lib/simple-firewall');
  firewall.adapters = require('./lib/adapters/builtin');
  return firewall;
}());