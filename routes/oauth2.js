var express = require('express');
var oauth2orize = require('oauth2orize');
var passport = require('passport');
var HTTPBasicStrategy = require('passport-http').BasicStrategy;
var OAuth2ClientPasswordStrategy = require('passport-oauth2-client-password');
var crypto = require('crypto');
var db = require('../db');


function verify(clientID, clientSecret, cb) {
  db.get('SELECT * FROM clients WHERE id = ?', [ clientID ], function(err, row) {
    if (err) { return next(err); }
    if (!row) { return cb(null, false); }
    if (!crypto.timingSafeEqual(Buffer.from(row.secret), Buffer.from(clientSecret))) {
      return cb(null, false);
    }
    var client = {
      id: row.id,
      name: row.name,
      redirectURI: row.redirect_uri
    };
    return cb(null, client);
  });
};

passport.use(new HTTPBasicStrategy(verify));
passport.use(new OAuth2ClientPasswordStrategy(verify));


var as = oauth2orize.createServer();

as.exchange(oauth2orize.exchange.password(function issue(client, username, password, scope, cb) {
  console.log('EXHANGE');
  console.log(client);
  console.log(username);
  console.log(password);
  console.log(scope)
  
  
  return cb(null, 'at', 'rt');
}));

var router = express.Router();

router.post('/token',
  //passport.authenticate(['basic', 'oauth2-client-password'], { session: false }),
  as.token(),
  as.errorHandler());

module.exports = router;
