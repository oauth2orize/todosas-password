var express = require('express');
var oauth2orize = require('oauth2orize');
var passport = require('passport');
var HTTPBasicStrategy = require('passport-http').BasicStrategy;
var OAuth2ClientPasswordStrategy = require('passport-oauth2-client-password');
var OAuth2ClientPublicStrategy = require('passport-oauth2-client-public');
var crypto = require('crypto');
var dateFormat = require('dateformat');

exports = module.exports = function(usersDB, oauth2DB) {

  function verify(clientID, clientSecret, cb) {
    oauth2DB.get('SELECT * FROM clients WHERE id = ?', [ clientID ], function(err, row) {
      if (err) { return next(err); }
      if (!row) { return cb(null, false); }
      if (!row.secret) { return cb(null, false); }
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

  var authenticator = new passport.Authenticator();
  authenticator.use(new HTTPBasicStrategy(verify));
  authenticator.use(new OAuth2ClientPasswordStrategy(verify));
  authenticator.use(new OAuth2ClientPublicStrategy(function verify(clientID, cb) {
    oauth2DB.get('SELECT * FROM clients WHERE id = ?', [ clientID ], function(err, row) {
      if (err) { return next(err); }
      if (!row) { return cb(null, false); }
      if (row.secret) { return cb(null, false); }
      var client = {
        id: row.id,
        name: row.name,
        redirectURI: row.redirect_uri
      };
      return cb(null, client);
    });
  }));


  var as = oauth2orize.createServer();

  as.exchange(oauth2orize.exchange.password(function issue(client, username, password, scope, cb) {
    usersDB.get('SELECT * FROM users WHERE username = ?', [ username ], function(err, row) {
      if (err) { return cb(err); }
      if (!row) { return cb(null, false); }
    
      crypto.pbkdf2(password, row.salt, 310000, 32, 'sha256', function(err, hashedPassword) {
        if (err) { return cb(err); }
        if (!crypto.timingSafeEqual(row.hashed_password, hashedPassword)) {
          return cb(null, false);
        }
      
        crypto.randomBytes(64, function(err, buffer) {
          if (err) { return cb(err); }
          var accessToken = buffer.toString('base64');
          var expiresAt = new Date(Date.now() + 7200000); // 2 hours from now
      
          oauth2DB.run('INSERT INTO access_tokens (user_id, client_id, scope, expires_at, token) VALUES (?, ?, ?, ?, ?)', [
            row.id,
            client.id,
            [ 'profile' ].join(' '),
            dateFormat(expiresAt, 'yyyy-mm-dd HH:MM:ss', true),
            accessToken,
          ], function(err) {
            if (err) { return cb(err); }
      
      
            return cb(null, accessToken, 'rt');
          });
        });
      });
    });
  }));


  var router = express.Router();

  router.post('/token',
    authenticator.authenticate(['basic', 'oauth2-client-password', 'oauth2-client-public'], { session: false, failWithError: true }),
    as.token(),
    as.errorHandler());

  return router;
};
