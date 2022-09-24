var sqlite3 = require('sqlite3');
var mkdirp = require('mkdirp');
var crypto = require('crypto');

mkdirp.sync('./var/db');

var usersDB = new sqlite3.Database('./var/db/users.db');
var authzDB = new sqlite3.Database('./var/db/authz.db');

usersDB.serialize(function() {
  usersDB.run("CREATE TABLE IF NOT EXISTS users ( \
    id INTEGER PRIMARY KEY, \
    username TEXT UNIQUE, \
    hashed_password BLOB, \
    salt BLOB, \
    name TEXT \
  )");
  
  // create an initial user (username: alice, password: letmein)
  var salt = crypto.randomBytes(16);
  usersDB.run('INSERT OR IGNORE INTO users (username, hashed_password, salt) VALUES (?, ?, ?)', [
    'alice',
    crypto.pbkdf2Sync('letmein', salt, 310000, 32, 'sha256'),
    salt
  ]);
});

authzDB.serialize(function() {
  authzDB.run("CREATE TABLE IF NOT EXISTS clients ( \
    id INTEGER PRIMARY KEY, \
    secret TEXT, \
    name TEXT NOT NULL, \
    redirect_uri TEXT \
  )");
  
  authzDB.run("CREATE TABLE IF NOT EXISTS grants ( \
    id INTEGER PRIMARY KEY, \
    user_id INTEGER NOT NULL, \
    client_id INTEGER NOT NULL, \
    scope TEXT, \
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, \
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP \
  )");
  
  authzDB.run("CREATE TABLE IF NOT EXISTS authorization_codes ( \
    client_id INTEGER NOT NULL, \
    redirect_uri TEXT, \
    user_id INTEGER NOT NULL, \
    grant_id INTEGER NOT NULL, \
    scope TEXT, \
    issued_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, \
    expires_at DATETIME NOT NULL, \
    code TEXT UNIQUE NOT NULL \
  )");
  
  authzDB.run("CREATE TABLE IF NOT EXISTS access_tokens ( \
    user_id INTEGER NOT NULL, \
    client_id INTEGER NOT NULL, \
    scope TEXT, \
    issued_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, \
    expires_at DATETIME NOT NULL, \
    token TEXT UNIQUE NOT NULL \
  )");
  
  authzDB.run("CREATE TABLE IF NOT EXISTS refresh_tokens ( \
    grant_id INTEGER NOT NULL, \
    issued_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, \
    expires_at DATETIME, \
    token TEXT UNIQUE NOT NULL \
  )");
  
  // create an initial client (client ID: 1, client secret: 7Fjfp0ZBr1KtDRbnfVdmIw)
  authzDB.run('INSERT OR IGNORE INTO clients (id, secret, name, redirect_uri) VALUES (?, ?, ?, ?)', [
    1,
    '7Fjfp0ZBr1KtDRbnfVdmIw',
    'Todos',
    'http://localhost:3000/oauth2/redirect'
  ]);
  
  authzDB.run('INSERT OR IGNORE INTO clients (id, name, redirect_uri) VALUES (?, ?, ?)', [
    2,
    'Todos',
    'http://localhost:3000/'
  ]);
});

exports.usersDB = usersDB;
exports.authzDB = authzDB;
