var createError = require('http-errors');
var express = require('express');
var path = require('path');
var logger = require('morgan');
var db = require('./db');

var oauth2Router = require('./routes/oauth2')(db.usersDB, db.usersDB);
var userinfoRouter = require('@oauth2orize-examples/userinfoapi-bearer')(db.usersDB, db.usersDB);

var app = express();

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(function(req, res, next) {
  console.log('# ' + req.method + ' ' + req.url)
  console.log(req.headers)
  console.log(req.session)
  next();
});

app.use('/oauth2', oauth2Router);
app.use('/openidconnect', userinfoRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
