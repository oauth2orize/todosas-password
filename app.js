var createError = require('http-errors');
var express = require('express');
var path = require('path');
var passport = require('passport');
var logger = require('morgan');
var db = require('./db');

var oauth2Router = require('./routes/oauth2');
var userinfoRouter = require('userinfoapi-bearer')(db, db);

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
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
