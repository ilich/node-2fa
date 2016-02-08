var db = require('../db');
var ObjectID = require('mongodb').ObjectID;
var LocalStrategy = require('passport-local').Strategy;
var bcrypt = require('bcrypt-nodejs');

module.exports = function (passport) {
    var INVALID_LOGIN = 'Incorrect username or password.';
    
    passport.serializeUser(function (user, done) {
        return done(null, user._id);    
    });
    
    passport.deserializeUser(function (id, done) {
        var users = db.get().collection('users');
        users.findOne(new ObjectID(id), function (err, user) {
            if (err) {
                return done(err);
            } else if (user === null) {
                return done(null, false);
            } else {
                return done(null, user);
            }
        });  
    });
    
    passport.use('login', new LocalStrategy({
        usernameField: 'username',
        passwordField: 'password'
    }, function (username, password, done) {
        process.nextTick(function () {
            var users = db.get().collection('users');
            users.findOne({ username: username }, function (err, user) {
                if (err) {
                    return done(err);
                }
                
                if (user === null) {
                    return done(null, false, { message: INVALID_LOGIN });
                }
                
                bcrypt.compare(password, user.password, function (err, result) {
                    if (err) {
                        return done(err);
                    }
                    
                    if (result === true) {
                        return done(null, user);
                    } else {
                        return done(null, false, { message: INVALID_LOGIN });
                    }
                });
            });
        });
    }));
    
    passport.use('register', new LocalStrategy({
        usernameField: 'username',
        passwordField: 'password',
        passReqToCallback: true
    }, function (req, username, password, done) {
        if (!/^[A-Za-z0-9_]+$/g.test(req.body.username)) {
            return done(null, false, { message: 'Invalid username.' });
        }
        
        if (req.body.password.length === 0) {
            return done(null, false, { message: 'Password is required.' });
        }
        
        if (req.body.password !== req.body.confirmPassword) {
            return done(null, false, { message: 'Passwords do not match.' });
        }
        
        var users = db.get().collection('users');
        users.findOne({ username: username}, function (err, user) {
            if (err) {
                return done(err);
            }
            
            if (user !== null) {
                return done(null, false, { message: 'Invalid username.' });
            }
            
            bcrypt.hash(password, null, null, function (err, hash) {
                if (err) {
                    return done(err);    
                }
                
                var user = {
                    username: username,
                    password: hash
                };
                
                users.insert(user, function (err) {
                    if (err) {
                        return done(err);
                    }    
                    
                    return done(null, user);
                });
            }); 
        });
    }));
};