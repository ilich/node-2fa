var db = require('../db');
var ObjectID = require('mongodb').ObjectID;
var bcrypt = require('bcrypt-nodejs');
var tokenStorage = require('../utils/remember-me-token');
var GoogleAuthenticator = require('passport-2fa-totp').GoogeAuthenticator;
var TwoFAStartegy = require('passport-2fa-totp').Strategy;
var RememberMeStrategy = require('passport-remember-me').Strategy;

module.exports = function (passport) {
    var INVALID_LOGIN = 'Invalid username or password';
    
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
    
    passport.use('login', new TwoFAStartegy({
        usernameField: 'username',
        passwordField: 'password',
        codeField: 'code'
    }, function (username, password, done) {
        // 1st step verification: username and password
        
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
    }, function (user, done) {
        // 2nd step verification: TOTP code from Google Authenticator
        
        if (!user.secret) {
            done(new Error("Google Authenticator is not setup yet."));
        } else {
            // Google Authenticator uses 30 seconds key period
            // https://github.com/google/google-authenticator/wiki/Key-Uri-Format
            
            var secret = GoogleAuthenticator.decodeSecret(user.secret);
            done(null, secret, 30);
        }
    }));
    
    passport.use('register', new TwoFAStartegy({
        usernameField: 'username',
        passwordField: 'password',
        passReqToCallback: true,
        skipTotpVerification: true
    }, function (req, username, password, done) {
        // 1st step verification: validate input and create new user
        
        if (!/^[A-Za-z0-9_]+$/g.test(req.body.username)) {
            return done(null, false, { message: 'Invalid username' });
        }
        
        if (req.body.password.length === 0) {
            return done(null, false, { message: 'Password is required' });
        }
        
        if (req.body.password !== req.body.confirmPassword) {
            return done(null, false, { message: 'Passwords do not match' });
        }
        
        var users = db.get().collection('users');
        users.findOne({ username: username}, function (err, user) {
            if (err) {
                return done(err);
            }
            
            if (user !== null) {
                return done(null, false, { message: 'Invalid username' });
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
    
    passport.use(new RememberMeStrategy(function (token, done) {
        process.nextTick(function() {
            tokenStorage.consume(token, function (err, user) {
                if (err) {
                    return done(err);
                } else if (user === false) {
                    return done(null, false);
                } else {
                    return done(null, user);
                }
            });
        });
    },
    function (user, done) {
        process.nextTick(function() {
            tokenStorage.create(user, done);
        });
    }));
};