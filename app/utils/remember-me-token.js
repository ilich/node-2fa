var rack = require('hat').rack();
var ObjectID = require('mongodb').ObjectID;
var db = require('../db');

module.exports = {
    consume: function (token, done) {
        var tokens = db.get().collection('tokens'),
            users = db.get().collection('users');
            
        tokens.findOne({ token: token }, function (err, token) {
            if (err) {
                return done(err);
            }
            
            if (!token) {
                return done(null, false);
            }
            
            users.findOne(new ObjectID(token.user), function (err, user) {
                if (err) {
                    return done(err);
                }
                
                tokens.remove(token, function (err) {
                    if (err) {
                        return done(err); 
                    } else if (user === null) {
                        return done(null, false);
                    } else {
                        return done(null, user);
                    }    
                });
            });
        });
    },
    
    create: function (user, done) {
        var token = rack(),
            tokens = db.get().collection('tokens');
        
        tokens.insert({
            token: token,
            user: user._id
        }, function (err) {
            if (err) {
                return done(err);
            } else {
                return done(null, token);
            }
        });
    },
    
    logout: function (req, res, done) {
        var token = req.cookies['remember_me'];
        if (!token) {
            return done();
        }
        
        var tokens = db.get().collection('tokens');
        tokens.remove({ token: token }, function () {
            res.clearCookie('remember_me');
            return done();    
        });
    }
};