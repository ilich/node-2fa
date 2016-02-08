var express = require('express');
var router = express.Router();
var passport = require('passport');

var authenticated = function (req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    
    return res.redirect('/');
}

router.get('/', function(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/profile');
    }
    
    var errors = req.flash('error');
    return res.render('index', { 
        errors: errors
    });
});

router.post('/', passport.authenticate('login', {
    successRedirect: '/profile',
    failureRedirect: '/',
    failureFlash: true
}));

router.get('/register', function (req, res, next) {
    var errors = req.flash('error');
    return res.render('register', {
        errors: errors
    });
});

router.post('/register', passport.authenticate('register', {
    successRedirect: '/profile',
    failureRedirect: '/register',
    failureFlash: true
}));

router.get('/profile', authenticated, function (req, res, next) {
    return res.render("profile", {
        user: req.user
    });
});

router.get('/logout', authenticated, function (req, res, next) {
    req.logout();
    return res.redirect('/');
});

module.exports = router;
