const express = require("express");
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require("passport");

// User model
const User = require('../models/User');

// Login Page
router.get('/login', (req, res) => res.render('login'));

// Register Page
router.get('/register', (req, res) => res.render('register'));

// Register Handle
router.post('/register', (req, res) => {
    const { email, username, pass, confirmpass } = req.body;
    let errors = [];

    // Check required fields
    if(!email || !username || !pass || !confirmpass) {
        errors.push({ msg: 'All fields are required' });
    }

    // Check passwords match
    if(pass !== confirmpass) {
        errors.push({ msg: 'Passwords do not match' });
    }

    // Check pass lenght
    if(pass.length < 8) {
        errors.push({ msg: 'Password should be at least 8 characters' });
    }
    if(errors.length > 0) {
        res.render('register', {
            errors,
            email,
            username,
            pass,
            confirmpass
        });
    } else {
        // Validation passed
        User.findOne({ email: email })
        .then(user => {
            if(user) {
                // User exists
                errors.push({ msg: 'Email already registred' })
                res.render('register', {
                    errors,
                    email,
                    username,
                    pass,
                    confirmpass
                });
            } else {
                const newUser = new User({
                    email,
                    username,
                    pass
                });

                // Hash Password
                bcrypt.genSalt(10, (err, salt) =>
                    bcrypt.hash(newUser.pass, salt, (err, hash) => {
                        if(err) throw err;
                        // Set password to hashed
                        newUser.pass = hash;
                        // Save user
                        newUser.save()
                            .then(user => {
                                req.flash('success_msg', 'You are now registered');
                                res.redirect('/users/login');
                            })
                            .catch(err => console.log(err));
                    }))
            }
        });
    }
});

// Login Handle
router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true
    })(req, res, next);
});

module.exports = router;
