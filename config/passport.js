const localStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// Local User Model
const User = require('../models/User');
module.exports = function(passport) {
    passport.use(
        new localStrategy({ usernameField: 'email' }, (email, pass, done) => {
            // Match User
            User.findOne({ email: email })
                .then(user => {
                    if(!user) {
                        console.log(User.email)
                        return done(null, false, { message: 'That email is not registered' });
                    }

                    // Mach Password
                    bcrypt.compare(pass, user.pass, (err, isMatch) => {
                        if(err) throw err;

                        if(isMatch) {
                            return done(null, user);
                        } else {
                            return done(null, false, { message: 'Password incorrect' });
                        }
                    });
                })
                .catch(err => console.log(err));
        })
    );

    passport.serializeUser((user, done) => {
        done(null, user.id);
    });
    
    passport.deserializeUser((id, done) => {
        User.findById(id, (err, user) => {
            done(err, user);
        });
    });
}