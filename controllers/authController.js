const bcrypt = require('bcryptjs');
const passport = require('passport');
const User = require('../models/User'); 
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
require('dotenv').config();

// Register Handle
exports.registerHandle = async (req, res) => {
    const { name, email, password, password2 } = req.body;
    let errors = [];

    // Validations
    if (!name || !email || !password || !password2) {
        errors.push({ msg: 'Please enter all fields' });
    }
    if (password !== password2) {
        errors.push({ msg: 'Passwords do not match' });
    }
    if (password.length < 8) {
        errors.push({ msg: 'Password must be at least 8 characters' });
    }

    if (errors.length > 0) {
        return res.render('register', { errors, name, email, password, password2 });
    }

    try {
        const existingUser = await User.findOne({ email });

        if (existingUser) {
            errors.push({ msg: 'Email already registered' });
            return res.render('register', { errors, name, email, password, password2 });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({ name, email, password: hashedPassword });

        await newUser.save();
        req.flash('success_msg', 'You are now registered and can log in');
        res.redirect('/auth/login');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Something went wrong, please try again.');
        res.redirect('/auth/register');
    }
};

// Login Handle
exports.loginHandle = (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/auth/login',
        failureFlash: true
    })(req, res, next);
};


// Logout Handle
exports.logoutHandle = (req, res) => {
    req.logout(err => {
        if (err) return next(err);
        req.flash('success_msg', 'You are logged out');
        res.redirect('/auth/login');
    });
};

exports.forgotPassword = async (req, res) => {
    const { email } = req.body;
    let errors = [];

    if (!email) {
        errors.push({ msg: 'Please enter an email' });
    }

    if (errors.length > 0) {
        return res.render('forgot', { errors, email });
    }

    try {
        const user = await User.findOne({ email });

        if (!user) {
            errors.push({ msg: 'User not found' });
            return res.render('forgot', { errors, email });
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '30m' });

        const CLIENT_URL = `http://${req.headers.host}`;
        const resetLink = `${CLIENT_URL}/auth/reset/${token}`;

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });

        const mailOptions = {
            from: '"Auth Admin" <your_email@gmail.com>',
            to: email,
            subject: "Password Reset",
            html: `<p>Click <a href="${resetLink}">here</a> to reset your password. The link expires in 30 minutes.</p>`
        };

        await transporter.sendMail(mailOptions);
        req.flash('success_msg', 'Password reset link sent to your email');
        res.redirect('/auth/login');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Something went wrong, please try again.');
        res.redirect('/auth/forgot');
    }
};

exports.resetPassword = async (req, res) => {
    const { token } = req.params;
    const { password, password2 } = req.body;
    let errors = [];

    if (!password || !password2) {
        errors.push({ msg: 'Please enter all fields' });
    } else if (password.length < 8) {
        errors.push({ msg: 'Password must be at least 8 characters' });
    } else if (password !== password2) {
        errors.push({ msg: 'Passwords do not match' });
    }

    if (errors.length > 0) {
        return res.render('reset', { errors, token });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id);

        if (!user) {
            req.flash('error_msg', 'Invalid or expired link');
            return res.redirect('/auth/login');
        }

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        await user.save();

        req.flash('success_msg', 'Password updated successfully. You can log in now.');
        res.redirect('/auth/login');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Something went wrong, please try again.');
        res.redirect('/auth/login');
    }
};


