const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

//------------ Render Views (EJS) ------------//
router.get('/login', (req, res) => res.render('login'));
router.get('/register', (req, res) => res.render('register'));
router.get('/forgot', (req, res) => res.render('forgot'));
router.get('/reset/:token', (req, res) => res.render('reset', { token: req.params.token }));

//------------ Authentication Routes ------------//
router.post('/register', authController.registerHandle);
router.post('/login', authController.loginHandle);
router.get('/logout', authController.logoutHandle);

//------------ Password Reset Routes ------------//
router.post('/forgot', authController.forgotPassword);
router.post('/reset/:token', authController.resetPassword);

module.exports = router;
