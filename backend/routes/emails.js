const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const auth = require('../middleware/auth');
const {
    getGoogleAuthUrl,
    handleGoogleCallback,
    getEmailConfigs,
    createEmail,
    sendBulkEmails,
    deleteEmailConfig,
    getSentEmails,
    getEmailStats
} = require('../controllers/emailController');

// Get email configurations
router.get('/configs', auth, getEmailConfigs);

// Get Google Auth URL (initiate OAuth flow)
router.get('/google-auth', auth, getGoogleAuthUrl);

// Create email campaign
router.post('/create', auth, [
    body('subject').notEmpty().withMessage('Subject is required'),
    body('body').notEmpty().withMessage('Email body is required'),
    body('senderEmail').isEmail().withMessage('Valid sender email is required'),
    body('recipientData').isArray().withMessage('Recipient data must be an array')
], createEmail);

// Send email campaign
router.post('/send/:mailId', auth, sendBulkEmails);

// Get sent emails
router.get('/sent', auth, getSentEmails);

// Get email stats
router.get('/stats', auth, getEmailStats);

// Delete email configuration
router.post('/delete-email-config', auth, [
    body('senderEmail').isEmail().withMessage('Valid sender email is required')
], deleteEmailConfig);

// Google OAuth callback (no auth middleware - this is a public callback)
router.get('/google-callback', handleGoogleCallback);

module.exports = router; 
