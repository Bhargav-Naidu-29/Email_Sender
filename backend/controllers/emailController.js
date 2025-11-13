const { google } = require('googleapis');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const User = require('../models/User');
const EmailCampaign = require('../models/EmailCampaign');
const { convert } = require('html-to-text');
const protection = require('../utils/encryptionUtils');

dotenv.config();

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

const getBackendUrl = () => {
  if (process.env.RENDER) return process.env.RENDER_EXTERNAL_URL;
  if (process.env.VERCEL_URL) return `https://${process.env.VERCEL_URL}`;
  return process.env.BACKEND_URL || 'http://localhost:5000';
};

const BACKEND_URL = getBackendUrl();
const APP_REDIRECT_URI = `${BACKEND_URL}/api/emails/google-callback`;

function createOAuthClient() {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    const missing = [];
    if (!GOOGLE_CLIENT_ID) missing.push('GOOGLE_CLIENT_ID');
    if (!GOOGLE_CLIENT_SECRET) missing.push('GOOGLE_CLIENT_SECRET');
    throw new Error(`Missing required Google OAuth credentials: ${missing.join(', ')}. Please set these in your backend .env file.`);
  }
  return new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, APP_REDIRECT_URI);
}

/* ===================== AUTH FLOW ===================== */

/**
 * Get Google authorization URL
 */
const getGoogleAuthUrl = (req, res) => {
  try {
    console.log('🔐 Generating Google OAuth URL for user:', req.user._id);
    const oAuth2Client = createOAuthClient();

    // 'prompt: consent' helps to get refresh token on first consent.
    // Consider switching to 'select_account' or removing prompt after initial linking in production.
    const authOptions = {
      access_type: 'offline',
      // Use full Gmail scope for proper SMTP OAuth2 support
      scope: ['https://mail.google.com/', 'https://www.googleapis.com/auth/userinfo.email'],
      prompt: 'consent',
      state: req.user._id.toString()
    };

    const authorizeUrl = oAuth2Client.generateAuthUrl(authOptions);
    console.log('✅ Google OAuth URL generated successfully');
    console.log('   Redirect URI:', APP_REDIRECT_URI);

    res.json({ success: true, authUrl: authorizeUrl });
  } catch (error) {
    console.error('❌ Error generating Google auth URL:', error);
    // Provide more specific error message
    const errorMessage = error.message.includes('Missing required') 
      ? error.message 
      : `Failed to generate authorization URL: ${error.message}`;
    res.status(500).json({ 
      success: false, 
      message: errorMessage,
      error: error.message 
    });
  }
};

/**
 * Handle Google OAuth callback
 */
const handleGoogleCallback = async (req, res) => {
  const { code, state } = req.query;
  const userId = state;

  if (!code) {
    // user denied or missing code
    return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/draft?auth=failed`);
  }

  try {
    const oAuth2Client = createOAuthClient();
    const { tokens } = await oAuth2Client.getToken(code);
    const { refresh_token, access_token } = tokens;

    // Get user's email from Google
    oAuth2Client.setCredentials({ access_token: access_token || null });
    const oauth2 = google.oauth2({ version: 'v2', auth: oAuth2Client });
    const { data } = await oauth2.userinfo.get();
    const userEmail = data?.email;

    if (!userEmail) {
      return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/draft?auth=error&msg=Could not retrieve email`);
    }

    // Find user
    const user = await User.findById(userId);
    if (!user) {
      return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/draft?auth=error&msg=User not found`);
    }

    // Save refresh token (only if present)
    if (refresh_token) {
      const encryptedData = protection.encrypt(refresh_token);
      const newConfig = {
        senderEmail: userEmail,
        encryptedRefreshToken: {
          encrypted: encryptedData.encrypted,
          iv: encryptedData.iv,
          authTag: encryptedData.authTag
        },
        invalid: false // Clear invalid flag on re-authentication
      };

      // Remove any existing config with same email then push new config
      user.emailConfigs = (user.emailConfigs || []).filter(cfg => cfg.senderEmail !== userEmail);
      user.emailConfigs.push(newConfig);
      await user.save();
      console.log(`Saved new refresh token for ${userEmail} (invalid flag cleared)`);
    } else {
      // No refresh token returned (user may have previously authorized). Clear invalid flag anyway
      const existingConfig = (user.emailConfigs || []).find(cfg => cfg.senderEmail === userEmail);
      if (existingConfig) {
        existingConfig.invalid = false;
        await user.save();
      }
      console.log(`No refresh token returned for ${userEmail} (may already be authorized)`);
    }

    return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/draft?auth=success`);
  } catch (error) {
    console.error('Error in Google callback:', error);
    const errorMsg = encodeURIComponent(error.message || 'unknown_error');
    return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/draft?auth=error&msg=${errorMsg}`);
  }
};

/**
 * Delete email config and revoke token
 */
const deleteEmailConfig = async (req, res) => {
  try {
    const { senderEmail } = req.body;
    const user = await User.findById(req.user._id);

    if (!senderEmail) return res.status(400).json({ success: false, message: 'Sender email is required' });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const configIndex = (user.emailConfigs || []).findIndex(config => config.senderEmail === senderEmail);
    if (configIndex === -1) return res.status(404).json({ success: false, message: 'Email configuration not found' });

    const config = user.emailConfigs[configIndex];

    // Attempt revoke (best-effort)
    try {
      if (config.encryptedRefreshToken) {
        const decryptedRefreshToken = protection.decrypt(config.encryptedRefreshToken);
        const refreshTokenStr = (typeof decryptedRefreshToken === 'string' ? decryptedRefreshToken : decryptedRefreshToken.toString());
        const oAuth2Client = createOAuthClient();
        await oAuth2Client.revokeToken(refreshTokenStr);
        console.log(`Successfully revoked token for ${senderEmail}`);
      }
    } catch (revokeError) {
      console.error(`Failed to revoke token for ${senderEmail}:`, revokeError.message);
      // don't block deletion
    }

    // Remove config from DB
    user.emailConfigs.splice(configIndex, 1);
    await user.save();

    return res.status(200).json({ success: true, message: 'Email configuration deleted successfully' });
  } catch (error) {
    console.error('Delete email config error:', error);
    return res.status(500).json({ success: false, message: 'Failed to delete email configuration', error: error.message });
  }
};

/**
 * Get email configs (non-sensitive)
 */
const getEmailConfigs = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const emailConfigs = (user.emailConfigs || []).map(config => ({ 
      senderEmail: config.senderEmail, 
      _id: config._id,
      invalid: config.invalid || false 
    }));
    return res.status(200).json({ success: true, data: emailConfigs });
  } catch (error) {
    console.error('Error fetching email configs:', error);
    return res.status(500).json({ success: false, message: 'Failed to fetch email configurations', error: error.message });
  }
};

/* ===================== CAMPAIGN & SENDING ===================== */

/**
 * Create Email Campaign
 */
const createEmail = async (req, res) => {
  const { subject, body, recipientData, senderEmail } = req.body;

  if (!subject || !body || !recipientData || !senderEmail) {
    return res.status(400).json({ success: false, message: 'All fields are required' });
  }

  // Validate recipients: expects keys recipientEmail and recipientName (and optionally personalizedSubject/body)
  const invalidRecipients = recipientData.filter(r =>
    !r.recipientEmail || !r.recipientName
  );

  if (invalidRecipients.length > 0) {
    return res.status(400).json({
      success: false,
      message: 'Invalid recipient data. Each recipient must include recipientEmail and recipientName.'
    });
  }

  try {
    // Normalize sender email to lowercase for consistency
    const normalizedSenderEmail = senderEmail.toLowerCase().trim();
    
    // Verify that the sender email is configured and valid
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const emailConfig = (user.emailConfigs || []).find(cfg => 
      cfg.senderEmail.toLowerCase() === normalizedSenderEmail
    );
    if (!emailConfig) {
      console.error('❌ Email config not found during campaign creation for:', normalizedSenderEmail);
      console.error('Available configs:', (user.emailConfigs || []).map(cfg => cfg.senderEmail));
      return res.status(400).json({ 
        success: false, 
        message: `Email configuration for ${senderEmail} not found. Please authenticate this Gmail account first.`,
        requiresAuth: true
      });
    }

    if (emailConfig.invalid) {
      return res.status(400).json({ 
        success: false, 
        message: `Gmail account ${senderEmail} authentication has expired or is invalid. Please re-authenticate this account.`,
        requiresReauth: true,
        senderEmail: senderEmail
      });
    }
    
    console.log('✅ Creating campaign with senderEmail:', normalizedSenderEmail);
    const campaign = new EmailCampaign({
      senderId: req.user._id,
      senderEmail: normalizedSenderEmail, // Use normalized email
      recipientData,
      subject,
      body,
      stats: { total: recipientData.length, sent: 0, failed: 0 }
    });

    await campaign.save();

    return res.status(201).json({ success: true, message: 'Email campaign created successfully', mailId: campaign._id, data: campaign });
  } catch (error) {
    console.error('Error creating email campaign:', error);
    return res.status(500).json({ success: false, message: 'Failed to create email campaign', error: error.message });
  }
};

/**
 * Helper: obtains an access token using refresh token and returns { accessToken, expiresIn }
 */
async function obtainAccessTokenFromRefresh(oAuth2Client, refreshToken) {
  try {
    // Clear any existing credentials first
    oAuth2Client.setCredentials({});
    
    // Set the refresh token
    oAuth2Client.setCredentials({ refresh_token: refreshToken });
    
    // Get access token
    const tokenResponse = await oAuth2Client.getAccessToken();

    // tokenResponse may be either string or object depending on googleapis version
    const accessToken = tokenResponse?.token || tokenResponse;
    
    // try to extract expiry info if present
    const expiresIn = tokenResponse?.res?.data?.expires_in || 3600;
    
    console.log('Access token obtained successfully, expires in:', expiresIn, 'seconds');
    
    return { accessToken, expiresIn };
  } catch (error) {
    console.error('Error obtaining access token:', error.message);
    // rethrow to be handled by caller
    throw error;
  }
}

/**
 * Send bulk emails using OAuth2
 */
const sendBulkEmails = async (req, res) => {
  try {
    const { mailId } = req.params;
    const campaign = await EmailCampaign.findOne({ _id: mailId });
    if (!campaign) return res.status(404).json({ success: false, message: 'Email campaign not found' });

    if (campaign.status === 'processing' || campaign.status === 'completed') {
      return res.status(400).json({ success: false, message: `Campaign is already ${campaign.status}.` });
    }

    console.log('📧 Starting email send - Campaign senderEmail:', campaign.senderEmail);
    console.log('📧 Campaign ID:', mailId);
    console.log('📧 Campaign subject:', campaign.subject);

    const user = await User.findById(campaign.senderId);
    if (!user) return res.status(404).json({ success: false, message: 'User associated with this campaign not found.' });

    console.log('👤 User found:', user.userName);
    console.log('📋 Available email configs:', (user.emailConfigs || []).map(cfg => `${cfg.senderEmail} (invalid: ${cfg.invalid})`).join(', '));
    console.log('🔍 Looking for email config matching:', campaign.senderEmail);

    // Case-insensitive matching for sender email
    const selectedConfig = (user.emailConfigs || []).find(cfg => 
      cfg.senderEmail.toLowerCase() === campaign.senderEmail.toLowerCase()
    );
    if (!selectedConfig || !selectedConfig.encryptedRefreshToken) {
      console.error('❌ Email config not found for:', campaign.senderEmail);
      console.error('Available configs:', (user.emailConfigs || []).map(cfg => cfg.senderEmail));
      return res.status(400).json({ success: false, message: 'Sender email configuration not found. Please re-authenticate your Gmail account.' });
    }
    
    console.log('✅ Using email config for:', selectedConfig.senderEmail);
    console.log('✅ Config is invalid:', selectedConfig.invalid);

    try {
      console.log('🔓 Attempting to decrypt refresh token for:', campaign.senderEmail);
      // Decrypt refresh token
      const rawDecrypted = protection.decrypt(selectedConfig.encryptedRefreshToken);
      const decryptedRefreshToken = typeof rawDecrypted === 'string' ? rawDecrypted : rawDecrypted.toString();

      console.log('🔑 Successfully decrypted refresh token (length:', decryptedRefreshToken.length, 'chars)');

      const oAuth2Client = createOAuthClient();
      
      // Get an access token (and expiry)
      let accessToken, expiresIn;
      try {
        console.log('🔄 Requesting new access token from Google for:', campaign.senderEmail);
        const tokenResult = await obtainAccessTokenFromRefresh(oAuth2Client, decryptedRefreshToken);
        accessToken = tokenResult.accessToken;
        expiresIn = tokenResult.expiresIn;
        console.log('✅ Access token obtained successfully');
      } catch (tokenError) {
        console.error('❌ Error obtaining access token:', tokenError.message);
        
        // Check if it's an authentication error
        if (tokenError.message?.includes('invalid_grant') || 
            tokenError.message?.includes('invalid_token') ||
            tokenError.message?.includes('Token has been revoked') ||
            tokenError.message?.includes('User credentials invalid')) {
          // Mark config as invalid
          selectedConfig.invalid = true;
          await user.save();
          
          return res.status(401).json({ 
            success: false, 
            message: 'Gmail authentication expired or invalid. Please re-authenticate your Gmail account by deleting and re-adding it.',
            error: 'INVALID_REFRESH_TOKEN',
            requiresReauth: true
          });
        }
        
        throw tokenError;
      }

      if (!accessToken) {
        throw new Error('Failed to obtain access token from Google.');
      }

      // compute expiry timestamp in seconds (nodemailer expects seconds, not milliseconds)
      const now = Math.floor(Date.now() / 1000);
      let tokenExpiry = now + expiresIn;

       // Create transporter with just the basic OAuth2 info
       // We'll update the accessToken dynamically when sending each email
       console.log('📬 Creating nodemailer transporter with senderEmail:', campaign.senderEmail);
       console.log('🔑 Using access token that expires in:', expiresIn, 'seconds');
       const transporter = nodemailer.createTransport({
         service: 'gmail',
         auth: {
           type: 'OAuth2',
           user: campaign.senderEmail,
           clientId: GOOGLE_CLIENT_ID,
           clientSecret: GOOGLE_CLIENT_SECRET,
           refreshToken: decryptedRefreshToken,
           accessToken: accessToken,  // Pass the freshly obtained token
           expires: tokenExpiry
         },
         // Enable OAuth2 debugging
         debug: true
       });

       // Store a reference to refresh the token when needed
       const refreshAccessToken = async () => {
         console.log('🔄 Refreshing access token...');
         const result = await obtainAccessTokenFromRefresh(oAuth2Client, decryptedRefreshToken);
         const newExpiry = Math.floor(Date.now() / 1000) + result.expiresIn;
         tokenExpiry = newExpiry; // Update the closure variable
         transporter.options.auth.accessToken = result.accessToken;
         transporter.options.auth.expires = newExpiry;
         console.log('✅ Access token refreshed, new expiry:', newExpiry);
         return result.accessToken;
       };

      // Verify transporter but don't crash on verification failure — log and continue
      try {
        await transporter.verify();
        console.log('✅ Transporter verified successfully');
      } catch (verifyErr) {
        console.error('❌ Transporter verification failed:', verifyErr.message);
        console.error('Verification error details:', verifyErr);
        // Mark campaign as failed
        campaign.status = 'failed';
        await campaign.save();
        return res.status(500).json({ 
          success: false, 
          message: 'Email authentication failed. Please re-authenticate your Gmail account.',
          error: verifyErr.message
        });
      }

      // Mark campaign as processing
      campaign.status = 'processing';
      await campaign.save();

      const emailPromises = campaign.recipientData.map(async (recipient) => {
        const recipientName = recipient.recipientName;
        const recipientEmail = recipient.recipientEmail;
        const personalizedSubject = recipient.personalizedSubject || campaign.subject;
        const personalizedBody = recipient.personalizedBody || campaign.body;

        const mailOptions = {
          from: `${user.userName} <${campaign.senderEmail}>`,
          to: recipientEmail,
          subject: personalizedSubject,
          html: personalizedBody,
          text: convert(personalizedBody)
        };

        try {
          // Check if we need to refresh the token before sending
          const currentTime = Math.floor(Date.now() / 1000);
          if (currentTime >= tokenExpiry - 60) {
            console.log('🔄 Token expiring soon, refreshing before send...');
            await refreshAccessToken();
          }

          await transporter.sendMail(mailOptions);

          recipient.status = 'sent';
          campaign.stats.sent++;
          return { status: 'sent', email: recipientEmail };
        } catch (err) {
          // detect invalid_grant (refresh token revoked) and mark config invalid
          const errMsg = err?.message || String(err);
          console.error(`Failed to send to ${recipientEmail}:`, errMsg);

          recipient.status = 'failed';
          recipient.error = errMsg;
          campaign.stats.failed++;

          // Check for various authentication error messages
          const authErrorPatterns = [
            'invalid_grant',
            'invalid_token',
            'Token has been revoked',
            'User credentials invalid',
            'Username and Password not accepted',
            'Invalid login',
            'Authentication failed'
          ];
          
          const isAuthError = authErrorPatterns.some(pattern => 
            errMsg.toLowerCase().includes(pattern.toLowerCase())
          );

          if (isAuthError) {
            console.error(`Authentication error detected for ${campaign.senderEmail}. Marking config as invalid.`);
            // mark config as invalid so user can re-authenticate
            selectedConfig.invalid = true;
            try { await user.save(); } catch (saveErr) { console.error('Failed to mark config invalid:', saveErr.message); }
            
            // Stop processing and return error
            throw new Error(`Gmail authentication failed: ${errMsg}. Please re-authenticate your Gmail account.`);
          }

          return { status: 'failed', email: recipientEmail, error: errMsg };
        }
      });

      try {
        await Promise.all(emailPromises);
      } catch (authError) {
        // Authentication error occurred, stop processing
        if (authError.message?.includes('Gmail authentication failed')) {
          campaign.status = 'failed';
          await campaign.save();
          return res.status(401).json({ 
            success: false, 
            message: authError.message,
            error: 'AUTHENTICATION_FAILED',
            requiresReauth: true
          });
        }
        throw authError;
      }

      campaign.status = campaign.stats.failed === 0 ? 'completed' : 'failed';
      campaign.markModified('recipientData');
      await campaign.save();

      return res.status(200).json({ success: true, message: `Email campaign completed. ${campaign.stats.sent} sent, ${campaign.stats.failed} failed` });
    } catch (error) {
      console.error('Error in email processing (OAuth):', error);
      // If error indicates token is invalid, mark config invalid
      if (error?.message?.includes('invalid_grant') || error?.message?.includes('invalid_token')) {
        selectedConfig.invalid = true;
        try { await user.save(); } catch (saveErr) { console.error('Failed to save invalid flag on config:', saveErr.message); }
      }
      campaign.status = 'failed';
      await campaign.save().catch(() => {});
      return res.status(500).json({ success: false, message: error.message || 'Failed to send emails due to authentication error.' });
    }
  } catch (error) {
    console.error('Error in sending bulk emails (outer):', error);
    return res.status(500).json({ success: false, message: error.message || 'An unexpected error occurred.' });
  }
};

/* ===================== STATS & REPORTING ===================== */

const getSentEmails = async (req, res) => {
  try {
    const campaigns = await EmailCampaign.find({ senderId: req.user._id }).sort({ createdAt: -1 });

    const sentEmails = campaigns.map(campaign => ({
      _id: campaign._id,
      subject: campaign.subject,
      recipientCount: (campaign.recipientData || []).length,
      status: campaign.status,
      createdAt: campaign.createdAt,
      stats: campaign.stats,
      recipients: (campaign.recipientData || []).map(recipient => ({
        name: recipient.recipientName,
        email: recipient.recipientEmail,
        status: recipient.status || 'pending',
        error: recipient.error || null,
        customFields: recipient.customFields || {}
      }))
    }));

    return res.status(200).json({ success: true, data: sentEmails });
  } catch (error) {
    console.error('Error fetching sent emails:', error);
    return res.status(500).json({ success: false, message: 'Failed to fetch sent emails', error: error.message });
  }
};

const getEmailStats = async (req, res) => {
  try {
    const campaigns = await EmailCampaign.find({ senderId: req.user._id });

    const stats = {
      totalCampaigns: campaigns.length,
      completed: campaigns.filter(c => c.status === 'completed').length,
      failed: campaigns.filter(c => c.status === 'failed').length,
      processing: campaigns.filter(c => c.status === 'processing').length,
      pending: campaigns.filter(c => !c.status || c.status === 'pending').length,
      totalRecipients: campaigns.reduce((acc, c) => acc + (c.stats?.total || 0), 0),
      totalSent: campaigns.reduce((acc, c) => acc + (c.stats?.sent || 0), 0),
      totalFailed: campaigns.reduce((acc, c) => acc + (c.stats?.failed || 0), 0)
    };

    return res.status(200).json({ success: true, stats });
  } catch (error) {
    console.error('Error fetching email stats:', error);
    return res.status(500).json({ success: false, message: 'Failed to fetch email stats', error: error.message });
  }
};

module.exports = {
  getGoogleAuthUrl,
  handleGoogleCallback,
  deleteEmailConfig,
  getEmailConfigs,
  createEmail,
  sendBulkEmails,
  getSentEmails,
  getEmailStats
};
