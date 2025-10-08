
// Load environment variables from .env file
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const express = require('express');
const https = require('https');
const fs = require('fs');
const helmet = require('helmet');
const cors = require('cors');
const multer = require('multer');
const cookieParser = require('cookie-parser');

// Import modules
const database = require('./database');
const security = require('./modules/security');
const logger = require('./modules/logger');
const loginModule = require('./modules/login');
const registerModule = require('./modules/register');
const forgotPasswordModule = require('./modules/forgot-password');
const SearchLimitModule = require('./modules/searchLimit');
const adminModule = require('./modules/admin');
const adminDownloadModule = require('./modules/admin-download');
const MenuCustomization = require('./modules/menuCustomization');
const DomainVerification = require('./modules/domainVerification');
const UserCleanup = require('./modules/userCleanup');
const sessionCheck = require('./modules/sessionCheck');

// Configure multer for file uploads (used in backup restore)
const uploadBackup = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 500 * 1024 * 1024 }
}).single('backup');

// Import client modules
const CrawlerModule = require('./modules/client/crawler');
const ClientDatabase = require('./modules/client/database');
const ClientFileManager = require('./modules/client/fileManager');
const PublicSummaryViewer = require('./modules/publicSummaryViewer');
const AutoSummaryGenerator = require('./modules/autoSummaryGenerator');

const app = express();
const PORT = process.env.PORT || 5000;

// Trust proxy for rate limiting in Replit environment
app.set('trust proxy', 1);

// Security middleware - Configure helmet to allow iframe embedding
app.use(helmet({
  frameguard: false, // Disable X-Frame-Options to allow iframe
  contentSecurityPolicy: false // Disable CSP or configure it properly below
}));
app.use(security.securityHeaders);
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? process.env.ALLOWED_ORIGINS?.split(',') : true,
  credentials: true
}));

// Rate limiting
const loginLimiter = security.createRateLimit(15 * 60 * 1000, 5); // 5 attempts per 15 minutes
const registerLimiter = security.createRateLimit(60 * 60 * 1000, 3); // 3 registrations per hour
const forgotPasswordLimiter = security.createRateLimit(60 * 60 * 1000, 3); // 3 attempts per hour

app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// Add logging middleware
app.use(logger.logRequest.bind(logger));

// Initialize local database
database.init().then(async () => {
  logger.info('Local database ready');
  logger.database('SQLite database successfully connected');
  
  // Initialize client modules
  global.crawlerModule = new CrawlerModule(database);
  global.clientDatabase = new ClientDatabase();
  global.clientFileManager = new ClientFileManager();
  global.publicSummaryViewer = new PublicSummaryViewer(global.clientDatabase, logger);
  global.autoSummaryGenerator = new AutoSummaryGenerator(database, global.clientDatabase, global.crawlerModule);
  
  // Initialize client tables
  await global.clientDatabase.initClientTables();
  logger.info('Client modules ready');
  
  // Initialize search limit module
  const defaultDailyLimit = Number(process.env.DAILY_SEARCH_LIMIT) || 10;
  global.searchLimit = new SearchLimitModule(database, logger, { defaultDailyLimit });
  await global.searchLimit.init();
  logger.info(`Daily search limit module ready (default limit: ${defaultDailyLimit})`);
  
  // Initialize menu customization module
  global.menuCustomization = new MenuCustomization(database, logger);
  await global.menuCustomization.initialize();
  logger.info('Menu customization module ready');
  
  // Initialize domain verification module
  global.domainVerification = new DomainVerification(database, logger);
  logger.info('Domain verification module ready');
  
  // Initialize user cleanup module
  global.userCleanup = new UserCleanup(database, logger);
  logger.info('User cleanup module ready');
}).catch((error) => {
  logger.error('Error connecting to database', error);
});

// Authentication middleware
const requireAuth = async (req, res, next) => {
  try {
    const sessionId = req.headers['x-session-id'];
    const csrfToken = req.headers['x-csrf-token'];

    if (!sessionId || !csrfToken) {
      logger.security('Request without authentication', { ip: req.ip, path: req.path });
      return res.status(401).json({ error: 'Authentication required' });
    }

    const session = await security.validateSession(sessionId);
    if (!session) {
      logger.security('Invalid or expired session', { sessionId, ip: req.ip });
      return res.status(401).json({ error: 'Invalid or expired session' });
    }

    const isValidCSRF = await security.validateCSRF(csrfToken, sessionId);
    if (!isValidCSRF) {
      logger.security('CSRF token validation failed', { sessionId, ip: req.ip });
      return res.status(403).json({ error: 'CSRF token validation failed' });
    }

    req.user = { id: session.userId };
    req.userId = session.userId;
    next();
  } catch (error) {
    logger.error('Error in authentication middleware', error, { ip: req.ip });
    return res.status(500).json({ error: 'Authentication error' });
  }
};

// Verification middleware
const requireVerified = async (req, res, next) => {
  try {
    const result = await database.query(
      'SELECT verification_status FROM users WHERE id = ?',
      [req.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (result.rows[0].verification_status !== 'verified') {
      return res.status(403).json({ 
        error: 'Domain verification required',
        message: 'To access this feature, you must first verify your domain',
        verified: false
      });
    }

    next();
  } catch (error) {
    logger.error('Error in verification middleware', error, { ip: req.ip });
    return res.status(500).json({ error: 'Verification check error' });
  }
};

// Apply session check middleware to all routes
app.use(sessionCheck.checkActiveSession);

// Serve HTML pages
app.get('/', (req, res) => {
  // Check if user is authenticated
  const sessionId = req.headers['x-session-id'] || req.cookies?.sessionId;
  if (sessionId) {
    // Redirect authenticated users to dashboard
    res.redirect('/dashboard');
  } else {
    // Show landing page to non-authenticated users
    res.sendFile(path.join(__dirname, 'public', 'landing.html'));
  }
});

app.get('/login', sessionCheck.redirectIfAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', sessionCheck.redirectIfAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/forgot-password', sessionCheck.redirectIfAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'forgot-password.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/menu-customization', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'menu-customization.html'));
});

app.get('/domain-verification', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'domain-verification.html'));
});

app.get('/url-management', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'url-management.html'));
});

app.get('/docs', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'docs.html'));
});

// API Routes
app.post('/api/register', registerLimiter, async (req, res) => {
  try {
    const { username, password, securityQuestion, securityAnswer, domain } = req.body;
    const result = await registerModule.registerUser(username, password, securityQuestion, securityAnswer, domain);
    
    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    logger.error('Error in registration route', error, { username: req.body.username, domain: req.body.domain, ip: req.ip });
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await loginModule.authenticateUser(username, password, req);
    
    if (result.success) {
      res.status(200).json(result);
    } else {
      res.status(401).json(result);
    }
  } catch (error) {
    logger.error('Error in login route', error, { username: req.body.username, ip: req.ip });
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/logout', async (req, res) => {
  try {
    const sessionId = req.headers['x-session-id'];
    const result = await loginModule.logout(sessionId);
    res.status(200).json(result);
  } catch (error) {
    logger.error('Error in logout route', error, { ip: req.ip });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Forgot password routes
app.get('/api/security-question/:username', forgotPasswordLimiter, async (req, res) => {
  try {
    const { username } = req.params;
    const result = await forgotPasswordModule.getSecurityQuestion(username);
    
    if (result.success) {
      res.status(200).json(result);
    } else {
      res.status(404).json(result);
    }
  } catch (error) {
    logger.error('Error in security question route', error, { username: req.params.username, ip: req.ip });
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/forgot-password/verify', forgotPasswordLimiter, async (req, res) => {
  try {
    const { username, securityAnswer } = req.body;
    const result = await forgotPasswordModule.verifySecurityAnswer(username, securityAnswer);
    
    if (result.success) {
      res.status(200).json(result);
    } else {
      res.status(401).json(result);
    }
  } catch (error) {
    logger.error('Error in security answer verification route', error, { username: req.body.username, ip: req.ip });
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/forgot-password/reset', forgotPasswordLimiter, async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;
    const result = await forgotPasswordModule.resetPassword(resetToken, newPassword);
    
    if (result.success) {
      res.status(200).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    logger.error('Error in password recovery route', error, { ip: req.ip });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected route example
app.get('/api/profile', requireAuth, async (req, res) => {
  try {
    const result = await database.query(
      'SELECT id, username, domain, verification_status, created_at, last_login FROM users WHERE id = ?',
      [req.user.id]
    );
    
    if (result.rows.length > 0) {
      res.json({ success: true, user: result.rows[0] });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    logger.error('Error in profile route', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Domain verification routes
app.post('/api/domain/request-verification', requireAuth, async (req, res) => {
  try {
    const result = await global.domainVerification.requestVerification(req.userId);
    res.json(result);
  } catch (error) {
    logger.error('Error in domain verification request', error, { userId: req.userId, ip: req.ip });
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.post('/api/domain/verify', requireAuth, async (req, res) => {
  try {
    const result = await global.domainVerification.verifyDomain(req.userId);
    res.json(result);
  } catch (error) {
    logger.error('Error in domain verification', error, { userId: req.userId, ip: req.ip });
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/domain/status', requireAuth, async (req, res) => {
  try {
    const result = await global.domainVerification.getVerificationStatus(req.userId);
    res.json(result);
  } catch (error) {
    logger.error('Error getting verification status', error, { userId: req.userId, ip: req.ip });
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.post('/api/domain/subdomain', requireAuth, requireVerified, async (req, res) => {
  try {
    const { subdomain } = req.body;
    const result = await global.domainVerification.addSubdomain(req.userId, subdomain);
    res.json(result);
  } catch (error) {
    logger.error('Error adding subdomain', error, { userId: req.userId, ip: req.ip });
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.delete('/api/domain/subdomain/:subdomain', requireAuth, requireVerified, async (req, res) => {
  try {
    const { subdomain } = req.params;
    const result = await global.domainVerification.removeSubdomain(req.userId, subdomain);
    res.json(result);
  } catch (error) {
    logger.error('Error removing subdomain', error, { userId: req.userId, ip: req.ip });
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Menu customization routes (protected by verification)
app.get('/api/menu-items', requireAuth, requireVerified, async (req, res) => {
  try {
    const result = await global.menuCustomization.getMenuItems(req.userId);
    res.json(result);
  } catch (error) {
    logger.error('Error getting menu items', error, { userId: req.userId, ip: req.ip });
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error',
      items: []
    });
  }
});

app.post('/api/menu-items', requireAuth, requireVerified, async (req, res) => {
  try {
    const { items } = req.body;
    
    if (!Array.isArray(items)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid items format' 
      });
    }

    const result = await global.menuCustomization.saveMenuItems(req.userId, items);
    res.json(result);
  } catch (error) {
    logger.error('Error saving menu items', error, { userId: req.userId, ip: req.ip });
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error' 
    });
  }
});

// Search limit middleware wrapper
const searchLimitAndCount = (req, res, next) => {
  if (global.searchLimit) {
    return global.searchLimit.enforceDailyLimitAndCount(req, res, next);
  }
  next();
};

// Validate search query function
function validateSearchQuery(query) {
  if (!query || typeof query !== 'string') {
    return { valid: false, error: 'Query is required' };
  }

  // Check for non-English characters
  const nonEnglishPattern = /[^\x00-\x7F]/;
  if (nonEnglishPattern.test(query)) {
    return { 
      valid: false, 
      error: 'Only English characters are supported'
    };
  }

  // Allowed characters: a-z, A-Z, 0-9, space, and limited special chars
  const allowedPattern = /^[a-zA-Z0-9\s.,?!\-_+@#]+$/;
  if (!allowedPattern.test(query)) {
    return { 
      valid: false, 
      error: 'Only English letters, numbers, and limited special characters (.,?!-_+@#) are allowed'
    };
  }

  // Length check
  if (query.trim().length > 500) {
    return { valid: false, error: 'Query too long (max 500 characters)' };
  }

  return { valid: true };
}

// Submit URL for crawling and summarization
app.post('/api/submit-url', requireAuth, searchLimitAndCount, async (req, res) => {
  try {
    const { url } = req.body;
    const userId = req.user.id;
    
    if (!url || url.trim().length === 0) {
      return res.status(400).json({ error: 'URL is required' });
    }

    const userResult = await database.query('SELECT username, domain FROM users WHERE id = ?', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const username = userResult.rows[0].username;
    const userDomain = userResult.rows[0].domain;
    
    if (!userDomain) {
      return res.status(400).json({ error: 'No domain configured for this user' });
    }

    // Get user's subdomains
    const subdomainsResult = await database.query(
      'SELECT subdomain FROM user_subdomains WHERE user_id = ?',
      [userId]
    );
    const userSubdomains = subdomainsResult.rows.map(r => r.subdomain);

    try {
      const submittedUrl = new URL(url.trim());
      const userDomainUrl = userDomain.startsWith('http') ? new URL(userDomain) : new URL(`https://${userDomain}`);
      
      const submittedHostname = submittedUrl.hostname.toLowerCase().replace(/^www\./, '');
      const userHostname = userDomainUrl.hostname.toLowerCase().replace(/^www\./, '');
      
      // Check if URL matches main domain or any subdomain
      const isMainDomain = submittedHostname === userHostname;
      const isAllowedSubdomain = userSubdomains.some(subdomain => 
        submittedHostname === subdomain.replace(/^www\./, '')
      );

      if (!isMainDomain && !isAllowedSubdomain) {
        return res.status(403).json({ 
          error: `URL must be from your domain or registered subdomains (${userHostname})`,
          submittedDomain: submittedHostname,
          allowedDomain: userHostname,
          allowedSubdomains: userSubdomains
        });
      }
    } catch (urlError) {
      return res.status(400).json({ error: 'Invalid URL format' });
    }

    // Validate URL doesn't redirect before processing
    logger.info('Validating URL for redirects', { userId, url });
    const urlValidation = await global.crawlerModule.validateUrlExists(url.trim());
    
    if (!urlValidation.exists) {
      logger.info('URL does not exist (manual submission)', { userId, url, status: urlValidation.status });
      return res.status(404).json({
        success: false,
        error: 'URL does not exist or is not accessible',
        httpStatus: urlValidation.status
      });
    }

    // Check if URL redirected
    if (urlValidation.redirected && urlValidation.finalUrl !== url.trim()) {
      logger.info('URL redirects to different location (manual submission)', { 
        userId, 
        originalUrl: url.trim(), 
        finalUrl: urlValidation.finalUrl 
      });
      return res.status(400).json({
        success: false,
        error: 'URL redirects are not allowed. Please submit the final destination URL.',
        originalUrl: url.trim(),
        redirectsTo: urlValidation.finalUrl
      });
    }

    // Generate URL hash to check for duplicates
    const urlHash = global.crawlerModule.hashUrl(url.trim());
    
    // Check if URL already exists in system (completed, crawling, or pending)
    const existingCrawl = await global.clientDatabase.getCrawlStatus(urlHash);
    
    if (existingCrawl) {
      // URL already exists in system - reject duplicate
      logger.info('URL already exists in system, rejecting duplicate', { 
        userId, 
        url, 
        urlHash,
        status: existingCrawl.crawl_status 
      });
      
      // Find existing search request for this URL to return its requestId
      const existingSearch = await database.query(
        'SELECT request_id FROM searches WHERE user_id = ? AND result_urls LIKE ? ORDER BY created_at DESC LIMIT 1',
        [userId, `%${urlHash}%`]
      );
      
      const existingRequestId = existingSearch.rows.length > 0 
        ? existingSearch.rows[0].request_id 
        : null;

      return res.status(409).json({
        success: false,
        error: 'This URL has already been submitted',
        urlHash: urlHash,
        existingRequestId: existingRequestId,
        status: existingCrawl.crawl_status,
        alreadyExists: true,
        message: existingCrawl.crawl_status === 'completed' 
          ? 'URL has been processed. View its summary in history.'
          : existingCrawl.crawl_status === 'crawling'
          ? 'URL is currently being processed. Please wait.'
          : 'URL is in processing queue. Please check back shortly.'
      });
    }

    // Create unique search record for new URL
    const timestamp = Date.now();
    const crypto = require('crypto');
    const requestId = crypto.createHash('sha256')
                           .update(`${username}_${timestamp}_${url}_${Math.random()}`)
                           .digest('hex');

    await database.query(
      'INSERT INTO searches (request_id, user_id, query) VALUES (?, ?, ?)',
      [requestId, userId, url]
    );

    try {
      const crawlResult = await global.crawlerModule.crawlUrl(url, userId);
      
      if (crawlResult.success) {
        await database.query(
          'UPDATE searches SET result_urls = ? WHERE request_id = ?',
          [JSON.stringify([crawlResult.urlHash]), requestId]
        );

        logger.info('URL submitted and crawled successfully', { userId, url, requestId, urlHash: crawlResult.urlHash });

        res.json({
          success: true,
          requestId,
          urlHash: crawlResult.urlHash,
          message: 'URL submitted for processing'
        });
      } else {
        res.status(500).json({ 
          error: 'Failed to process URL',
          requestId
        });
      }

    } catch (crawlError) {
      logger.error('Error in crawl URL', crawlError, { userId, url, requestId });
      
      res.status(500).json({ 
        error: 'Failed to process URL',
        requestId,
        details: crawlError.message
      });
    }

  } catch (error) {
    logger.error('Error in submit URL', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get URL submission history
app.get('/api/url-history', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const result = await database.query(
      'SELECT request_id, query as url, created_at FROM searches WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
      [userId]
    );
    
    res.json({ success: true, submissions: result.rows });
  } catch (error) {
    logger.error('Error in URL history', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ error: 'Failed to get URL history' });
  }
});

// Database info endpoint
app.get('/api/database-info', async (req, res) => {
  try {
    const stats = await database.getStats();
    res.json({ success: true, database: stats });
  } catch (error) {
    logger.error('Error in database info', error, { ip: req.ip });
    res.status(500).json({ error: 'Failed to get database information' });
  }
});

// Client crawl URL endpoint
app.post('/api/crawl-url', requireAuth, async (req, res) => {
  try {
    const { url } = req.body;
    const userId = req.user.id;
    
    if (!url || url.trim().length === 0) {
      return res.status(400).json({ error: 'URL is required' });
    }

    logger.info('Crawl URL request', { userId, url });
    
    const result = await global.crawlerModule.crawlUrl(url, userId);
    
    if (result.success) {
      res.json({
        success: true,
        requestId: result.requestId,
        urlHash: result.urlHash,
        data: result.data,
        storage: result.storage
      });
    } else {
      res.status(500).json({
        success: false,
        error: 'Crawl failed'
      });
    }

  } catch (error) {
    logger.error('Error in crawl URL', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user crawl requests
app.get('/api/client-requests', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const requests = await global.clientDatabase.getUserCrawlRequests(userId);
    
    res.json({
      success: true,
      totalRequests: requests.length,
      requests: requests
    });
  } catch (error) {
    logger.error('Error getting client requests', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ error: 'Failed to get client requests' });
  }
});

// Get crawl results by request ID
app.get('/api/client-results/:requestId', requireAuth, async (req, res) => {
  try {
    const { requestId } = req.params;
    const result = await global.crawlerModule.getCrawlResults(requestId);
    
    if (!result) {
      return res.status(404).json({
        success: false,
        error: 'Results not found'
      });
    }
    
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    logger.error('Error getting client results', error, { requestId: req.params.requestId, ip: req.ip });
    res.status(500).json({ error: 'Failed to get client results' });
  }
});

// Get client content by request ID
app.get('/api/client-content/:requestId', requireAuth, async (req, res) => {
  try {
    const { requestId } = req.params;
    const content = global.clientFileManager.loadContent(requestId);
    
    if (!content) {
      return res.status(404).json({
        success: false,
        error: 'Content not found'
      });
    }
    
    res.json({
      success: true,
      data: content
    });
  } catch (error) {
    logger.error('Error getting client content', error, { requestId: req.params.requestId, ip: req.ip });
    res.status(500).json({ error: 'Failed to get client content' });
  }
});

// Get crawl status for URL
app.get('/api/crawl-status/:urlHash', requireAuth, async (req, res) => {
  try {
    const { urlHash } = req.params;
    const status = await global.clientDatabase.getCrawlStatus(urlHash);
    
    if (!status) {
      return res.status(404).json({
        success: false,
        error: 'URL not found'
      });
    }
    
    res.json({
      success: true,
      data: status
    });
  } catch (error) {
    logger.error('Error in crawl status', error, { urlHash: req.params.urlHash, ip: req.ip });
    res.status(500).json({ error: 'Failed to get crawl status' });
  }
});

// Get pending crawls
app.get('/api/pending-crawls', requireAuth, async (req, res) => {
  try {
    const result = await database.query(`
      SELECT url_hash, original_url, crawl_status, crawl_attempts, last_seen
      FROM url_hashes 
      WHERE crawl_status IN ('pending', 'failed')
      ORDER BY last_seen DESC
      LIMIT 50
    `);
    
    res.json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    logger.error('Error in pending crawls', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ error: 'Failed to get pending crawls' });
  }
});

// Retry failed crawls
app.post('/api/retry-failed-crawls', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Get failed crawls with less than 3 attempts
    const failedCrawls = await database.query(`
      SELECT url_hash, original_url
      FROM url_hashes 
      WHERE crawl_status = 'failed' AND crawl_attempts < 3
      LIMIT 10
    `);
    
    if (failedCrawls.rows.length === 0) {
      return res.json({
        success: true,
        message: 'No failed crawls to retry',
        retriedCount: 0
      });
    }
    
    // Prepare URLs for retry
    const urlsToRetry = failedCrawls.rows.map(row => ({
      url: row.original_url,
      urlHash: row.url_hash
    }));
    
    // Start retry in background
    global.crawlerModule.crawlInBackground(urlsToRetry, userId).catch(error => {
      console.error('Error in retry:', error);
    });
    
    res.json({
      success: true,
      message: 'Retry started in background',
      retriedCount: urlsToRetry.length
    });
    
  } catch (error) {
    logger.error('Error in retry', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ error: 'Failed to retry crawls' });
  }
});

// Get client statistics
app.get('/api/client-stats', requireAuth, async (req, res) => {
  try {
    const stats = await global.clientDatabase.getClientStats();
    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    logger.error('Error in client stats', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ error: 'Failed to get client statistics' });
  }
});

// Get blocked domains list
app.get('/api/blocked-domains', requireAuth, async (req, res) => {
  try {
    const blockedDomains = global.crawlerModule.domainFilter.getBlockedDomains();
    res.json({
      success: true,
      blockedDomains: blockedDomains
    });
  } catch (error) {
    logger.error('Error getting blocked domains', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ error: 'Failed to get blocked domains' });
  }
});

// Add blocked domain
app.post('/api/blocked-domains', requireAuth, async (req, res) => {
  try {
    const { domain } = req.body;
    
    if (!domain || domain.trim().length === 0) {
      return res.status(400).json({ error: 'Domain is required' });
    }
    
    const added = global.crawlerModule.domainFilter.addBlockedDomain(domain.trim());
    
    if (added) {
      logger.info('New domain added to blocked list', { domain, userId: req.user.id });
      res.json({
        success: true,
        message: 'Domain added to blocked list',
        domain: domain.trim()
      });
    } else {
      res.json({
        success: false,
        message: 'Domain already exists in blocked list'
      });
    }
  } catch (error) {
    logger.error('Error adding blocked domain', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ error: 'Failed to add blocked domain' });
  }
});

// Remove blocked domain
app.delete('/api/blocked-domains/:domain', requireAuth, async (req, res) => {
  try {
    const { domain } = req.params;
    const removed = global.crawlerModule.domainFilter.removeBlockedDomain(domain);
    
    if (removed) {
      logger.info('Domain removed from blocked list', { domain, userId: req.user.id });
      res.json({
        success: true,
        message: 'Domain removed from blocked list',
        domain: domain
      });
    } else {
      res.status(404).json({
        success: false,
        message: 'Domain not found in blocked list'
      });
    }
  } catch (error) {
    logger.error('Error removing blocked domain', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ error: 'Failed to remove blocked domain' });
  }
});

// Test domain filter
app.post('/api/test-domain-filter', requireAuth, async (req, res) => {
  try {
    const { urls } = req.body;
    
    if (!urls || !Array.isArray(urls)) {
      return res.status(400).json({ error: 'URLs array is required' });
    }
    
    const testResult = global.crawlerModule.domainFilter.testFilter(urls);
    
    res.json({
      success: true,
      result: testResult
    });
  } catch (error) {
    logger.error('Error testing domain filter', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ error: 'Failed to test domain filter' });
  }
});

// =====================================================================
// ADMIN PANEL ROUTES
// =====================================================================

// Admin authentication middleware
const requireAdminAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'Admin authentication required' });
    }

    const token = authHeader.substring(7);
    const sessionId = token;

    // Validate admin session
    const session = await security.validateSession(sessionId);
    if (!session || session.userId !== 1) { // Assuming user with ID 1 is admin
      return res.status(401).json({ success: false, error: 'Invalid admin session' });
    }

    req.adminUserId = session.userId;
    next();
  } catch (error) {
    logger.error('Error in admin authentication middleware', error);
    return res.status(500).json({ success: false, error: 'Admin authentication error' });
  }
};

// Admin login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({ success: false, error: 'Password is required' });
    }

    const isValidPassword = await adminModule.verifyAdminPassword(password);
    if (!isValidPassword) {
      logger.security('Invalid admin panel login attempt', { ip: req.ip });
      return res.status(401).json({ success: false, error: 'Invalid admin password' });
    }

    // Create session for admin (assuming user with ID 1 is admin)
    const session = await security.createSession(1, req.ip, req.get('User-Agent'));
    
    logger.security('Successful admin login', { ip: req.ip, sessionId: session.sessionId });
    
    res.json({
      success: true,
      token: session.sessionId,
      message: 'Admin login successful'
    });

  } catch (error) {
    logger.error('Error in admin login', error);
    res.status(500).json({ success: false, error: 'Admin login failed' });
  }
});

// Get admin stats
app.get('/api/admin/stats', requireAdminAuth, async (req, res) => {
  try {
    const stats = await adminModule.getDatabaseStats();
    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    logger.error('Error getting admin stats', error);
    res.status(500).json({ success: false, error: 'Failed to get admin stats' });
  }
});

// Get users list for admin
app.get('/api/admin/users', requireAdminAuth, async (req, res) => {
  try {
    const users = await adminModule.getUsersList();
    res.json({
      success: true,
      data: users
    });
  } catch (error) {
    logger.error('Error getting users list', error);
    res.status(500).json({ success: false, error: 'Failed to get users list' });
  }
});

// Get system info for admin
app.get('/api/admin/system', requireAdminAuth, async (req, res) => {
  try {
    const systemInfo = await adminModule.getSystemInfo();
    res.json({
      success: true,
      data: systemInfo
    });
  } catch (error) {
    logger.error('Error getting system info', error);
    res.status(500).json({ success: false, error: 'Failed to get system info' });
  }
});

// Cleanup expired sessions
app.post('/api/admin/cleanup-sessions', requireAdminAuth, async (req, res) => {
  try {
    const result = await adminModule.cleanupExpiredSessions();
    logger.info('Session cleanup by admin', { cleaned: result.cleaned });
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    logger.error('Error cleaning up sessions', error);
    res.status(500).json({ success: false, error: 'Failed to cleanup sessions' });
  }
});

// Optimize database
app.post('/api/admin/optimize-database', requireAdminAuth, async (req, res) => {
  try {
    const result = await adminModule.optimizeDatabase();
    logger.info('Database optimization by admin');
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    logger.error('Error optimizing database', error);
    res.status(500).json({ success: false, error: 'Failed to optimize database' });
  }
});

// Get download statistics
app.get('/api/admin/download-stats', requireAdminAuth, async (req, res) => {
  try {
    const contentStats = await adminDownloadModule.getDirectoryStats('client_content');
    const dataStats = await adminDownloadModule.getDirectoryStats('data');
    
    res.json({
      success: true,
      data: {
        client_content: contentStats,
        data: dataStats
      }
    });
  } catch (error) {
    logger.error('Error getting download stats', error);
    res.status(500).json({ success: false, error: 'Failed to get download stats' });
  }
});

// Generate download token
app.post('/api/admin/generate-download-token', requireAdminAuth, async (req, res) => {
  try {
    const { directory } = req.body;
    
    if (!directory) {
      return res.status(400).json({ success: false, error: 'Directory name required' });
    }
    
    if (!adminDownloadModule.validateDirectory(directory)) {
      logger.security('Attempt to download unauthorized directory', { directory, userId: req.adminUserId });
      return res.status(403).json({ success: false, error: 'Invalid directory' });
    }
    
    const tokenData = adminDownloadModule.generateDownloadToken(req.adminUserId, directory);
    
    // Store token in memory for validation (you could use Redis in production)
    if (!global.downloadTokens) {
      global.downloadTokens = new Map();
    }
    global.downloadTokens.set(tokenData.token, tokenData);
    
    // Auto-cleanup expired tokens after 6 minutes
    setTimeout(() => {
      global.downloadTokens.delete(tokenData.token);
    }, 6 * 60 * 1000);
    
    logger.security('Download token created', { directory, userId: req.adminUserId });
    
    res.json({
      success: true,
      token: tokenData.token,
      expiresIn: 300 // 5 minutes
    });
  } catch (error) {
    logger.error('Error creating download token', error);
    res.status(500).json({ success: false, error: 'Failed to generate download token' });
  }
});

// Download directory as zip
app.get('/api/admin/download/:token', async (req, res) => {
  try {
    const { token } = req.params;
    
    if (!global.downloadTokens) {
      global.downloadTokens = new Map();
    }
    
    const tokenData = global.downloadTokens.get(token);
    
    if (!adminDownloadModule.verifyDownloadToken(token, tokenData)) {
      logger.security('Download attempt with invalid token', { token });
      return res.status(401).json({ success: false, error: 'Invalid or expired token' });
    }
    
    logger.security('Starting directory download', { 
      directory: tokenData.dirName, 
      userId: tokenData.userId 
    });
    
    // Create and stream zip file
    await adminDownloadModule.createZipArchive(tokenData.dirName, res);
    
    // Remove token after successful download
    global.downloadTokens.delete(token);
    
  } catch (error) {
    logger.error('Error downloading file', error);
    if (!res.headersSent) {
      res.status(500).json({ success: false, error: 'Download failed' });
    }
  }
});

// Preview uploaded backup zip contents
app.post('/api/admin/preview-backup', requireAdminAuth, (req, res) => {
  uploadBackup(req, res, async (err) => {
    if (err) {
      logger.error('Error uploading file', err);
      return res.status(400).json({ success: false, error: 'Upload failed' });
    }

    if (!req.file) {
      return res.status(400).json({ success: false, error: 'No file uploaded' });
    }

    try {
      const contents = await adminDownloadModule.getZipContents(req.file.buffer);
      
      res.json({
        success: true,
        fileName: req.file.originalname,
        fileSize: req.file.size,
        fileSizeFormatted: adminDownloadModule.formatBytes(req.file.size),
        contents: contents,
        totalFiles: contents.filter(c => !c.isDirectory).length,
        totalDirs: contents.filter(c => c.isDirectory).length
      });
    } catch (error) {
      logger.error('Error previewing backup', error);
      res.status(500).json({ success: false, error: 'Failed to preview backup' });
    }
  });
});

// Restore backup from uploaded zip
app.post('/api/admin/restore-backup', requireAdminAuth, (req, res) => {
  uploadBackup(req, res, async (err) => {
    if (err) {
      logger.error('Error uploading restore file', err);
      return res.status(400).json({ success: false, error: 'Upload failed' });
    }

    if (!req.file) {
      return res.status(400).json({ success: false, error: 'No file uploaded' });
    }

    const { targetDirectory } = req.body;
    
    if (!targetDirectory) {
      return res.status(400).json({ success: false, error: 'Target directory required' });
    }

    try {
      const result = await adminDownloadModule.extractZipBackup(
        req.file.buffer, 
        targetDirectory
      );
      
      logger.security('Successful backup restoration', { 
        targetDirectory,
        fileSize: req.file.size,
        userId: req.adminUserId 
      });
      
      res.json({
        success: true,
        message: result.message,
        extractedTo: result.extractedTo,
        fileSize: adminDownloadModule.formatBytes(req.file.size)
      });
    } catch (error) {
      logger.error('Error restoring backup', error);
      res.status(500).json({ success: false, error: 'Failed to restore backup' });
    }
  });
});

// =====================================================================
// CONTENT MANAGEMENT & SUMMARIZATION ROUTES (Integrated from agent-client)
// =====================================================================

const AGENT_URL = 'https://search-zqjl.onrender.com/proxy-search';

// Get all JSON files with their status and summaries
app.get('/api/content/files', requireAuth, async (req, res) => {
  try {
    const files = await global.clientDatabase.getAllJsonFiles();
    res.json({ success: true, files });
  } catch (error) {
    logger.error('Error getting content files', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get pending files for processing
app.get('/api/content/pending', requireAuth, async (req, res) => {
  try {
    const pendingFiles = await global.clientDatabase.getPendingSummaryFiles();
    res.json({ success: true, files: pendingFiles });
  } catch (error) {
    logger.error('Error getting pending files', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ success: false, error: error.message });
  }
});

// Search limit check middleware wrapper
const searchLimitCheck = (req, res, next) => {
  if (global.searchLimit) {
    return global.searchLimit.enforceDailyLimit(req, res, next);
  }
  next();
};

// Get domain summaries with pagination
app.get('/api/domain-summaries', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 10, 10); // حداکثر 10 آیتم
    const type = req.query.type || 'all'; // all, manual, auto
    const status = req.query.status || 'all'; // all, completed, processing
    const offset = (page - 1) * limit;

    // Get user domain and subdomains
    const userResult = await database.query('SELECT domain FROM users WHERE id = ?', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    const userDomain = userResult.rows[0].domain;
    if (!userDomain) {
      return res.status(400).json({ success: false, error: 'No domain configured' });
    }

    // Get user's subdomains
    const subdomainsResult = await database.query(
      'SELECT subdomain FROM user_subdomains WHERE user_id = ?',
      [userId]
    );
    const userSubdomains = subdomainsResult.rows.map(r => r.subdomain);

    // Extract domain pattern for LIKE query
    const domainPattern = userDomain.replace(/^https?:\/\//, '').replace(/^www\./, '');

    // Build WHERE clause to include main domain and all subdomains
    let whereConditions = [];
    let queryParams = [];

    // Add main domain condition
    whereConditions.push(`uh.original_url LIKE ?`);
    queryParams.push(`%${domainPattern}%`);

    // Add subdomain conditions
    if (userSubdomains.length > 0) {
      userSubdomains.forEach(subdomain => {
        const subPattern = subdomain.replace(/^https?:\/\//, '').replace(/^www\./, '');
        whereConditions.push(`uh.original_url LIKE ?`);
        queryParams.push(`%${subPattern}%`);
      });
    }

    // Combine all conditions with OR
    const domainCondition = `(${whereConditions.join(' OR ')})`;
    whereConditions = [domainCondition];

    if (status !== 'all') {
      if (status === 'completed') {
        whereConditions.push(`uh.summary_status = 'summarized'`);
      } else if (status === 'processing') {
        whereConditions.push(`uh.summary_status IN ('pending', 'processing', 'queued')`);
      }
    }

    // Add type filter using subquery
    let typeCondition = '';
    let typeParams = [];
    if (type === 'manual') {
      typeCondition = ` AND EXISTS (
        SELECT 1 FROM searches 
        WHERE user_id = ? AND result_urls LIKE '%' || uh.url_hash || '%'
      )`;
      typeParams.push(userId);
    } else if (type === 'auto') {
      typeCondition = ` AND NOT EXISTS (
        SELECT 1 FROM searches 
        WHERE user_id = ? AND result_urls LIKE '%' || uh.url_hash || '%'
      )`;
      typeParams.push(userId);
    }

    // Get total count (no userId needed in count query)
    const countQueryParams = [...queryParams, ...typeParams];
    const countQuery = `
      SELECT COUNT(*) as total
      FROM url_hashes uh
      WHERE ${whereConditions.join(' AND ')}${typeCondition}
    `;
    const countResult = await database.query(countQuery, countQueryParams);
    const total = countResult.rows[0].total;
    const totalPages = Math.ceil(total / limit);

    // Get paginated data
    const dataQuery = `
      SELECT 
        uh.url_hash,
        uh.original_url,
        COALESCE(uh.crawl_completed_at, uh.last_seen, uh.first_seen) as crawl_completed_at,
        uh.summary_status,
        s.summary_text,
        s.created_at as summary_date,
        CASE 
          WHEN EXISTS (
            SELECT 1 FROM searches 
            WHERE user_id = ? AND result_urls LIKE '%' || uh.url_hash || '%'
          ) THEN 'manual'
          ELSE 'auto'
        END as crawl_type
      FROM url_hashes uh
      LEFT JOIN summaries s ON uh.url_hash = s.url_hash
      WHERE ${whereConditions.join(' AND ')}${typeCondition}
      ORDER BY COALESCE(uh.crawl_completed_at, uh.last_seen, uh.first_seen) DESC
      LIMIT ? OFFSET ?
    `;
    
    // Build params: userId for CASE, domain params, userId for type filter (if any), limit, offset
    const dataParams = [userId, ...queryParams, ...typeParams, limit, offset];
    const dataResult = await database.query(dataQuery, dataParams);

    const items = dataResult.rows;

    res.json({
      success: true,
      data: {
        items: items,
        pagination: {
          page: page,
          limit: limit,
          total: total,
          totalPages: totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1
        }
      }
    });

  } catch (error) {
    logger.error('Error getting domain summaries', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get summaries for a specific search request
app.get('/api/search/:requestId/summaries', requireAuth, searchLimitCheck, async (req, res) => {
  try {
    const { requestId } = req.params;
    const userId = req.user.id;
    
    // First check if this search belongs to the user
    const searchResult = await database.query(
      'SELECT * FROM searches WHERE request_id = ? AND user_id = ?',
      [requestId, userId]
    );
    
    if (searchResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Search not found' });
    }
    
    // Get URL hashes from search results
    const search = searchResult.rows[0];
    let urlHashes = [];
    try {
      urlHashes = JSON.parse(search.result_urls || '[]');
    } catch (e) {
      urlHashes = [];
    }
    
    // Get summaries for these URLs
    const summaries = [];
    for (const urlHash of urlHashes) {
      const summaryResult = await global.clientDatabase.getSummaryByUrlHash(urlHash);
      if (summaryResult) {
        summaries.push({
          urlHash: urlHash,
          originalUrl: summaryResult.original_url,
          summary: summaryResult.summary_text,
          status: summaryResult.summary_status,
          processedAt: summaryResult.summary_completed_at
        });
      }
    }
    
    res.json({ 
      success: true, 
      requestId: requestId,
      summaries: summaries,
      totalCount: summaries.length 
    });
    
  } catch (error) {
    logger.error('Error getting search summaries', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ success: false, error: error.message });
  }
});

// Process a specific file (enqueue to agent for summarization)
app.post('/api/content/:urlHash/process', requireAuth, async (req, res) => {
  try {
    const { urlHash } = req.params;
    const { priority = 1, maxAttempts = 3 } = req.body;
    
    // Get file info from database
    const files = await global.clientDatabase.getAllJsonFiles();
    const file = files.find(f => f.url_hash === urlHash);
    
    if (!file) {
      return res.status(404).json({ success: false, error: 'File not found' });
    }

    // Check if file path exists
    const fs = require('fs');
    const path = require('path');
    const filePath = path.join(__dirname, file.file_path);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ success: false, error: 'JSON file not found on disk' });
    }

    const jsonContent = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    
    // Send to agent for processing
    logger.info(`🚀 [${urlHash}] Sending file for processing...`, { userId: req.user.id });
    const axios = require('axios');
    const response = await axios.post(`${AGENT_URL}/api/process`, {
      fileId: urlHash,
      jsonData: jsonContent
    }, {
      timeout: 30000,
      headers: {
        'x-request-id': urlHash
      }
    });

    if (response.data.success) {
      // Save summary directly and mark as completed
      await global.clientDatabase.saveSummary(urlHash, response.data.summary);
      await global.clientDatabase.markFileAsSummarized(urlHash);
      
      res.json({ 
        success: true, 
        message: 'File processed and summary saved',
        summary: response.data.summary,
        urlHash: urlHash
      });
    } else {
      res.status(500).json({ 
        success: false, 
        error: response.data.error || 'Failed to process file' 
      });
    }

  } catch (error) {
    logger.error('Error sending file', error, { userId: req.user.id, ip: req.ip });
    if (error.code === 'ECONNREFUSED') {
      res.status(503).json({ 
        success: false, 
        error: 'Agent server is not available' 
      });
    } else {
      res.status(500).json({ 
        success: false, 
        error: error.message 
      });
    }
  }
});

// Process all pending files (enqueue all to agent)
app.post('/api/content/process-all', requireAuth, async (req, res) => {
  try {
    const pendingFiles = await global.clientDatabase.getPendingSummaryFiles();
    const results = [];
    const { priority = 1, maxAttempts = 3 } = req.body;
    
    logger.info(`📦 Sending ${pendingFiles.length} pending files...`, { userId: req.user.id });
    
    const fs = require('fs');
    const path = require('path');
    const axios = require('axios');
    
    for (const file of pendingFiles) {
      try {
        const filePath = path.join(__dirname, file.json_file_path);
        if (!fs.existsSync(filePath)) {
          console.error(`File not found: ${filePath}`);
          results.push({
            urlHash: file.url_hash,
            success: false,
            error: 'File not found on disk'
          });
          continue;
        }

        const jsonContent = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        
        // Send to agent for processing
        const response = await axios.post(`${AGENT_URL}/api/process`, {
          fileId: file.url_hash,
          jsonData: jsonContent
        }, {
          timeout: 30000,
          headers: {
            'x-request-id': file.url_hash
          }
        });

        if (response.data.success) {
          // Save summary directly and mark as completed
          await global.clientDatabase.saveSummary(file.url_hash, response.data.summary);
          await global.clientDatabase.markFileAsSummarized(file.url_hash);
          
          results.push({
            urlHash: file.url_hash,
            success: true,
            summary: response.data.summary.substring(0, 100) + '...',
            processed: true
          });
          
          console.log(`✅ Processed: ${file.url_hash}`);
        } else {
          results.push({
            urlHash: file.url_hash,
            success: false,
            error: response.data.error
          });
          console.error(`❌ Processing failed: ${file.url_hash} - ${response.data.error}`);
        }

      } catch (error) {
        results.push({
          urlHash: file.url_hash,
          success: false,
          error: error.message
        });
        console.error(`❌ Error sending ${file.url_hash}:`, error.message);
      }
    }
    
    const successCount = results.filter(r => r.success).length;
    
    res.json({ 
      success: true, 
      message: `Processed ${successCount}/${results.length} files`,
      results,
      summary: {
        total: results.length,
        processed: successCount,
        failed: results.length - successCount
      }
    });

  } catch (error) {
    logger.error('Error in batch sending', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get summary for a specific file
app.get('/api/content/:urlHash/summary', requireAuth, async (req, res) => {
  try {
    const { urlHash } = req.params;
    const files = await global.clientDatabase.getAllJsonFiles();
    const file = files.find(f => f.url_hash === urlHash);
    
    if (!file) {
      return res.status(404).json({ success: false, error: 'File not found' });
    }
    
    if (!file.summary_text) {
      return res.status(404).json({ success: false, error: 'Summary not found' });
    }
    
    res.json({ 
      success: true, 
      summary: file.summary_text,
      summaryDate: file.summary_date,
      urlHash: urlHash
    });

  } catch (error) {
    logger.error('Error getting summary', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ success: false, error: error.message });
  }
});

// Summary callback endpoint (called by agent when job completes) - SECURED
app.post('/api/summary-callback', async (req, res) => {
  try {
    // Security check: Verify internal request signature
    const authHeader = req.headers['x-internal-auth'];
    if (!authHeader) {
      logger.warn('❌ Summary callback rejected: Missing authentication header', { ip: req.ip });
      return res.status(401).json({ 
        success: false, 
        error: 'Authentication required' 
      });
    }

    // Parse timestamp and signature
    const [timestamp, signature] = authHeader.split('.');
    if (!timestamp || !signature) {
      logger.warn('❌ Summary callback rejected: Invalid auth format', { ip: req.ip });
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid authentication format' 
      });
    }

    // Check timestamp (prevent replay attacks - 5 minute window)
    const requestTime = parseInt(timestamp);
    const now = Date.now();
    if (Math.abs(now - requestTime) > 5 * 60 * 1000) {
      logger.warn('❌ Summary callback rejected: Request too old', { ip: req.ip, age: now - requestTime });
      return res.status(401).json({ 
        success: false, 
        error: 'Request timestamp invalid' 
      });
    }

    // Verify signature
    const crypto = require('crypto');
    const INTERNAL_SECRET = process.env.INTERNAL_SECRET;
    if (!INTERNAL_SECRET || INTERNAL_SECRET === 'development-internal-secret-for-mvp-only') {
      logger.error('❌ INTERNAL_SECRET not configured or using default value - security risk!');
      return res.status(500).json({ 
        success: false, 
        error: 'Server configuration error' 
      });
    }
    const requestBody = JSON.stringify(req.body);
    const expectedSignature = crypto.createHmac('sha256', INTERNAL_SECRET)
      .update(`${timestamp}.${requestBody}`)
      .digest('hex');

    if (signature !== expectedSignature) {
      logger.warn('❌ Summary callback rejected: Invalid signature', { ip: req.ip });
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid signature' 
      });
    }

    const { fileId, summary, metadata } = req.body;
    
    if (!fileId || !summary) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required fields: fileId and summary' 
      });
    }

    logger.info(`📥 [${fileId}] Received summary from agent (verified)`, { ip: req.ip });
    logger.info(`📝 [${fileId}] Summary length: ${summary.length} characters`);
    
    // Save summary to database
    await global.clientDatabase.saveSummary(fileId, summary);
    await global.clientDatabase.markFileAsSummarized(fileId);
    
    // Log metadata if provided
    if (metadata) {
      logger.info(`📊 [${fileId}] Metadata:`, {
        contentBlocks: metadata.contentBlocks,
        totalWords: metadata.totalWords,
        processingTime: metadata.processingTimeMs
      });
    }
    
    res.json({ 
      success: true, 
      message: 'Summary saved successfully',
      fileId: fileId
    });
    
  } catch (error) {
    logger.error(`❌ Error saving summary:`, error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// Content health check with database status
app.get('/api/content/health', requireAuth, async (req, res) => {
  try {
    // Check database connectivity
    const files = await global.clientDatabase.getAllJsonFiles();
    const pendingFiles = await global.clientDatabase.getPendingSummaryFiles();
    
    res.json({ 
      success: true, 
      message: 'Content system is running',
      timestamp: new Date().toISOString(),
      database: {
        connected: true,
        totalFiles: files.length,
        pendingFiles: pendingFiles.length,
        processedFiles: files.filter(f => f.summary_text).length
      }
    });
  } catch (error) {
    logger.error('Error in content system status', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({
      success: false,
      message: 'Content system running but database issue',
      timestamp: new Date().toISOString(),
      database: {
        connected: false,
        error: error.message
      }
    });
  }
});

// Agent health check
app.get('/api/agent/health', requireAuth, async (req, res) => {
  try {
    const axios = require('axios');
    const response = await axios.get(`${AGENT_URL}/api/health`, {
      timeout: 5000
    });
    res.json({ 
      success: true, 
      agent: response.data 
    });
  } catch (error) {
    logger.error('Error connecting to agent', error, { userId: req.user.id, ip: req.ip });
    res.status(503).json({ 
      success: false, 
      error: 'Agent server is not available',
      details: error.message
    });
  }
});

// Agent queue status
app.get('/api/agent/queue', requireAuth, async (req, res) => {
  try {
    const axios = require('axios');
    const response = await axios.get(`${AGENT_URL}/api/queue/status`, {
      timeout: 5000
    });
    res.json({ 
      success: true, 
      queue: response.data 
    });
  } catch (error) {
    logger.error('Error in agent queue status', error, { userId: req.user.id, ip: req.ip });
    res.status(503).json({ 
      success: false, 
      error: 'Agent server is not available',
      details: error.message
    });
  }
});

// =====================================================================
// PUBLIC SUMMARY VIEWER ROUTE (Catch-all for URL paths)
// =====================================================================

// Public summary viewer - must be before other catch-all routes
app.get(/^\/(.*)$/, async (req, res, next) => {
  // Skip static files, API routes, and auth pages
  const skipPaths = [
    '/api/',
    '/login',
    '/register',
    '/forgot-password',
    '/dashboard',
    '/admin',
    '/favicon',
    '/style.css',
    '/auth.js',
    '/domain-console.js',
    '/summaries.js',
    '/admin.js',
    '/search-results.css',
    '/landing.html'
  ];

  // Check if path should be skipped
  const shouldSkip = skipPaths.some(skipPath => req.path.startsWith(skipPath));
  
  if (shouldSkip || req.path === '/' || req.path === '/menu-customization') {
    return next();
  }

  // Try to serve as public summary
  try {
    const urlPath = req.path.substring(1); // Remove leading slash
    
    if (!urlPath) {
      return next();
    }

    const result = await global.publicSummaryViewer.getSummaryByPath(urlPath);

    if (result.success) {
      const domain = urlPath.split('/')[0];
      const htmlPage = await global.publicSummaryViewer.generateSummaryPage(result.data, domain);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(htmlPage);
    } else if (result.notFound || result.pending) {
      // Try auto-crawl
      const autoCrawlResult = await global.autoSummaryGenerator.handleAutoCrawlRequest(urlPath);
      
      if (autoCrawlResult.status === 'initiated' || autoCrawlResult.status === 'processing') {
        logger.info(`🤖 Auto-crawl ${autoCrawlResult.status} for: ${urlPath}`);
        const processingPage = global.publicSummaryViewer.generateErrorPage(
          'Content is being processed. Summary will appear automatically when ready.',
          urlPath,
          true // Enable auto-refresh polling
        );
        res.status(202).setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(processingPage);
      } else if (autoCrawlResult.status === 'completed') {
        // Summary ready, reload page
        res.redirect(req.path);
      } else if (autoCrawlResult.status === 'not_found' || autoCrawlResult.reason === 'url_not_found') {
        // URL does not exist (404) - DO NOT save to database
        logger.info(`🚫 404 - Page does not exist: ${urlPath} (HTTP ${autoCrawlResult.httpStatus || 'unknown'})`);
        const errorPage = global.publicSummaryViewer.generate404Page(urlPath);
        res.status(404).setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(errorPage);
      } else if (autoCrawlResult.status === 'not_eligible') {
        const errorPage = global.publicSummaryViewer.generateErrorPage(
          autoCrawlResult.message || 'This URL is not eligible for summarization or is not registered in the system.',
          urlPath,
          false // No auto-refresh
        );
        res.status(404).setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(errorPage);
      } else {
        const errorPage = global.publicSummaryViewer.generateErrorPage(
          'Error processing URL. Please try again.',
          urlPath,
          false
        );
        res.status(500).setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(errorPage);
      }
    } else {
      return next();
    }
  } catch (error) {
    logger.error('Error in public summary display', error, { path: req.path });
    next();
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error', err, { ip: req.ip, path: req.path });
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler for API routes only
app.use(/^\/api\/(.*)/, (req, res) => {
  res.status(404).json({ error: 'API route not found' });
});

// Fallback to login page for other routes
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Admin panel available at /admin route

// Start server
const server = app.listen(PORT, '0.0.0.0', async () => {
  logger.info(`🚀 Secure authentication server started on port ${PORT}`);
  logger.info('🔒 Security features enabled: Rate limiting, CSRF protection, Session management');
  logger.info('📊 Using local SQLite database - no external dependencies');
  
  // Display database statistics
  try {
    const stats = await database.getStats();
    const sessionStats = await security.getSessionStats();
    logger.info(`📈 Database status: ${stats.status} | Users: ${stats.totalUsers} | Type: ${stats.databaseType}`);
    logger.info(`🔐 Active sessions: ${sessionStats.activeSessions} | Total sessions: ${sessionStats.totalSessions}`);
    
    // Database initialized - admin panel available at /admin
    
  } catch (error) {
    logger.error('Error getting server stats', error);
  }
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    database.close();
    process.exit(0);
  });
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully');
  server.close(() => {
    database.close();
    process.exit(0);
  });
});
