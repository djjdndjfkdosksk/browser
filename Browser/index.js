
require('dotenv').config();

const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const multer = require('multer');

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

// Configure multer for file uploads (used in backup restore)
const uploadBackup = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 500 * 1024 * 1024 }
}).single('backup');

// Import client modules
const CrawlerModule = require('./modules/client/crawler');
const ClientDatabase = require('./modules/client/database');
const ClientFileManager = require('./modules/client/fileManager');

const app = express();
const PORT = process.env.PORT || 5000;

// Trust proxy for rate limiting in Replit environment
app.set('trust proxy', 1);

// Security middleware
app.use(helmet());
app.use(security.securityHeaders);
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? process.env.ALLOWED_ORIGINS?.split(',') : true,
  credentials: true
}));

// Rate limiting
const loginLimiter = security.createRateLimit(15 * 60 * 1000, 5); // 5 attempts per 15 minutes
const registerLimiter = security.createRateLimit(60 * 60 * 1000, 3); // 3 registrations per hour
const forgotPasswordLimiter = security.createRateLimit(60 * 60 * 1000, 3); // 3 attempts per hour

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// Add logging middleware
app.use(logger.logRequest.bind(logger));

// Initialize local database
database.init().then(async () => {
  logger.info('دیتابیس محلی آماده است');
  logger.database('دیتابیس SQLite با موفقیت اتصال برقرار کرد');
  
  // Initialize client modules
  global.crawlerModule = new CrawlerModule(database);
  global.clientDatabase = new ClientDatabase();
  global.clientFileManager = new ClientFileManager();
  
  // Initialize client tables
  await global.clientDatabase.initClientTables();
  logger.info('ماژول‌های client آماده شدند');
  
  // Initialize search limit module
  const defaultDailyLimit = Number(process.env.DAILY_SEARCH_LIMIT) || 10;
  global.searchLimit = new SearchLimitModule(database, logger, { defaultDailyLimit });
  await global.searchLimit.init();
  logger.info(`ماژول محدودیت سرچ روزانه آماده شد (محدودیت پیش‌فرض: ${defaultDailyLimit})`);
}).catch((error) => {
  logger.error('خطا در اتصال به دیتابیس', error);
});

// Authentication middleware
const requireAuth = async (req, res, next) => {
  try {
    const sessionId = req.headers['x-session-id'];
    const csrfToken = req.headers['x-csrf-token'];

    if (!sessionId || !csrfToken) {
      logger.security('درخواست بدون احراز هویت', { ip: req.ip, path: req.path });
      return res.status(401).json({ error: 'Authentication required' });
    }

    const session = await security.validateSession(sessionId);
    if (!session) {
      logger.security('جلسه نامعتبر یا منقضی', { sessionId, ip: req.ip });
      return res.status(401).json({ error: 'Invalid or expired session' });
    }

    const isValidCSRF = await security.validateCSRF(csrfToken, sessionId);
    if (!isValidCSRF) {
      logger.security('شکست در اعتبارسنجی CSRF token', { sessionId, ip: req.ip });
      return res.status(403).json({ error: 'CSRF token validation failed' });
    }

    req.user = { id: session.userId };
    req.userId = session.userId;
    next();
  } catch (error) {
    logger.error('خطا در middleware احراز هویت', error, { ip: req.ip });
    return res.status(500).json({ error: 'Authentication error' });
  }
};

// Serve HTML pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/forgot-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'forgot-password.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// API Routes
app.post('/api/register', registerLimiter, async (req, res) => {
  try {
    const { username, password, securityQuestion, securityAnswer } = req.body;
    const result = await registerModule.registerUser(username, password, securityQuestion, securityAnswer);
    
    if (result.success) {
      res.status(201).json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    logger.error('خطا در route ثبت نام', error, { username: req.body.username, ip: req.ip });
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
    logger.error('خطا در route ورود', error, { username: req.body.username, ip: req.ip });
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/logout', async (req, res) => {
  try {
    const sessionId = req.headers['x-session-id'];
    const result = await loginModule.logout(sessionId);
    res.status(200).json(result);
  } catch (error) {
    logger.error('خطا در route خروج', error, { ip: req.ip });
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
    logger.error('خطا در route سوال امنیتی', error, { username: req.params.username, ip: req.ip });
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
    logger.error('خطا در route تأیید پاسخ امنیتی', error, { username: req.body.username, ip: req.ip });
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
    logger.error('خطا در route بازیابی گذرواژه', error, { ip: req.ip });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected route example
app.get('/api/profile', requireAuth, async (req, res) => {
  try {
    const result = await database.query(
      'SELECT id, username, created_at, last_login FROM users WHERE id = ?',
      [req.user.id]
    );
    
    if (result.rows.length > 0) {
      res.json({ success: true, user: result.rows[0] });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    logger.error('خطا در route پروفایل', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ error: 'Internal server error' });
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

// Search endpoint
app.post('/api/search', requireAuth, searchLimitAndCount, async (req, res) => {
  try {
    const { query } = req.body;
    const userId = req.user.id;
    
    if (!query || query.trim().length === 0) {
      return res.status(400).json({ error: 'Query is required' });
    }

    // Validate query format
    const validation = validateSearchQuery(query);
    if (!validation.valid) {
      logger.security('جستجوی نامعتبر', { userId, query: query.substring(0, 50), error: validation.error });
      return res.status(400).json({ 
        success: false,
        error: validation.error
      });
    }

    // Generate requestId: username + timestamp + query (hashed)
    const userResult = await database.query('SELECT username FROM users WHERE id = ?', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const username = userResult.rows[0].username;
    const timestamp = Date.now();
    const crypto = require('crypto');
    const requestId = crypto.createHash('sha256')
                           .update(`${username}_${timestamp}_${query}`)
                           .digest('hex');

    // Store search query in database
    await database.query(
      'INSERT INTO searches (request_id, user_id, query) VALUES (?, ?, ?)',
      [requestId, userId, query]
    );

    // Forward to Search proxy with authentication
    const axios = require('axios');
    try {
      // Generate authentication for internal request
      const authTimestamp = Date.now().toString();
      const requestBody = { q: query, requestId };
      const INTERNAL_SECRET = process.env.INTERNAL_SECRET || 'development-internal-secret-for-mvp-only';
      
      const signature = crypto.createHmac('sha256', INTERNAL_SECRET)
        .update(`${authTimestamp}.${JSON.stringify(requestBody)}`)
        .digest('hex');
      
      const proxyResponse = await axios.post('https://search-zqjl.onrender.com/proxy-search', requestBody, {
        timeout: 30000,
        headers: {
          'Content-Type': 'application/json',
          'x-internal-auth': `${authTimestamp}.${signature}`
        }
      });

      // Store search result first
      await database.query(
        'UPDATE searches SET result = ? WHERE request_id = ?',
        [JSON.stringify(proxyResponse.data.data), requestId]
      );

      // Process search results with auto-crawl
      let processResult = { urlHashes: [], autoCrawl: { selectedUrls: 0, newUrls: 0, alreadyCrawled: 0, startedCrawling: [], skippedCrawling: [] } };
      
      try {
        processResult = await global.crawlerModule.processSearchResultsWithAutoCrawl(
          proxyResponse.data.data, 
          userId
        );

        // Update with URL hashes
        await database.query(
          'UPDATE searches SET result_urls = ? WHERE request_id = ?',
          [JSON.stringify(processResult.urlHashes), requestId]
        );
      } catch (crawlError) {
        logger.error('خطا در پردازش خودکار خزش', crawlError, { userId, requestId });
        // Continue without auto-crawl if it fails
      }

      logger.info('جستجو موفق', { userId, query, requestId, urlCount: processResult.urlHashes.length });

      res.json({
        success: true,
        requestId,
        data: proxyResponse.data.data,
        urlHashes: processResult.urlHashes.length,
        autoCrawl: processResult.autoCrawl
      });

    } catch (proxyError) {
      logger.error('خطا در پروکسی جستجو', proxyError, { userId, query, requestId });
      
      // Update search record with error
      await database.query(
        'UPDATE searches SET result = ? WHERE request_id = ?',
        [JSON.stringify({ error: 'Search service unavailable' }), requestId]
      );
      
      res.status(500).json({ 
        error: 'Search service unavailable',
        requestId,
        details: proxyError.message
      });
    }

  } catch (error) {
    logger.error('خطا در endpoint جستجو', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get search history
app.get('/api/search-history', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const result = await database.query(
      'SELECT request_id, query, created_at FROM searches WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
      [userId]
    );
    
    res.json({ success: true, searches: result.rows });
  } catch (error) {
    logger.error('خطا در تاریخچه جستجو', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ error: 'Failed to get search history' });
  }
});

// Restore search from history
app.get('/api/search/:requestId/restore', requireAuth, async (req, res) => {
  try {
    const { requestId } = req.params;
    const userId = req.user.id;
    
    // Get search data
    const searchResult = await database.query(
      'SELECT * FROM searches WHERE request_id = ? AND user_id = ?',
      [requestId, userId]
    );
    
    if (searchResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Search not found' });
    }
    
    const search = searchResult.rows[0];
    let result = null;
    let urlHashes = [];
    
    try {
      result = JSON.parse(search.result || '{}');
      urlHashes = JSON.parse(search.result_urls || '[]');
    } catch (e) {
      result = {};
      urlHashes = [];
    }
    
    res.json({
      success: true,
      requestId: requestId,
      query: search.query,
      data: result,
      urlHashes: urlHashes,
      searchDate: search.created_at
    });
    
  } catch (error) {
    logger.error('خطا در بازیابی جستجو', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ error: 'Failed to restore search' });
  }
});

// Database info endpoint
app.get('/api/database-info', async (req, res) => {
  try {
    const stats = await database.getStats();
    res.json({ success: true, database: stats });
  } catch (error) {
    logger.error('خطا در اطلاعات دیتابیس', error, { ip: req.ip });
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

    logger.info('درخواست crawl URL', { userId, url });
    
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
    logger.error('خطا در crawl URL', error, { userId: req.user.id, ip: req.ip });
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
    logger.error('خطا در دریافت درخواست‌های client', error, { userId: req.user.id, ip: req.ip });
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
    logger.error('خطا در دریافت نتایج client', error, { requestId: req.params.requestId, ip: req.ip });
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
    logger.error('خطا در دریافت محتوای client', error, { requestId: req.params.requestId, ip: req.ip });
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
    logger.error('خطا در وضعیت خزش', error, { urlHash: req.params.urlHash, ip: req.ip });
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
    logger.error('خطا در خزش‌های انتظار', error, { userId: req.user.id, ip: req.ip });
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
      console.error('خطا در تلاش مجدد:', error);
    });
    
    res.json({
      success: true,
      message: 'Retry started in background',
      retriedCount: urlsToRetry.length
    });
    
  } catch (error) {
    logger.error('خطا در تلاش مجدد', error, { userId: req.user.id, ip: req.ip });
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
    logger.error('خطا در آمار client', error, { userId: req.user.id, ip: req.ip });
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
    logger.error('خطا در دریافت دامنه‌های ممنوع', error, { userId: req.user.id, ip: req.ip });
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
      logger.info('دامنه جدید به لیست ممنوع اضافه شد', { domain, userId: req.user.id });
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
    logger.error('خطا در اضافه کردن دامنه ممنوع', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ error: 'Failed to add blocked domain' });
  }
});

// Remove blocked domain
app.delete('/api/blocked-domains/:domain', requireAuth, async (req, res) => {
  try {
    const { domain } = req.params;
    const removed = global.crawlerModule.domainFilter.removeBlockedDomain(domain);
    
    if (removed) {
      logger.info('دامنه از لیست ممنوع حذف شد', { domain, userId: req.user.id });
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
    logger.error('خطا در حذف دامنه ممنوع', error, { userId: req.user.id, ip: req.ip });
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
    logger.error('خطا در تست فیلتر دامنه', error, { userId: req.user.id, ip: req.ip });
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

    // بررسی session معتبر ادمین
    const session = await security.validateSession(sessionId);
    if (!session || session.userId !== 1) { // فرض بر این که کاربر با ID 1 ادمین است
      return res.status(401).json({ success: false, error: 'Invalid admin session' });
    }

    req.adminUserId = session.userId;
    next();
  } catch (error) {
    logger.error('خطا در middleware احراز هویت ادمین', error);
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
      logger.security('تلاش ورود نامعتبر به پنل ادمین', { ip: req.ip });
      return res.status(401).json({ success: false, error: 'Invalid admin password' });
    }

    // ایجاد session برای ادمین (فرض بر این که کاربر با ID 1 ادمین است)
    const session = await security.createSession(1, req.ip, req.get('User-Agent'));
    
    logger.security('ورود موفق ادمین', { ip: req.ip, sessionId: session.sessionId });
    
    res.json({
      success: true,
      token: session.sessionId,
      message: 'Admin login successful'
    });

  } catch (error) {
    logger.error('خطا در ورود ادمین', error);
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
    logger.error('خطا در دریافت آمار ادمین', error);
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
    logger.error('خطا در دریافت لیست کاربران', error);
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
    logger.error('خطا در دریافت اطلاعات سیستم', error);
    res.status(500).json({ success: false, error: 'Failed to get system info' });
  }
});

// Cleanup expired sessions
app.post('/api/admin/cleanup-sessions', requireAdminAuth, async (req, res) => {
  try {
    const result = await adminModule.cleanupExpiredSessions();
    logger.info('پاک سازی جلسات توسط ادمین', { cleaned: result.cleaned });
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    logger.error('خطا در پاک سازی جلسات', error);
    res.status(500).json({ success: false, error: 'Failed to cleanup sessions' });
  }
});

// Optimize database
app.post('/api/admin/optimize-database', requireAdminAuth, async (req, res) => {
  try {
    const result = await adminModule.optimizeDatabase();
    logger.info('بهینه سازی دیتابیس توسط ادمین');
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    logger.error('خطا در بهینه سازی دیتابیس', error);
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
    logger.error('خطا در دریافت آمار دانلود', error);
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
      logger.security('تلاش دانلود دایرکتوری غیرمجاز', { directory, userId: req.adminUserId });
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
    
    logger.security('توکن دانلود ایجاد شد', { directory, userId: req.adminUserId });
    
    res.json({
      success: true,
      token: tokenData.token,
      expiresIn: 300 // 5 minutes
    });
  } catch (error) {
    logger.error('خطا در ایجاد توکن دانلود', error);
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
      logger.security('تلاش دانلود با توکن نامعتبر', { token });
      return res.status(401).json({ success: false, error: 'Invalid or expired token' });
    }
    
    logger.security('شروع دانلود دایرکتوری', { 
      directory: tokenData.dirName, 
      userId: tokenData.userId 
    });
    
    // Create and stream zip file
    await adminDownloadModule.createZipArchive(tokenData.dirName, res);
    
    // Remove token after successful download
    global.downloadTokens.delete(token);
    
  } catch (error) {
    logger.error('خطا در دانلود فایل', error);
    if (!res.headersSent) {
      res.status(500).json({ success: false, error: 'Download failed' });
    }
  }
});

// Preview uploaded backup zip contents
app.post('/api/admin/preview-backup', requireAdminAuth, (req, res) => {
  uploadBackup(req, res, async (err) => {
    if (err) {
      logger.error('خطا در آپلود فایل', err);
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
      logger.error('خطا در پیش‌نمایش بک‌آپ', error);
      res.status(500).json({ success: false, error: 'Failed to preview backup' });
    }
  });
});

// Restore backup from uploaded zip
app.post('/api/admin/restore-backup', requireAdminAuth, (req, res) => {
  uploadBackup(req, res, async (err) => {
    if (err) {
      logger.error('خطا در آپلود فایل بازیابی', err);
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
      
      logger.security('بازیابی بک‌آپ موفق', { 
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
      logger.error('خطا در بازیابی بک‌آپ', error);
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
    logger.error('خطا در دریافت فایل‌های محتوا', error, { userId: req.user.id, ip: req.ip });
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get pending files for processing
app.get('/api/content/pending', requireAuth, async (req, res) => {
  try {
    const pendingFiles = await global.clientDatabase.getPendingSummaryFiles();
    res.json({ success: true, files: pendingFiles });
  } catch (error) {
    logger.error('خطا در دریافت فایل‌های در انتظار', error, { userId: req.user.id, ip: req.ip });
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
    logger.error('خطا در دریافت خلاصه‌های جستجو', error, { userId: req.user.id, ip: req.ip });
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
    logger.info(`🚀 [${urlHash}] ارسال فایل برای پردازش...`, { userId: req.user.id });
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
    logger.error('خطا در ارسال فایل', error, { userId: req.user.id, ip: req.ip });
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
    
    logger.info(`📦 ارسال ${pendingFiles.length} فایل در انتظار...`, { userId: req.user.id });
    
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
          
          console.log(`✅ پردازش شد: ${file.url_hash}`);
        } else {
          results.push({
            urlHash: file.url_hash,
            success: false,
            error: response.data.error
          });
          console.error(`❌ پردازش ناموفق: ${file.url_hash} - ${response.data.error}`);
        }

      } catch (error) {
        results.push({
          urlHash: file.url_hash,
          success: false,
          error: error.message
        });
        console.error(`❌ خطا در ارسال ${file.url_hash}:`, error.message);
      }
    }
    
    const successCount = results.filter(r => r.success).length;
    
    res.json({ 
      success: true, 
      message: `پردازش شد ${successCount}/${results.length} فایل`,
      results,
      summary: {
        total: results.length,
        processed: successCount,
        failed: results.length - successCount
      }
    });

  } catch (error) {
    logger.error('خطا در ارسال دسته‌ای', error, { userId: req.user.id, ip: req.ip });
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
    logger.error('خطا در دریافت خلاصه', error, { userId: req.user.id, ip: req.ip });
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

    logger.info(`📥 [${fileId}] دریافت خلاصه از agent (verified)`, { ip: req.ip });
    logger.info(`📝 [${fileId}] طول خلاصه: ${summary.length} کاراکتر`);
    
    // Save summary to database
    await global.clientDatabase.saveSummary(fileId, summary);
    await global.clientDatabase.markFileAsSummarized(fileId);
    
    // Log metadata if provided
    if (metadata) {
      logger.info(`📊 [${fileId}] متادیتا:`, {
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
    logger.error(`❌ خطا در ذخیره خلاصه:`, error);
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
    logger.error('خطا در وضعیت سیستم محتوا', error, { userId: req.user.id, ip: req.ip });
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
    logger.error('خطا در اتصال به agent', error, { userId: req.user.id, ip: req.ip });
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
    logger.error('خطا در وضعیت صف agent', error, { userId: req.user.id, ip: req.ip });
    res.status(503).json({ 
      success: false, 
      error: 'Agent server is not available',
      details: error.message
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('خطای مدیریت نشده', err, { ip: req.ip, path: req.path });
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler for API routes only
app.use(/^\/api\/.*/, (req, res) => {
  res.status(404).json({ error: 'API route not found' });
});

// Fallback to login page for other routes
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Admin panel available at /admin route

// Start server
const server = app.listen(PORT, '0.0.0.0', async () => {
  logger.info(`🚀 سرور احراز هویت امن روی پورت ${PORT} آغاز شد`);
  logger.info('🔒 قابلیت‌های امنیتی فعال: Rate limiting, CSRF protection, Session management');
  logger.info('📊 استفاده از دیتابیس SQLite محلی - بدون وابستگی خارجی');
  
  // Display database statistics
  try {
    const stats = await database.getStats();
    const sessionStats = await security.getSessionStats();
    logger.info(`📈 وضعیت دیتابیس: ${stats.status} | کاربران: ${stats.totalUsers} | نوع: ${stats.databaseType}`);
    logger.info(`🔐 جلسات فعال: ${sessionStats.activeSessions} | کل جلسات: ${sessionStats.totalSessions}`);
    
    // Database initialized - admin panel available at /admin
    
  } catch (error) {
    logger.error('خطا در دریافت آمار سرور', error);
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
