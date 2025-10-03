
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const database = require('../database');
const logger = require('./logger');

class SecurityModule {
  constructor() {
    // Get SESSION_SECRET from environment - REQUIRED for security
    this.sessionSecret = process.env.SESSION_SECRET;
    if (!this.sessionSecret) {
      logger.error('SESSION_SECRET is required but not found in environment');
      process.exit(1); // Exit process if no SESSION_SECRET in production
    }
    
    // Initialize cleanup interval (run every 5 minutes)
    this.startSessionCleanup();
  }

  // Rate limiting middleware
  createRateLimit(windowMs = 15 * 60 * 1000, max = 5) {
    return rateLimit({
      windowMs,
      max,
      message: { error: 'Too many attempts, please try again later.' },
      standardHeaders: true,
      legacyHeaders: false,
    });
  }

  // Generate secure session token using SESSION_SECRET
  generateSessionToken() {
    const timestamp = Date.now().toString();
    const randomBytes = crypto.randomBytes(32).toString('hex');
    const hash = crypto.createHmac('sha256', this.sessionSecret)
                      .update(timestamp + randomBytes)
                      .digest('hex');
    return hash;
  }

  // Generate CSRF token
  generateCSRFToken() {
    return crypto.randomBytes(32).toString('hex');
  }

  // Encrypt sensitive data using AES-256-GCM with proper IV handling
  encryptData(data) {
    try {
      const algorithm = 'aes-256-gcm';
      const salt = crypto.randomBytes(32); // Random salt per encryption
      const key = crypto.scryptSync(this.sessionSecret, salt, 32);
      const iv = crypto.randomBytes(12); // 12 bytes for GCM
      
      const cipher = crypto.createCipheriv(algorithm, key, iv);
      
      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      const authTag = cipher.getAuthTag();
      
      return {
        encrypted,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        salt: salt.toString('hex')
      };
    } catch (error) {
      logger.error('خطا در رمزنگاری داده', error);
      throw error;
    }
  }

  // Decrypt sensitive data using stored salt and IV
  decryptData(encryptedData, ivHex, authTagHex, saltHex) {
    try {
      const algorithm = 'aes-256-gcm';
      const salt = Buffer.from(saltHex, 'hex');
      const key = crypto.scryptSync(this.sessionSecret, salt, 32);
      const iv = Buffer.from(ivHex, 'hex');
      
      const decipher = crypto.createDecipheriv(algorithm, key, iv);
      decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
      
      let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      logger.error('خطا در رمزگشایی داده', error);
      return null;
    }
  }

  // Create session in database
  async createSession(userId, ipAddress = null, userAgent = null) {
    try {
      const sessionId = this.generateSessionToken();
      const csrfToken = this.generateCSRFToken();
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
      
      await database.query(`
        INSERT INTO sessions (session_id, user_id, csrf_token, expires_at, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?, ?)
      `, [sessionId, userId, csrfToken, expiresAt.toISOString(), ipAddress, userAgent]);
      
      logger.auth('جلسه جدید ایجاد شد', { userId, sessionId, ipAddress });
      
      return { sessionId, csrfToken };
    } catch (error) {
      logger.error('خطا در ایجاد جلسه', error, { userId });
      throw error;
    }
  }

  // Validate session from database
  async validateSession(sessionId) {
    try {
      const result = await database.query(`
        SELECT session_id, user_id, csrf_token, created_at, last_activity, expires_at, is_active
        FROM sessions
        WHERE session_id = ? AND is_active = 1
      `, [sessionId]);
      
      if (result.rows.length === 0) {
        return false;
      }
      
      const session = result.rows[0];
      const now = new Date();
      const expiresAt = new Date(session.expires_at);
      const lastActivity = new Date(session.last_activity);
      
      // Check if session expired
      if (now > expiresAt) {
        await this.destroySession(sessionId);
        logger.security('جلسه منقضی شده حذف گردید', { sessionId });
        return false;
      }
      
      // Check for inactivity timeout (30 minutes)
      const inactivityTimeout = 30 * 60 * 1000; // 30 minutes
      if (now - lastActivity > inactivityTimeout) {
        await this.destroySession(sessionId);
        logger.security('جلسه غیرفعال حذف گردید', { sessionId });
        return false;
      }
      
      // Update last activity
      await database.query(`
        UPDATE sessions SET last_activity = CURRENT_TIMESTAMP
        WHERE session_id = ?
      `, [sessionId]);
      
      return {
        userId: session.user_id,
        sessionId: session.session_id,
        csrfToken: session.csrf_token,
        createdAt: new Date(session.created_at).getTime(),
        lastActivity: now.getTime()
      };
    } catch (error) {
      logger.error('خطا در اعتبارسنجی جلسه', error, { sessionId });
      return false;
    }
  }

  // Validate CSRF token from database
  async validateCSRF(csrfToken, sessionId) {
    try {
      const result = await database.query(`
        SELECT csrf_token FROM sessions
        WHERE session_id = ? AND csrf_token = ? AND is_active = 1
      `, [sessionId, csrfToken]);
      
      return result.rows.length > 0;
    } catch (error) {
      logger.error('خطا در اعتبارسنجی CSRF توکن', error, { sessionId });
      return false;
    }
  }

  // Destroy session from database
  async destroySession(sessionId) {
    try {
      await database.query(`
        UPDATE sessions SET is_active = 0
        WHERE session_id = ?
      `, [sessionId]);
      
      logger.auth('جلسه با موفقیت حذف شد', { sessionId });
      return true;
    } catch (error) {
      logger.error('خطا در حذف جلسه', error, { sessionId });
      return false;
    }
  }

  // Destroy all sessions for a specific user
  async destroySessionsByUser(userId) {
    try {
      const result = await database.query(`
        UPDATE sessions SET is_active = 0
        WHERE user_id = ? AND is_active = 1
      `, [userId]);
      
      logger.auth(`تمام جلسات کاربر حذف شد`, { userId, count: result.changes });
      return result.changes;
    } catch (error) {
      logger.error('خطا در حذف جلسات کاربر', error, { userId });
      return 0;
    }
  }

  // Enhanced input sanitization  
  sanitizeInput(input, options = {}) {
    if (typeof input !== 'string') {
      logger.warn('ورودی غیر رشته‌ای برای پاکسازی', { inputType: typeof input });
      return '';
    }
    
    let sanitized = input.trim();
    
    // Remove dangerous HTML/script tags
    sanitized = sanitized.replace(/<script[^>]*>.*?<\/script>/gi, '');
    sanitized = sanitized.replace(/<iframe[^>]*>.*?<\/iframe>/gi, '');
    sanitized = sanitized.replace(/<object[^>]*>.*?<\/object>/gi, '');
    sanitized = sanitized.replace(/<embed[^>]*>/gi, '');
    
    // Escape HTML characters
    sanitized = sanitized.replace(/[<>"'&]/g, (match) => {
      const entities = {
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '&': '&amp;'
      };
      return entities[match];
    });
    
    // SQL injection protection
    const sqlPatterns = [
      /('|(--)|(\|)|(\*)|(\%))|(;)/i,
      /(union|select|insert|delete|update|drop|create|alter|exec|execute)/i
    ];
    
    for (const pattern of sqlPatterns) {
      if (pattern.test(sanitized)) {
        logger.security('تلاش بالقوه SQL Injection شناسایی شد', { input: sanitized.substring(0, 50) });
        return '';
      }
    }
    
    // Convert to lowercase if specified
    if (options.lowercase !== false) {
      sanitized = sanitized.toLowerCase();
    }
    
    // Maximum length check
    const maxLength = options.maxLength || 1000;
    if (sanitized.length > maxLength) {
      logger.warn(`ورودی طولانی کوتاه شد: ${sanitized.length} -> ${maxLength}`);
      sanitized = sanitized.substring(0, maxLength);
    }
    
    return sanitized;
  }

  // Password strength validation
  validatePasswordStrength(password) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    return password.length >= minLength && hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChar;
  }

  // Advanced validation methods
  validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 254;
  }
  
  validateUsername(username) {
    const usernameRegex = /^[a-zA-Z0-9_-]{3,30}$/;
    return usernameRegex.test(username);
  }
  
  validateInput(input, type, options = {}) {
    if (!input) {
      return { isValid: false, error: 'ورودی ضروری است' };
    }
    
    const sanitized = this.sanitizeInput(input, options);
    
    switch (type) {
      case 'username':
        if (!this.validateUsername(sanitized)) {
          return { isValid: false, error: 'نام کاربری باید بین 3 تا 30 کاراکتر و فقط شامل حروف و اعداد باشد' };
        }
        break;
      case 'email':
        if (!this.validateEmail(sanitized)) {
          return { isValid: false, error: 'فرمت ایمیل نامعتبر است' };
        }
        break;
      case 'password':
        if (!this.validatePasswordStrength(input)) { // Don't sanitize password
          return { isValid: false, error: 'گذرواژه باید حداقل 8 کاراکتر با ترکیبی از حروف بزرگ، کوچک، اعداد و علائم خاص باشد' };
        }
        return { isValid: true, value: input }; // Return original password
      default:
        break;
    }
    
    return { isValid: true, value: sanitized };
  }

  // Session cleanup - runs automatically
  startSessionCleanup() {
    // Run cleanup every 5 minutes
    setInterval(async () => {
      await this.cleanupExpiredSessions();
    }, 5 * 60 * 1000);
    
    // Initial cleanup
    setTimeout(() => {
      this.cleanupExpiredSessions();
    }, 10000); // Wait 10 seconds after startup
  }
  
  async cleanupExpiredSessions() {
    try {
      const result = await database.query(`
        UPDATE sessions SET is_active = 0
        WHERE (expires_at < CURRENT_TIMESTAMP OR 
               datetime(last_activity, '+30 minutes') < CURRENT_TIMESTAMP)
        AND is_active = 1
      `);
      
      if (result.changes > 0) {
        logger.info(`پاکسازی جلسات: ${result.changes} جلسه منقضی حذف شد`);
      }
      
      // Delete old inactive sessions (older than 7 days)
      const deleteResult = await database.query(`
        DELETE FROM sessions
        WHERE datetime(created_at, '+7 days') < CURRENT_TIMESTAMP
        AND is_active = 0
      `);
      
      if (deleteResult.changes > 0) {
        logger.info(`حذف جلسات قدیمی: ${deleteResult.changes} جلسه حذف شد`);
      }
    } catch (error) {
      logger.error('خطا در پاکسازی جلسات', error);
    }
  }
  
  // Get session statistics
  async getSessionStats() {
    try {
      const activeResult = await database.query(`
        SELECT COUNT(*) as count FROM sessions WHERE is_active = 1
      `);
      
      const totalResult = await database.query(`
        SELECT COUNT(*) as count FROM sessions
      `);
      
      return {
        activeSessions: activeResult.rows[0].count,
        totalSessions: totalResult.rows[0].count
      };
    } catch (error) {
      logger.error('خطا در دریافت آمار جلسات', error);
      return { activeSessions: 0, totalSessions: 0 };
    }
  }

  // Security headers middleware
  securityHeaders(req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
  }
}

module.exports = new SecurityModule();
