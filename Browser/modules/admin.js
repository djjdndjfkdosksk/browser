
const bcrypt = require('bcrypt');
const database = require('../database');
const logger = require('./logger');

class AdminModule {
  constructor() {
    this.adminPasswordHash = process.env.ADMIN_PASSWORD_HASH;
    if (!this.adminPasswordHash) {
      logger.error('ADMIN_PASSWORD_HASH not configured in environment variables');
      throw new Error('Admin password hash is required');
    }
  }

  // تأیید رمز عبور ادمین
  async verifyAdminPassword(password) {
    try {
      return await bcrypt.compare(password, this.adminPasswordHash);
    } catch (error) {
      logger.error('خطا در تأیید رمز عبور ادمین', error);
      return false;
    }
  }

  // دریافت آمار کامل دیتابیس
  async getDatabaseStats() {
    try {
      // آمار کاربران
      const userStats = await database.query(`
        SELECT 
          COUNT(*) as total_users,
          SUM(CASE WHEN last_login IS NOT NULL THEN 1 ELSE 0 END) as active_users,
          SUM(CASE WHEN datetime(created_at, '+7 days') > datetime('now') THEN 1 ELSE 0 END) as new_users_week
        FROM users
      `);

      // آمار جلسات
      const sessionStats = await database.query(`
        SELECT 
          COUNT(*) as total_sessions,
          SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_sessions,
          SUM(CASE WHEN datetime(created_at, '+1 day') > datetime('now') THEN 1 ELSE 0 END) as sessions_today
        FROM sessions
      `);

      // آمار URL ها
      const urlStats = await database.query(`
        SELECT 
          COUNT(*) as total_urls,
          SUM(CASE WHEN crawl_status = 'completed' THEN 1 ELSE 0 END) as crawled_urls,
          SUM(CASE WHEN crawl_status = 'pending' THEN 1 ELSE 0 END) as pending_urls,
          SUM(CASE WHEN crawl_status = 'failed' THEN 1 ELSE 0 END) as failed_urls,
          SUM(CASE WHEN crawl_status = 'crawling' THEN 1 ELSE 0 END) as crawling_urls
        FROM url_hashes
      `);

      // آمار جستجوها
      const searchStats = await database.query(`
        SELECT 
          COUNT(*) as total_searches,
          SUM(CASE WHEN datetime(created_at, '+1 day') > datetime('now') THEN 1 ELSE 0 END) as searches_today,
          SUM(CASE WHEN datetime(created_at, '+7 days') > datetime('now') THEN 1 ELSE 0 END) as searches_week
        FROM searches
      `);

      // آمار محتوا و خلاصه‌ها
      const contentStats = await database.query(`
        SELECT 
          COUNT(*) as total_requests,
          SUM(total_blocks) as total_blocks,
          SUM(total_words) as total_words,
          AVG(processing_time) as avg_processing_time
        FROM user_crawl_requests
      `);

      // آمار خلاصه‌ها
      const summaryStats = await database.query(`
        SELECT 
          COUNT(*) as total_summaries,
          SUM(CASE WHEN summary_text IS NOT NULL THEN 1 ELSE 0 END) as completed_summaries,
          SUM(CASE WHEN summary_text IS NULL THEN 1 ELSE 0 END) as pending_summaries,
          AVG(LENGTH(summary_text)) as avg_summary_length
        FROM summaries
      `);

      // آمار استفاده روزانه - استفاده از جدول searches برای محاسبه
      const usageStats = await database.query(`
        SELECT 
          COUNT(DISTINCT user_id) as active_users_today,
          COUNT(*) as total_searches_used,
          CAST(COUNT(*) AS FLOAT) / NULLIF(COUNT(DISTINCT user_id), 0) as avg_searches_per_user
        FROM searches 
        WHERE date(created_at) = date('now')
      `);

      // حجم دیتابیس
      const dbSize = await database.query(`
        SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()
      `);

      return {
        timestamp: new Date().toISOString(),
        users: userStats.rows[0],
        sessions: sessionStats.rows[0],
        urls: urlStats.rows[0],
        searches: searchStats.rows[0],
        content: contentStats.rows[0],
        summaries: summaryStats.rows[0],
        usage: usageStats.rows[0],
        database: {
          size: dbSize.rows[0]?.size || 0,
          sizeFormatted: this.formatBytes(dbSize.rows[0]?.size || 0)
        }
      };
    } catch (error) {
      logger.error('خطا در دریافت آمار دیتابیس', error);
      throw error;
    }
  }

  // دریافت لیست کاربران با جزئیات
  async getUsersList() {
    try {
      const users = await database.query(`
        SELECT 
          u.id,
          u.username,
          u.created_at,
          u.last_login,
          u.failed_attempts,
          u.locked_until,
          COUNT(DISTINCT s.session_id) as total_sessions,
          COUNT(DISTINCT sr.id) as total_searches,
          0 as searches_today
        FROM users u
        LEFT JOIN sessions s ON u.id = s.user_id
        LEFT JOIN searches sr ON u.id = sr.user_id
        GROUP BY u.id
        ORDER BY u.created_at DESC
      `);

      return users.rows;
    } catch (error) {
      logger.error('خطا در دریافت لیست کاربران', error);
      throw error;
    }
  }

  // دریافت جزئیات سیستم
  async getSystemInfo() {
    try {
      const memoryUsage = process.memoryUsage();
      const uptime = process.uptime();
      
      return {
        nodeVersion: process.version,
        platform: process.platform,
        architecture: process.arch,
        uptime: {
          seconds: uptime,
          formatted: this.formatUptime(uptime)
        },
        memory: {
          rss: memoryUsage.rss,
          heapTotal: memoryUsage.heapTotal,
          heapUsed: memoryUsage.heapUsed,
          external: memoryUsage.external,
          formatted: {
            rss: this.formatBytes(memoryUsage.rss),
            heapTotal: this.formatBytes(memoryUsage.heapTotal),
            heapUsed: this.formatBytes(memoryUsage.heapUsed),
            external: this.formatBytes(memoryUsage.external)
          }
        }
      };
    } catch (error) {
      logger.error('خطا در دریافت اطلاعات سیستم', error);
      throw error;
    }
  }

  // فرمت کردن بایت ها
  formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  // فرمت کردن زمان فعالیت
  formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    
    return `${days}d ${hours}h ${minutes}m ${secs}s`;
  }

  // پاک سازی جلسات منقضی شده
  async cleanupExpiredSessions() {
    try {
      const result = await database.query(`
        UPDATE sessions SET is_active = 0
        WHERE (expires_at < CURRENT_TIMESTAMP OR 
               datetime(last_activity, '+30 minutes') < CURRENT_TIMESTAMP)
        AND is_active = 1
      `);

      return { cleaned: result.changes };
    } catch (error) {
      logger.error('خطا در پاک سازی جلسات', error);
      throw error;
    }
  }

  // بهینه سازی دیتابیس
  async optimizeDatabase() {
    try {
      await database.query('VACUUM');
      await database.query('ANALYZE');
      
      logger.info('دیتابیس بهینه سازی شد');
      return { success: true, message: 'Database optimized successfully' };
    } catch (error) {
      logger.error('خطا در بهینه سازی دیتابیس', error);
      throw error;
    }
  }
}

module.exports = new AdminModule();
