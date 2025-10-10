
class SearchLimitModule {
  constructor(database, logger, options = {}) {
    this.database = database;
    this.logger = logger;
    this.defaultDailyLimit = options.defaultDailyLimit || 10;
  }

  async init() {
    try {
      await this.database.query(`
        CREATE TABLE IF NOT EXISTS user_daily_usage (
          user_id INTEGER NOT NULL,
          date TEXT NOT NULL,
          search_count INTEGER DEFAULT 0,
          PRIMARY KEY (user_id, date),
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `);

      await this.database.query(`
        CREATE INDEX IF NOT EXISTS idx_user_daily_usage_user_date 
        ON user_daily_usage(user_id, date)
      `);

      await this.database.query(`
        CREATE TABLE IF NOT EXISTS user_limits (
          user_id INTEGER PRIMARY KEY,
          daily_limit INTEGER NOT NULL,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `);

      const cleanupDays = 60;
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - cleanupDays);
      const cutoffDateStr = cutoffDate.toISOString().split('T')[0];
      
      await this.database.query(`
        DELETE FROM user_daily_usage WHERE date < ?
      `, [cutoffDateStr]);

      this.logger.info('ماژول محدودیت سرچ روزانه آماده شد');
    } catch (error) {
      this.logger.error('خطا در راه‌اندازی ماژول محدودیت سرچ', error);
      throw error;
    }
  }

  getTodayDateString() {
    return new Date().toISOString().split('T')[0];
  }

  async getEffectiveLimit(userId) {
    try {
      const result = await this.database.query(
        `SELECT daily_limit FROM user_limits WHERE user_id = ?`,
        [userId]
      );
      
      if (result && result.rows && result.rows.length > 0) {
        return result.rows[0].daily_limit;
      }
      
      return this.defaultDailyLimit;
    } catch (error) {
      this.logger.error('خطا در دریافت محدودیت کاربر', error);
      return this.defaultDailyLimit;
    }
  }

  async incrementIfAllowed(userId) {
    try {
      const today = this.getTodayDateString();
      const limit = await this.getEffectiveLimit(userId);

      if (limit <= 0) {
        return {
          allowed: false,
          currentCount: 0,
          limit: limit
        };
      }

      const updateResult = await this.database.query(`
        UPDATE user_daily_usage 
        SET search_count = search_count + 1 
        WHERE user_id = ? AND date = ? AND search_count < ?
      `, [userId, today, limit]);

      if (updateResult.changes === 1) {
        const result = await this.database.query(
          `SELECT search_count FROM user_daily_usage WHERE user_id = ? AND date = ?`,
          [userId, today]
        );
        const newCount = result && result.rows && result.rows.length > 0 
          ? result.rows[0].search_count 
          : 1;
        
        return {
          allowed: true,
          currentCount: newCount,
          limit: limit
        };
      }

      const insertResult = await this.database.query(`
        INSERT OR IGNORE INTO user_daily_usage (user_id, date, search_count)
        VALUES (?, ?, 1)
      `, [userId, today]);

      if (insertResult.changes === 1) {
        return {
          allowed: true,
          currentCount: 1,
          limit: limit
        };
      }

      const retryUpdateResult = await this.database.query(`
        UPDATE user_daily_usage 
        SET search_count = search_count + 1 
        WHERE user_id = ? AND date = ? AND search_count < ?
      `, [userId, today, limit]);

      if (retryUpdateResult.changes === 1) {
        const result = await this.database.query(
          `SELECT search_count FROM user_daily_usage WHERE user_id = ? AND date = ?`,
          [userId, today]
        );
        const newCount = result && result.rows && result.rows.length > 0 
          ? result.rows[0].search_count 
          : 1;
        
        return {
          allowed: true,
          currentCount: newCount,
          limit: limit
        };
      }

      const currentResult = await this.database.query(
        `SELECT search_count FROM user_daily_usage WHERE user_id = ? AND date = ?`,
        [userId, today]
      );

      const currentCount = currentResult && currentResult.rows && currentResult.rows.length > 0 
        ? currentResult.rows[0].search_count 
        : limit;

      return {
        allowed: false,
        currentCount: currentCount,
        limit: limit
      };
    } catch (error) {
      this.logger.error('خطا در بررسی و افزایش محدودیت سرچ', error);
      return { allowed: false, currentCount: 0, limit: this.defaultDailyLimit };
    }
  }

  async isOverLimit(userId) {
    try {
      const today = this.getTodayDateString();
      const limit = await this.getEffectiveLimit(userId);

      const result = await this.database.query(
        `SELECT search_count FROM user_daily_usage WHERE user_id = ? AND date = ?`,
        [userId, today]
      );

      const currentCount = result && result.rows && result.rows.length > 0 
        ? result.rows[0].search_count 
        : 0;
      
      return {
        isOver: currentCount >= limit,
        currentCount: currentCount,
        limit: limit
      };
    } catch (error) {
      this.logger.error('خطا در بررسی محدودیت سرچ', error);
      return { isOver: false, currentCount: 0, limit: this.defaultDailyLimit };
    }
  }

  async setUserLimit(userId, limit) {
    try {
      if (limit === null || limit === undefined) {
        await this.database.query(
          `DELETE FROM user_limits WHERE user_id = ?`,
          [userId]
        );
        this.logger.info(`محدودیت شخصی کاربر ${userId} حذف شد`);
      } else {
        await this.database.query(`
          INSERT INTO user_limits (user_id, daily_limit, updated_at)
          VALUES (?, ?, CURRENT_TIMESTAMP)
          ON CONFLICT(user_id) DO UPDATE SET
            daily_limit = ?,
            updated_at = CURRENT_TIMESTAMP
        `, [userId, limit, limit]);
        this.logger.info(`محدودیت روزانه کاربر ${userId} به ${limit} تغییر یافت`);
      }
      return true;
    } catch (error) {
      this.logger.error('خطا در تنظیم محدودیت شخصی کاربر', error);
      return false;
    }
  }

  enforceDailyLimitAndCount = async (req, res, next) => {
    try {
      const userId = req.userId;
      
      if (!userId) {
        return res.status(401).json({ 
          success: false,
          error: 'Authentication required' 
        });
      }

      const result = await this.incrementIfAllowed(userId);

      if (!result.allowed) {
        this.logger.security('محدودیت سرچ روزانه', { 
          userId, 
          currentCount: result.currentCount,
          limit: result.limit,
          ip: req.ip 
        });
        
        return res.status(429).json({
          success: false,
          error: 'محدودیت سرچ روزانه به پایان رسید. لطفاً فردا دوباره تلاش کنید.',
          errorEn: 'Daily search limit reached. Please try again tomorrow.',
          currentCount: result.currentCount,
          limit: result.limit
        });
      }

      next();
    } catch (error) {
      this.logger.error('خطا در middleware محدودیت سرچ', error);
      return res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  };

  enforceDailyLimit = async (req, res, next) => {
    try {
      const userId = req.userId;
      
      if (!userId) {
        return res.status(401).json({ 
          success: false,
          error: 'Authentication required' 
        });
      }

      const result = await this.isOverLimit(userId);

      if (result.isOver) {
        this.logger.security('تلاش برای دسترسی به summaries با محدودیت سرچ تمام شده', { 
          userId, 
          currentCount: result.currentCount,
          limit: result.limit,
          ip: req.ip 
        });
        
        return res.status(429).json({
          success: false,
          error: 'محدودیت سرچ روزانه به پایان رسید. لطفاً فردا دوباره تلاش کنید.',
          errorEn: 'Daily search limit reached. Please try again tomorrow.',
          currentCount: result.currentCount,
          limit: result.limit
        });
      }

      next();
    } catch (error) {
      this.logger.error('خطا در middleware بررسی محدودیت', error);
      return res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  };
}

module.exports = SearchLimitModule;
