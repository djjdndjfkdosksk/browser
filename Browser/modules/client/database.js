
const database = require('../../database');

class ClientDatabase {
  constructor() {
    this.database = database;
  }

  // Initialize client-specific tables
  async initClientTables() {
    try {
      // Create url_hashes table
      await this.database.query(`
        CREATE TABLE IF NOT EXISTS url_hashes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          url_hash VARCHAR(64) UNIQUE NOT NULL,
          original_url TEXT NOT NULL,
          first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
          last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
          access_count INTEGER DEFAULT 1,
          crawl_status VARCHAR(20) DEFAULT 'pending',
          crawl_completed_at DATETIME NULL,
          crawl_attempts INTEGER DEFAULT 0
        )
      `);

      // Add missing columns if they don't exist
      try {
        await this.database.query(`
          ALTER TABLE url_hashes ADD COLUMN crawl_status VARCHAR(20) DEFAULT 'pending'
        `);
      } catch (e) {
        // Column already exists
      }

      try {
        await this.database.query(`
          ALTER TABLE url_hashes ADD COLUMN crawl_completed_at DATETIME NULL
        `);
      } catch (e) {
        // Column already exists
      }

      try {
        await this.database.query(`
          ALTER TABLE url_hashes ADD COLUMN crawl_attempts INTEGER DEFAULT 0
        `);
      } catch (e) {
        // Column already exists
      }

      // Add new summary tracking columns
      try {
        await this.database.query(`
          ALTER TABLE url_hashes ADD COLUMN json_file_path TEXT
        `);
      } catch (e) {
        // Column already exists
      }

      try {
        await this.database.query(`
          ALTER TABLE url_hashes ADD COLUMN total_words INTEGER
        `);
      } catch (e) {
        // Column already exists
      }

      try {
        await this.database.query(`
          ALTER TABLE url_hashes ADD COLUMN main_content_words INTEGER
        `);
      } catch (e) {
        // Column already exists
      }

      try {
        await this.database.query(`
          ALTER TABLE url_hashes ADD COLUMN summary_status VARCHAR(20) DEFAULT 'pending'
        `);
      } catch (e) {
        // Column already exists
      }

      try {
        await this.database.query(`
          ALTER TABLE url_hashes ADD COLUMN summary_completed_at DATETIME NULL
        `);
      } catch (e) {
        // Column already exists
      }

      try {
        await this.database.query(`
          ALTER TABLE url_hashes ADD COLUMN summary_attempts INTEGER DEFAULT 0
        `);
      } catch (e) {
        // Column already exists
      }

      // Create user_crawl_requests table
      await this.database.query(`
        CREATE TABLE IF NOT EXISTS user_crawl_requests (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          request_id VARCHAR(64) UNIQUE NOT NULL,
          user_id INTEGER NOT NULL,
          url_hash VARCHAR(64) NOT NULL,
          json_file_path TEXT,
          processing_time REAL,
          total_blocks INTEGER DEFAULT 0,
          total_words INTEGER DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id),
          FOREIGN KEY (url_hash) REFERENCES url_hashes(url_hash)
        )
      `);

      // Add result_urls column to searches table
      await this.database.query(`
        ALTER TABLE searches ADD COLUMN result_urls TEXT
      `).catch(() => {
        // Column might already exist, ignore error
      });

      // Create summaries table for storing AI-generated summaries
      await this.database.query(`
        CREATE TABLE IF NOT EXISTS summaries (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          url_hash VARCHAR(64) NOT NULL,
          summary_text TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (url_hash) REFERENCES url_hashes(url_hash) ON DELETE CASCADE
        )
      `);

      // Create indexes
      await this.database.query(`
        CREATE INDEX IF NOT EXISTS idx_url_hashes_hash ON url_hashes(url_hash)
      `);

      // Create indexes for domain summaries optimization
      await this.database.query(`
        CREATE INDEX IF NOT EXISTS idx_url_hashes_original_url ON url_hashes(original_url)
      `);

      await this.database.query(`
        CREATE INDEX IF NOT EXISTS idx_url_hashes_crawl_completed ON url_hashes(crawl_completed_at DESC)
      `);

      await this.database.query(`
        CREATE INDEX IF NOT EXISTS idx_url_hashes_status ON url_hashes(crawl_status, summary_status)
      `);

      await this.database.query(`
        CREATE INDEX IF NOT EXISTS idx_user_crawl_requests_user ON user_crawl_requests(user_id)
      `);

      await this.database.query(`
        CREATE INDEX IF NOT EXISTS idx_user_crawl_requests_hash ON user_crawl_requests(url_hash)
      `);

      // Add new indexes for efficient querying
      await this.database.query(`
        CREATE INDEX IF NOT EXISTS idx_url_hashes_summary_status ON url_hashes(summary_status)
      `);

      await this.database.query(`
        CREATE INDEX IF NOT EXISTS idx_url_hashes_crawl_status ON url_hashes(crawl_status)
      `);

      await this.database.query(`
        CREATE INDEX IF NOT EXISTS idx_summaries_url_hash ON summaries(url_hash)
      `);

      console.log('✅ Client database tables initialized');
      return true;
    } catch (error) {
      console.error('❌ Error initializing client tables:', error);
      throw error;
    }
  }

  // Get all crawl requests for a user
  async getUserCrawlRequests(userId) {
    const result = await this.database.query(`
      SELECT ucr.*, uh.original_url
      FROM user_crawl_requests ucr
      JOIN url_hashes uh ON ucr.url_hash = uh.url_hash
      WHERE ucr.user_id = ?
      ORDER BY ucr.created_at DESC
      LIMIT 50
    `, [userId]);

    return result.rows;
  }

  // Update crawl status for URL
  async updateCrawlStatus(urlHash, status, attempts = 0) {
    if (status === 'completed') {
      await this.database.query(`
        UPDATE url_hashes 
        SET crawl_status = ?, crawl_attempts = ?, crawl_completed_at = CURRENT_TIMESTAMP, last_seen = CURRENT_TIMESTAMP
        WHERE url_hash = ?
      `, [status, attempts, urlHash]);
    } else {
      await this.database.query(`
        UPDATE url_hashes 
        SET crawl_status = ?, crawl_attempts = ?, last_seen = CURRENT_TIMESTAMP
        WHERE url_hash = ?
      `, [status, attempts, urlHash]);
    }
  }

  // Get crawl status for URL
  async getCrawlStatus(urlHash) {
    const result = await this.database.query(`
      SELECT crawl_status, crawl_completed_at, crawl_attempts, last_seen
      FROM url_hashes WHERE url_hash = ?
    `, [urlHash]);
    
    return result.rows.length > 0 ? result.rows[0] : null;
  }

  // Check if URL should be crawled (legacy method - calls getCrawlStatus)
  async shouldCrawlUrl(urlHash) {
    const urlData = await this.getCrawlStatus(urlHash);
    return this.shouldCrawlUrlFromStatus(urlData);
  }

  // Optimized version: Check if URL should be crawled based on existing status data
  shouldCrawlUrlFromStatus(urlData) {
    // If URL is new
    if (!urlData) return true;
    
    // If already crawled, no need to crawl again
    if (urlData.crawl_status === 'completed') return false;
    
    // If currently crawling and less than 30 minutes have passed
    if (urlData.crawl_status === 'crawling') {
      const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);
      if (new Date(urlData.last_seen) > thirtyMinutesAgo) return false;
    }
    
    // If pending or failed, should be crawled
    return true;
  }

  // Update summary status for URL
  async updateSummaryStatus(urlHash, status, attempts = 0) {
    if (status === 'summarized') {
      await this.database.query(`
        UPDATE url_hashes 
        SET summary_status = ?, summary_attempts = ?, summary_completed_at = CURRENT_TIMESTAMP
        WHERE url_hash = ?
      `, [status, attempts, urlHash]);
    } else {
      await this.database.query(`
        UPDATE url_hashes 
        SET summary_status = ?, summary_attempts = ?
        WHERE url_hash = ?
      `, [status, attempts, urlHash]);
    }
  }

  // Get files pending summarization
  async getPendingSummaryFiles() {
    const result = await this.database.query(`
      SELECT url_hash, original_url, json_file_path, total_words, main_content_words
      FROM url_hashes 
      WHERE summary_status = 'pending' AND crawl_status = 'completed' AND json_file_path IS NOT NULL
      ORDER BY crawl_completed_at DESC
    `);
    return result.rows;
  }

  // Get all files with summary status (for API)
  async getAllJsonFiles() {
    const result = await this.database.query(`
      SELECT uh.url_hash as id, uh.json_file_path as file_path, uh.url_hash, 
             uh.summary_status as status, uh.total_words, uh.main_content_words,
             uh.crawl_completed_at as created_at, uh.summary_completed_at as processed_at,
             s.summary_text, s.created_at as summary_date
      FROM url_hashes uh
      LEFT JOIN summaries s ON uh.url_hash = s.url_hash
      WHERE uh.crawl_status = 'completed' AND uh.json_file_path IS NOT NULL
      ORDER BY uh.crawl_completed_at DESC
    `);
    return result.rows;
  }

  // Save summary for a URL
  async saveSummary(urlHash, summaryText) {
    await this.database.query(`
      INSERT INTO summaries (url_hash, summary_text)
      VALUES (?, ?)
    `, [urlHash, summaryText]);
  }

  // Mark file as queued for summarization
  async markFileAsQueued(urlHash) {
    await this.updateSummaryStatus(urlHash, 'queued');
  }

  // Mark file as summarized
  async markFileAsSummarized(urlHash) {
    await this.updateSummaryStatus(urlHash, 'summarized');
  }

  // Get summary by URL hash
  async getSummaryByUrlHash(urlHash) {
    const result = await this.database.query(`
      SELECT uh.url_hash, uh.original_url, uh.summary_status, uh.summary_completed_at,
             s.summary_text, s.created_at as summary_date
      FROM url_hashes uh
      LEFT JOIN summaries s ON uh.url_hash = s.url_hash
      WHERE uh.url_hash = ?
    `, [urlHash]);
    
    return result.rows.length > 0 ? result.rows[0] : null;
  }

  // Update JSON file metadata when crawl completes
  async updateJsonFileMetadata(urlHash, filePath, totalWords, mainContentWords) {
    await this.database.query(`
      UPDATE url_hashes 
      SET json_file_path = ?, total_words = ?, main_content_words = ?
      WHERE url_hash = ?
    `, [filePath, totalWords, mainContentWords, urlHash]);
  }

  // Get client statistics
  async getClientStats() {
    const totalRequests = await this.database.query(`
      SELECT COUNT(*) as count FROM user_crawl_requests
    `);

    const totalUrls = await this.database.query(`
      SELECT COUNT(*) as count FROM url_hashes
    `);

    const totalBlocks = await this.database.query(`
      SELECT SUM(total_blocks) as sum FROM user_crawl_requests
    `);

    const totalWords = await this.database.query(`
      SELECT SUM(total_words) as sum FROM user_crawl_requests
    `);

    const crawlStats = await this.database.query(`
      SELECT crawl_status, COUNT(*) as count FROM url_hashes 
      GROUP BY crawl_status
    `);

    const summaryStats = await this.database.query(`
      SELECT summary_status, COUNT(*) as count FROM url_hashes 
      WHERE crawl_status = 'completed'
      GROUP BY summary_status
    `);

    const crawlStatusCounts = {};
    crawlStats.rows.forEach(row => {
      crawlStatusCounts[row.crawl_status] = row.count;
    });

    const summaryStatusCounts = {};
    summaryStats.rows.forEach(row => {
      summaryStatusCounts[row.summary_status] = row.count;
    });

    return {
      totalRequests: totalRequests.rows[0].count,
      totalUrls: totalUrls.rows[0].count,
      totalBlocks: totalBlocks.rows[0].sum || 0,
      totalWords: totalWords.rows[0].sum || 0,
      crawlStatus: crawlStatusCounts,
      summaryStatus: summaryStatusCounts
    };
  }
}

module.exports = ClientDatabase;
