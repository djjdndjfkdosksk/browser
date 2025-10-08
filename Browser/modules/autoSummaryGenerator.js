const crypto = require('crypto');

class AutoSummaryGenerator {
  constructor(database, clientDatabase, crawlerModule) {
    this.database = database;
    this.clientDatabase = clientDatabase;
    this.crawlerModule = crawlerModule;
  }

  hashUrl(url) {
    return crypto.createHash('md5').update(url).digest('hex');
  }

  extractUrlFromPath(urlPath) {
    const cleanPath = urlPath.replace(/^\/+/, '');

    if (!cleanPath) {
      return null;
    }

    let fullUrl = cleanPath;
    if (!fullUrl.startsWith('http://') && !fullUrl.startsWith('https://')) {
      fullUrl = 'https://' + fullUrl;
    }

    return fullUrl;
  }

  async getDomainOwner(url) {
    try {
      const parsedUrl = new URL(url);
      const hostname = parsedUrl.hostname.toLowerCase().replace(/^www\./, '');

      // Check if the hostname is a registered subdomain
      const subdomainResult = await this.database.query(
        'SELECT user_id FROM user_subdomains WHERE subdomain = ?',
        [hostname]
      );

      if (subdomainResult.rows.length > 0) {
        const userId = subdomainResult.rows[0].user_id;
        const userResult = await this.database.query(
          'SELECT id, username, domain FROM users WHERE id = ?',
          [userId]
        );
        if (userResult.rows.length > 0) {
          return userResult.rows[0];
        }
      }

      // If not a subdomain, check if it's a main domain or a subdomain of a main domain
      const result = await this.database.query(`
        SELECT id, username, domain 
        FROM users 
        WHERE LOWER(REPLACE(REPLACE(domain, 'https://', ''), 'http://', '')) LIKE ?
           OR LOWER(REPLACE(REPLACE(domain, 'https://', ''), 'http://', '')) LIKE ?
      `, [`%${hostname}%`, `${hostname}%`]);

      if (result.rows.length === 0) {
        return null;
      }

      for (const user of result.rows) {
        const userDomain = user.domain.replace(/^https?:\/\//, '').replace(/^www\./, '').toLowerCase();
        if (hostname === userDomain || hostname.endsWith(`.${userDomain}`)) {
          return user;
        }
      }

      return null;
    } catch (error) {
      console.error('Error extracting domain owner:', error);
      return null;
    }
  }

  async validateUrlForAutoCrawl(urlPath) {
    try {
      const fullUrl = urlPath.startsWith('http') ? urlPath : `https://${urlPath}`;
      const parsedUrl = new URL(fullUrl);
      const hostname = parsedUrl.hostname.replace(/^www\./, '');

      // First try to find user by main domain
      let userResult = await this.database.query(
        'SELECT id, verification_status FROM users WHERE domain LIKE ?',
        [`%${hostname}%`]
      );

      // If not found by main domain, try to find by subdomain
      if (userResult.rows.length === 0) {
        const subdomainResult = await this.database.query(
          'SELECT user_id FROM user_subdomains WHERE subdomain = ?',
          [hostname]
        );

        if (subdomainResult.rows.length > 0) {
          const userId = subdomainResult.rows[0].user_id;
          userResult = await this.database.query(
            'SELECT id, verification_status FROM users WHERE id = ?',
            [userId]
          );
        }
      }

      if (userResult.rows.length === 0) {
        return { 
          valid: false, 
          reason: 'domain_not_registered',
          message: 'Domain or subdomain not registered in system' 
        };
      }

      const user = userResult.rows[0];

      if (user.verification_status !== 'verified') {
        return { 
          valid: false, 
          reason: 'domain_not_verified',
          message: 'Main domain not verified' 
        };
      }

      return { 
        valid: true, 
        userId: user.id,
        url: fullUrl
      };

    } catch (error) {
      this.logger.error('Error validating URL for auto-crawl', error);
      return { 
        valid: false, 
        reason: 'validation_error',
        message: error.message 
      };
    }
  }

  async shouldAutoCrawl(urlPath) {
    try {
      const checkResult = await this.validateUrlForAutoCrawl(urlPath);
      if (!checkResult.valid) {
        return { shouldCrawl: false, reason: checkResult.reason, message: checkResult.message };
      }

      const fullUrl = checkResult.url;
      const urlHash = this.hashUrl(fullUrl);

      const existingSummary = await this.clientDatabase.getSummaryByUrlHash(urlHash);

      // اگر خلاصه شده است، نیازی به crawl نیست
      if (existingSummary && existingSummary.summary_status === 'summarized') {
        return { shouldCrawl: false, reason: 'already_exists', urlHash };
      }

      // اگر در حال پردازش است، منتظر بمانیم
      if (existingSummary && ['crawling', 'processing', 'queued'].includes(existingSummary.summary_status)) {
        return { shouldCrawl: false, reason: 'in_progress', urlHash };
      }

      // اگر pending یا failed است، باید دوباره crawl شود
      if (existingSummary && ['pending', 'failed'].includes(existingSummary.summary_status)) {
        console.log(`🔄 URL has status ${existingSummary.summary_status}, will retry crawl: ${urlHash}`);
        return { 
          shouldCrawl: true, 
          url: fullUrl, 
          urlHash, 
          userId: checkResult.userId,
          username: null,
          isRetry: true
        };
      }

      // اگر URL جدید است
      return { 
        shouldCrawl: true, 
        url: fullUrl, 
        urlHash, 
        userId: checkResult.userId,
        username: null,
        isRetry: false
      };
    } catch (error) {
      console.error('Error in shouldAutoCrawl:', error);
      return { shouldCrawl: false, reason: 'error', error: error.message };
    }
  }

  async initiateAutoCrawl(url, urlHash, userId) {
    try {
      console.log(`🤖 Starting auto-crawl for: ${url} (user: ${userId})`);

      await this.clientDatabase.updateCrawlStatus(urlHash, 'crawling');
      await this.clientDatabase.updateSummaryStatus(urlHash, 'processing');

      const crawlResult = await this.crawlerModule.crawlUrl(url, userId);

      if (crawlResult.success) {
        console.log(`✅ Auto-crawl successful: ${urlHash}`);

        const mainContentWords = crawlResult.data?.crawlResults?.[0]?.extractedData?.mainContentWords || 0;

        if (mainContentWords > 0) {
          const jsonContent = {
            url: url,
            urlHash: urlHash,
            savedAt: new Date().toISOString(),
            filteredData: crawlResult.data.crawlResults[0]?.extractedData || {}
          };

          await this.crawlerModule.sendToAgentForSummarization(urlHash, jsonContent);
          console.log(`🤖 Content sent for summarization: ${urlHash}`);

          return { success: true, status: 'summarizing' };
        } else {
          console.log(`⚠️ Insufficient content found: ${urlHash}`);
          await this.clientDatabase.updateCrawlStatus(urlHash, 'failed');
          await this.clientDatabase.updateSummaryStatus(urlHash, 'failed');
          return { success: false, reason: 'no_content' };
        }
      } else {
        console.log(`❌ Auto-crawl failed: ${urlHash}`);
        await this.clientDatabase.updateCrawlStatus(urlHash, 'failed');
        await this.clientDatabase.updateSummaryStatus(urlHash, 'failed');
        return { success: false, reason: 'crawl_failed' };
      }
    } catch (error) {
      console.error(`❌ Error in auto-crawl: ${error.message}`);
      await this.clientDatabase.updateCrawlStatus(urlHash, 'failed');
      await this.clientDatabase.updateSummaryStatus(urlHash, 'failed');
      return { success: false, reason: 'error', error: error.message };
    }
  }

  async handleAutoCrawlRequest(urlPath) {
    const checkResult = await this.shouldAutoCrawl(urlPath);

    if (!checkResult.shouldCrawl) {
      if (checkResult.reason === 'in_progress') {
        return { 
          status: 'processing', 
          urlHash: checkResult.urlHash,
          message: 'Summary is being generated' 
        };
      }
      if (checkResult.reason === 'already_exists') {
        return { 
          status: 'completed', 
          urlHash: checkResult.urlHash,
          message: 'Summary already exists' 
        };
      }
      return { 
        status: 'not_eligible', 
        reason: checkResult.reason,
        message: checkResult.message || 'Cannot auto-generate summary for this URL' 
      };
    }

    // ✅ CRITICAL: Validate if URL exists BEFORE any database operations
    console.log(`🔍 Validating if URL exists: ${checkResult.url}`);
    const validation = await this.crawlerModule.validateUrlExists(checkResult.url);
    
    if (!validation.exists) {
      console.log(`🚫 URL does not exist (HTTP ${validation.status}): ${checkResult.url}`);
      // DO NOT save to database, just return 404 error
      return {
        status: 'not_found',
        reason: 'url_not_found',
        httpStatus: validation.status,
        message: 'Page does not exist'
      };
    }

    // Check if URL redirects
    if (validation.redirected && validation.finalUrl !== checkResult.url) {
      console.log(`🚫 URL redirects (${checkResult.url} -> ${validation.finalUrl})`);
      // DO NOT save to database, just return 404 error for redirected URLs
      return {
        status: 'not_found',
        reason: 'url_redirects',
        httpStatus: validation.status,
        originalUrl: checkResult.url,
        redirectsTo: validation.finalUrl,
        message: 'Page does not exist'
      };
    }

    console.log(`✅ URL exists (HTTP ${validation.status}): ${checkResult.url}`);

    // اگر retry است، فقط وضعیت را آپدیت می‌کنیم
    if (checkResult.isRetry) {
      try {
        await this.database.query(`
          UPDATE url_hashes 
          SET crawl_status = 'queued', summary_status = 'queued' 
          WHERE url_hash = ?
        `, [checkResult.urlHash]);
        
        console.log(`🔄 Retrying crawl for existing URL: ${checkResult.urlHash}`);
      } catch (err) {
        console.error('Error updating URL status for retry:', err);
        return {
          status: 'error',
          message: 'Failed to queue URL for retry'
        };
      }
    } else {
      // URL جدید است، آن را وارد دیتابیس می‌کنیم
      try {
        const insertResult = await this.database.query(`
          INSERT OR IGNORE INTO url_hashes (url_hash, original_url, crawl_status, summary_status)
          VALUES (?, ?, 'queued', 'queued')
        `, [checkResult.urlHash, checkResult.url]);

        if (insertResult && insertResult.changes === 0) {
          // یک درخواست دیگر همین URL را در حال پردازش است
          return { 
            status: 'processing', 
            urlHash: checkResult.urlHash,
            message: 'Summary is already being generated by another request' 
          };
        }
      } catch (err) {
        console.error('Error inserting new URL:', err);
        return {
          status: 'error',
          message: 'Failed to queue URL for processing'
        };
      }
    }

    // شروع crawl در background
    setImmediate(async () => {
      await this.initiateAutoCrawl(checkResult.url, checkResult.urlHash, checkResult.userId);
    });

    return { 
      status: 'initiated', 
      urlHash: checkResult.urlHash,
      url: checkResult.url,
      message: checkResult.isRetry ? 'Retrying summary generation' : 'Summary generation started' 
    };
  }
}

module.exports = AutoSummaryGenerator;