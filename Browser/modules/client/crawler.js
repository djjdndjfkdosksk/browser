const axios = require('axios');
const crypto = require('crypto');
const DomainFilter = require('./domainFilter');


class CrawlerModule {
  constructor(database) {
    this.database = database;
    this.domainFilter = new DomainFilter();
  }

  // Validate if URL exists before crawling (HEAD request)
  async validateUrlExists(url) {
    try {
      const response = await axios.head(url, {
        timeout: 10000,
        maxRedirects: 5,
        validateStatus: (status) => status < 500
      });

      if (response.status === 404 || response.status === 410 || response.status === 403) {
        return { exists: false, status: response.status };
      }

      // Check if URL was redirected
      const finalUrl = response.request?.res?.responseUrl || response.config.url;
      const redirected = finalUrl !== url;

      return { 
        exists: true, 
        status: response.status,
        redirected: redirected,
        finalUrl: finalUrl
      };
    } catch (error) {
      // If HEAD fails, try GET with very short timeout
      try {
        const response = await axios.get(url, {
          timeout: 5000,
          maxRedirects: 5,
          validateStatus: (status) => status < 500,
          maxContentLength: 1024 // Only get first 1KB
        });

        if (response.status === 404 || response.status === 410 || response.status === 403) {
          return { exists: false, status: response.status };
        }

        // Check if URL was redirected
        const finalUrl = response.request?.res?.responseUrl || response.config.url;
        const redirected = finalUrl !== url;

        return { 
          exists: true, 
          status: response.status,
          redirected: redirected,
          finalUrl: finalUrl
        };
      } catch (getError) {
        console.error(`URL validation error: ${url}`, getError.message);
        return { exists: false, status: 0, error: getError.message };
      }
    }
  }

  // Hash URL to create consistent request ID
  hashUrl(url) {
    return crypto.createHash('md5').update(url).digest('hex');
  }

  // Extract URLs from search results and hash them
  async processSearchResults(searchResults) {
    const urls = [];

    if (searchResults.organic) {
      searchResults.organic.forEach(result => {
        if (result.link) {
          urls.push(result.link);
        }
      });
    }

    // Hash URLs and store in database
    const urlHashes = [];
    for (const url of urls) {
      const urlHash = this.hashUrl(url);
      urlHashes.push(urlHash);

      // Insert or update URL hash in database
      await this.database.query(`
        INSERT OR REPLACE INTO url_hashes (url_hash, original_url, last_seen, access_count, crawl_status)
        VALUES (?, ?, CURRENT_TIMESTAMP, 
          COALESCE((SELECT access_count FROM url_hashes WHERE url_hash = ?) + 1, 1),
          COALESCE((SELECT crawl_status FROM url_hashes WHERE url_hash = ?), 'pending'))
      `, [urlHash, url, urlHash, urlHash]);
    }

    return urlHashes;
  }

  // Process search results with auto-crawl for first 5 URLs
  async processSearchResultsWithAutoCrawl(searchResults, userId) {
    try {
      // Process all URLs first
      const allUrlHashes = await this.processSearchResults(searchResults);

      // Filter search results to remove blocked domains
      const filterResult = this.domainFilter.filterSearchResults(searchResults, 5);

      const urlsToCrawl = [];
      const autoCrawlInfo = {
        selectedUrls: 0,
        newUrls: 0,
        alreadyCrawled: 0,
        blockedUrls: filterResult.blockedUrls.length,
        skippedDomains: filterResult.skippedDomains,
        totalProcessed: filterResult.totalProcessed,
        startedCrawling: [],
        skippedCrawling: []
      };

      // Process valid URLs (not blocked)
      for (const result of filterResult.validUrls) {
        if (result.link) {
          try {
            const urlHash = this.hashUrl(result.link);
            autoCrawlInfo.selectedUrls++;

            // Get crawl status once and use it for both decisions
            const crawlStatus = await global.clientDatabase.getCrawlStatus(urlHash);
            const shouldCrawl = global.clientDatabase.shouldCrawlUrlFromStatus(crawlStatus);

            if (shouldCrawl) {
              if (!crawlStatus) {
                autoCrawlInfo.newUrls++;
              }

              urlsToCrawl.push({ url: result.link, urlHash });
              autoCrawlInfo.startedCrawling.push(urlHash);
            } else {
              autoCrawlInfo.alreadyCrawled++;
              autoCrawlInfo.skippedCrawling.push(urlHash);
            }
          } catch (urlError) {
            console.error('Error processing URL:', result.link, urlError.message);
          }
        }
      }

      // Log blocked domains
      if (filterResult.blockedUrls.length > 0) {
        console.log(`🚫 ${filterResult.blockedUrls.length} URLs from blocked domains filtered:`, 
                   filterResult.skippedDomains.join(', '));
      }

      // Start crawling in background
      if (urlsToCrawl.length > 0) {
        console.log(`🔄 Starting auto-crawl for ${urlsToCrawl.length} URLs`);
        this.crawlInBackground(urlsToCrawl, userId).catch(error => {
          console.error('Error in background crawl:', error.message);
        });
      }

      return {
        urlHashes: allUrlHashes,
        autoCrawl: autoCrawlInfo
      };

    } catch (error) {
      console.error('Error processing search results:', error.message);
      // Return minimal result on error
      return {
        urlHashes: [],
        autoCrawl: {
          selectedUrls: 0,
          newUrls: 0,
          alreadyCrawled: 0,
          startedCrawling: [],
          skippedCrawling: []
        }
      };
    }
  }

  // Crawl URLs in background with smart processing
  async crawlInBackground(urlsToCrawl, userId) {
    console.log(`🔄 Starting auto-crawl of ${urlsToCrawl.length} URLs in background`);

    const crawlResults = [];
    const browserNeededUrls = [];
    const successfulCrawls = [];

    // Crawl all URLs first
    for (const { url, urlHash } of urlsToCrawl) {
      try {
        // Update status to crawling
        await global.clientDatabase.updateCrawlStatus(urlHash, 'crawling');

        console.log(`🕷️ Auto-crawling: ${url}`);

        // Crawl the URL
        const result = await this.crawlUrl(url, userId);

        if (result.success) {
          crawlResults.push({ url, urlHash, result });

          // Check mainContentWords from the result
          const mainContentWords = result.data?.crawlResults?.[0]?.extractedData?.mainContentWords || 0;

          if (mainContentWords === 0) {
            // URL needs browser processing
            browserNeededUrls.push({ url, urlHash });
            console.log(`🌐 URL needs browser: ${url}`);
          } else {
            // URL has good content
            successfulCrawls.push({ url, urlHash, result });
            console.log(`✅ Crawl successful: ${urlHash} (${mainContentWords} main words)`);
          }

          // Update status to completed
          await global.clientDatabase.updateCrawlStatus(urlHash, 'completed');

        } else {
          // Update status to failed
          const attempts = (await global.clientDatabase.getCrawlStatus(urlHash))?.crawl_attempts || 0;
          await global.clientDatabase.updateCrawlStatus(urlHash, 'failed', attempts + 1);
          console.log(`❌ Crawl failed: ${urlHash}`);
        }

        // Wait 2 seconds between crawls
        await new Promise(resolve => setTimeout(resolve, 2000));

      } catch (error) {
        console.error(`❌ Error crawling ${url}:`, error.message);

        // Update status to failed
        const attempts = (await global.clientDatabase.getCrawlStatus(urlHash))?.crawl_attempts || 0;
        await global.clientDatabase.updateCrawlStatus(urlHash, 'failed', attempts + 1);
      }
    }

    console.log(`📊 Crawl result: ${successfulCrawls.length} successful, ${browserNeededUrls.length} need browser`);

    // Process results based on success criteria
    await this.processAllCrawlResults(successfulCrawls, browserNeededUrls, userId);

    console.log(`🏁 Auto-crawl completed`);
  }

  // Process all crawl results with smart AI summarization
  async processAllCrawlResults(successfulCrawls, browserNeededUrls, userId) {
    try {
      if (successfulCrawls.length > 0) {
        // Send each successful URL individually for AI summarization
        console.log(`✅ ${successfulCrawls.length} successful URLs - sending each individually for summarization`);

        const aiPromises = successfulCrawls.map(async ({ url, urlHash, result }) => {
          try {
            // Send each URL individually for its own summary
            const jsonContent = {
              url: url,
              urlHash: urlHash,
              savedAt: new Date().toISOString(),
              filteredData: result.data.crawlResults[0]?.extractedData || {}
            };

            await this.sendToAgentForSummarization(urlHash, jsonContent);
            console.log(`🤖 Content sent to Agent for summarization: ${urlHash}`);
          } catch (agentError) {
            console.error(`❌ Error sending ${urlHash} to Agent: ${agentError.message}`);
          }
        });

        await Promise.all(aiPromises);

        if (browserNeededUrls.length > 0) {
          console.log(`📝 ${browserNeededUrls.length} URLs need browser saved for future processing`);
        }

      } else if (successfulCrawls.length === 0) {
        const totalProcessed = successfulCrawls.length + browserNeededUrls.length;
        if (browserNeededUrls.length === totalProcessed && browserNeededUrls.length > 0) {
          // All URLs need browser - system should step aside to avoid errors
          console.log(`🚫 All URLs require browser - system steps aside to avoid errors`);
        } else {
          console.log(`❌ No successful URLs found`);
        }
      }

    } catch (error) {
      console.error('❌ Error processing crawl results:', error.message);
    }
  }

  // Crawl URL using external crawler service
  async crawlUrl(url, userId) {
    const requestId = this.hashUrl(url);
    const urlHash = requestId;

    try {
      const startTime = Date.now();

      // Send request to Smart Crawler API with enhanced security
      const crawlerUrl = 'https://cra-production.up.railway.app/api/smart-crawl';
      const requestData = {
        urls: [url],
        requestId: requestId,
        query: 'Smart content crawling',
        timestamp: Date.now(),
        source: 'internal-browser-app'
      };

      const response = await axios.post(crawlerUrl, requestData, {
        timeout: 300000, // 5 minutes timeout
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'Internal-Browser-App/1.0',
          'Accept': 'application/json'
        },
        validateStatus: (status) => status < 500, // Accept 4xx responses for proper error handling
        maxRedirects: 0 // Prevent redirect attacks
      });

      const endTime = Date.now();
      const processingTime = ((endTime - startTime) / 1000);

      if (response.data.success) {
        const summary = response.data.summary;
        const totalBlocks = response.data.crawlResults
          .filter(r => r.success && r.extractedData && r.extractedData.blocks)
          .reduce((sum, r) => sum + r.extractedData.blocks.length, 0);

        const totalWords = response.data.crawlResults
          .filter(r => r.success && r.extractedData && r.extractedData.totalWords)
          .reduce((sum, r) => sum + r.extractedData.totalWords, 0);

        // Store URL hash
        await this.database.query(`
          INSERT OR REPLACE INTO url_hashes (url_hash, original_url, last_seen, access_count)
          VALUES (?, ?, CURRENT_TIMESTAMP, 
            COALESCE((SELECT access_count FROM url_hashes WHERE url_hash = ?) + 1, 1))
        `, [urlHash, url, urlHash]);

        // Store crawl request (use INSERT OR REPLACE to handle duplicates)
        await this.database.query(`
          INSERT OR REPLACE INTO user_crawl_requests 
          (request_id, user_id, url_hash, processing_time, total_blocks, total_words)
          VALUES (?, ?, ?, ?, ?, ?)
        `, [requestId, userId, urlHash, processingTime, totalBlocks, totalWords]);

        // Save JSON file
        const jsonContent = {
          url: url,
          urlHash: urlHash,
          savedAt: new Date().toISOString(),
          processingTime: processingTime,
          filteredData: response.data.crawlResults[0]?.extractedData || {}
        };

        const filePath = this.saveJsonFile(requestId, jsonContent);

        // Update file path in database
        await this.database.query(`
          UPDATE user_crawl_requests SET json_file_path = ? WHERE request_id = ?
        `, [filePath, requestId]);

        // Update JSON file metadata in url_hashes for summary tracking
        const mainContentWords = response.data.crawlResults[0]?.extractedData?.mainContentWords || 0;
        await global.clientDatabase.updateJsonFileMetadata(urlHash, filePath, totalWords, mainContentWords);

        // Send to Agent immediately after successful crawl
        console.log(`🤖 [${urlHash}] Auto-sending to Agent for summarization...`);
        try {
          await this.sendToAgentForSummarization(urlHash, jsonContent);
          console.log(`✅ [${urlHash}] Content successfully sent to Agent`);
        } catch (agentError) {
          console.error(`⚠️ [${urlHash}] Error sending to Agent: ${agentError.message}`);
          // Don't fail the crawl if Agent is unavailable
        }

        return {
          success: true,
          requestId: requestId,
          urlHash: urlHash,
          data: response.data,
          storage: {
            database: true,
            filePath: filePath
          }
        };
      } else {
        throw new Error(response.data.error || 'Crawl failed');
      }
    } catch (error) {
      console.error('Crawl error:', error.message);
      throw error;
    }
  }

  // Save JSON file in hierarchical structure
  saveJsonFile(requestId, content) {
    const fs = require('fs');
    const path = require('path');

    const firstTwo = requestId.substring(0, 2);
    const secondTwo = requestId.substring(2, 4);
    const hierarchicalDir = path.join(__dirname, '../../client_content', firstTwo, secondTwo);

    // Create directory structure if it doesn't exist
    if (!fs.existsSync(hierarchicalDir)) {
      fs.mkdirSync(hierarchicalDir, { recursive: true });
    }

    const fileName = `${requestId}.json`;
    const filePath = path.join(hierarchicalDir, fileName);

    fs.writeFileSync(filePath, JSON.stringify(content, null, 2), 'utf8');

    return `client_content/${firstTwo}/${secondTwo}/${fileName}`;
  }

  // Get crawl results by request ID
  async getCrawlResults(requestId) {
    const result = await this.database.query(`
      SELECT * FROM user_crawl_requests WHERE request_id = ?
    `, [requestId]);

    if (result.rows.length === 0) {
      return null;
    }

    const metadata = result.rows[0];

    // Load JSON file if exists
    if (metadata.json_file_path) {
      const fs = require('fs');
      const path = require('path');
      const fullPath = path.join(__dirname, '../../', metadata.json_file_path);

      if (fs.existsSync(fullPath)) {
        const fileContent = fs.readFileSync(fullPath, 'utf8');
        metadata.content = JSON.parse(fileContent);
      }
    }

    return metadata;
  }

  // Send crawled content to Agent service for AI summarization
  async sendToAgentForSummarization(urlHash, jsonContent) {
    try {
      // Update summary status to 'processing'
      await global.clientDatabase.updateSummaryStatus(urlHash, 'processing');

      console.log(`🚀 [${urlHash}] Sending content to Agent for summarization...`);
      console.log(`📝 URL: ${jsonContent.url}`);
      console.log(`📊 Content: ${JSON.stringify(jsonContent.filteredData).substring(0, 200)}...`);

      const agentResponse = await axios.post('https://gshsh-production.up.railway.app/api/process', {
        fileId: urlHash,
        jsonData: jsonContent
      }, {
        timeout: 30000,
        headers: {
          'Content-Type': 'application/json',
          'x-request-id': urlHash
        }
      });

      if (agentResponse.data.success) {
        console.log(`✅ [${urlHash}] File processed successfully`);
        
        // Save summary directly from response
        if (agentResponse.data.summary) {
          await global.clientDatabase.saveSummary(urlHash, agentResponse.data.summary);
          await global.clientDatabase.markFileAsSummarized(urlHash);
          console.log(`💾 [${urlHash}] Summary saved`);
        }
        
        await global.clientDatabase.updateSummaryStatus(urlHash, 'summarized');
      } else {
        console.error(`❌ [${urlHash}] Processing error: ${agentResponse.data.error}`);
        await global.clientDatabase.updateSummaryStatus(urlHash, 'failed');
      }
    } catch (error) {
      console.error(`❌ [${urlHash}] Error sending to Agent: ${error.message}`);
      // Update summary status to failed
      await global.clientDatabase.updateSummaryStatus(urlHash, 'failed');
      throw new Error(`Failed to send to Agent: ${error.message}`);
    }
  }
}

module.exports = CrawlerModule;