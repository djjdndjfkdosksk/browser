
class DomainFilter {
  constructor() {
    // List of blocked domains
    this.blockedDomains = [
      'instagram.com',
      'wikipedia.org',
      'reddit.com',
      'facebook.com',
      'twitter.com',
      'x.com'
    ];
  }

  // Extract main domain from URL
  extractDomain(url) {
    try {
      const urlObject = new URL(url);
      let hostname = urlObject.hostname.toLowerCase();
      
      // Remove www. from the beginning of domain
      if (hostname.startsWith('www.')) {
        hostname = hostname.substring(4);
      }
      
      return hostname;
    } catch (error) {
      console.error('Error parsing URL:', url, error.message);
      return null;
    }
  }

  // Check if domain is in blocked list
  isBlockedDomain(url) {
    const domain = this.extractDomain(url);
    if (!domain) return false;

    // Check main domain and subdomains
    return this.blockedDomains.some(blockedDomain => {
      // Exact domain check
      if (domain === blockedDomain) return true;
      
      // Check subdomains (like m.facebook.com)
      if (domain.endsWith('.' + blockedDomain)) return true;
      
      return false;
    });
  }

  // Filter search results and select valid URLs
  filterSearchResults(searchResults, maxUrls = 2) {
    const validUrls = [];
    const blockedUrls = [];
    const skippedDomains = [];

    if (!searchResults.organic || searchResults.organic.length === 0) {
      return {
        validUrls: [],
        blockedUrls: [],
        skippedDomains: [],
        totalProcessed: 0
      };
    }

    let processedCount = 0;

    for (const result of searchResults.organic) {
      if (!result.link) continue;
      
      processedCount++;
      
      if (this.isBlockedDomain(result.link)) {
        const domain = this.extractDomain(result.link);
        blockedUrls.push({
          url: result.link,
          domain: domain,
          title: result.title || '.'
        });
        
        if (domain && !skippedDomains.includes(domain)) {
          skippedDomains.push(domain);
        }
      } else {
        validUrls.push(result);
        
        // Stop if we reached desired number
        if (validUrls.length >= maxUrls) {
          break;
        }
      }
    }

    return {
      validUrls: validUrls,
      blockedUrls: blockedUrls,
      skippedDomains: skippedDomains,
      totalProcessed: processedCount
    };
  }

  // Add new domain to blocked list
  addBlockedDomain(domain) {
    const cleanDomain = domain.toLowerCase().replace(/^www\./, '');
    if (!this.blockedDomains.includes(cleanDomain)) {
      this.blockedDomains.push(cleanDomain);
      return true;
    }
    return false;
  }

  // Remove domain from blocked list
  removeBlockedDomain(domain) {
    const cleanDomain = domain.toLowerCase().replace(/^www\./, '');
    const index = this.blockedDomains.indexOf(cleanDomain);
    if (index > -1) {
      this.blockedDomains.splice(index, 1);
      return true;
    }
    return false;
  }

  // Get list of blocked domains
  getBlockedDomains() {
    return [...this.blockedDomains];
  }

  // Test filter functionality
  testFilter(urls) {
    const results = {
      blocked: [],
      allowed: []
    };

    urls.forEach(url => {
      if (this.isBlockedDomain(url)) {
        results.blocked.push({
          url: url,
          domain: this.extractDomain(url)
        });
      } else {
        results.allowed.push({
          url: url,
          domain: this.extractDomain(url)
        });
      }
    });

    return results;
  }
}

module.exports = DomainFilter;
