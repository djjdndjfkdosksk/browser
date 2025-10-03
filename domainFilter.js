
class DomainFilter {
  constructor() {
    // لیست دامنه‌های ممنوع
    this.blockedDomains = [
      'instagram.com',
      'wikipedia.org',
      'reddit.com',
      'facebook.com',
      'twitter.com',
      'x.com'
    ];
  }

  // استخراج دامنه اصلی از URL
  extractDomain(url) {
    try {
      const urlObject = new URL(url);
      let hostname = urlObject.hostname.toLowerCase();
      
      // حذف www. از ابتدای دامنه
      if (hostname.startsWith('www.')) {
        hostname = hostname.substring(4);
      }
      
      return hostname;
    } catch (error) {
      console.error('خطا در پارس URL:', url, error.message);
      return null;
    }
  }

  // بررسی اینکه آیا دامنه در لیست ممنوع است یا خیر
  isBlockedDomain(url) {
    const domain = this.extractDomain(url);
    if (!domain) return false;

    // بررسی دامنه اصلی و زیردامنه‌ها
    return this.blockedDomains.some(blockedDomain => {
      // بررسی دقیق دامنه
      if (domain === blockedDomain) return true;
      
      // بررسی زیردامنه‌ها (مثل m.facebook.com)
      if (domain.endsWith('.' + blockedDomain)) return true;
      
      return false;
    });
  }

  // فیلتر کردن نتایج جستجو و انتخاب URL های معتبر
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
        
        // اگر به تعداد مطلوب رسیدیم، توقف
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

  // اضافه کردن دامنه جدید به لیست ممنوع
  addBlockedDomain(domain) {
    const cleanDomain = domain.toLowerCase().replace(/^www\./, '');
    if (!this.blockedDomains.includes(cleanDomain)) {
      this.blockedDomains.push(cleanDomain);
      return true;
    }
    return false;
  }

  // حذف دامنه از لیست ممنوع
  removeBlockedDomain(domain) {
    const cleanDomain = domain.toLowerCase().replace(/^www\./, '');
    const index = this.blockedDomains.indexOf(cleanDomain);
    if (index > -1) {
      this.blockedDomains.splice(index, 1);
      return true;
    }
    return false;
  }

  // دریافت لیست دامنه‌های ممنوع
  getBlockedDomains() {
    return [...this.blockedDomains];
  }

  // تست عملکرد فیلتر
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
