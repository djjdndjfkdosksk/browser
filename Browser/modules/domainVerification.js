const crypto = require('crypto');
const dns = require('dns').promises;

class DomainVerification {
  constructor(database, logger) {
    this.database = database;
    this.logger = logger;
    this.VERIFICATION_TIMEOUT = 48 * 60 * 60 * 1000;
    this.CHECK_INTERVAL = 5 * 60 * 1000;
    this.TXT_RECORD_PREFIX = '_domain-verification';
  }

  generateVerificationToken() {
    return crypto.randomBytes(32).toString('hex');
  }

  async requestVerification(userId) {
    try {
      const userResult = await this.database.query(
        'SELECT domain, verification_status FROM users WHERE id = ?',
        [userId]
      );

      if (userResult.rows.length === 0) {
        return { success: false, error: 'User not found' };
      }

      const user = userResult.rows[0];

      if (!user.domain) {
        return { success: false, error: 'No domain registered for this user' };
      }

      if (user.verification_status === 'verified') {
        return { success: false, error: 'Your domain has already been verified. No need to create a new verification record.' };
      }

      const existingResult = await this.database.query(
        'SELECT * FROM domain_verifications WHERE user_id = ? AND status = ? ORDER BY created_at DESC LIMIT 1',
        [userId, 'pending']
      );

      if (existingResult.rows.length > 0) {
        const existing = existingResult.rows[0];
        const expiresAt = new Date(existing.expires_at);

        if (expiresAt > new Date()) {
          return {
            success: true,
            verification: {
              token: existing.verification_token,
              txtRecordName: existing.txt_record_name,
              domain: existing.domain,
              expiresAt: expiresAt.toISOString()
            }
          };
        }
      }

      const token = this.generateVerificationToken();
      const domain = this.normalizeDomain(user.domain);
      const txtRecordName = `${this.TXT_RECORD_PREFIX}.${domain}`;
      const expiresAt = new Date(Date.now() + this.VERIFICATION_TIMEOUT);

      await this.database.query(
        `INSERT INTO domain_verifications (user_id, domain, verification_token, txt_record_name, expires_at) 
         VALUES (?, ?, ?, ?, ?)`,
        [userId, domain, token, txtRecordName, expiresAt.toISOString()]
      );

      this.logger.info('Domain verification request created', { userId, domain });

      return {
        success: true,
        verification: {
          token,
          txtRecordName,
          domain,
          expiresAt: expiresAt.toISOString()
        }
      };
    } catch (error) {
      this.logger.error('Error in domain verification request', error);
      return { success: false, error: 'Error creating verification request' };
    }
  }

  normalizeDomain(domain) {
    return domain
      .replace(/^https?:\/\//, '')
      .replace(/^www\./, '')
      .replace(/\/+$/, '')
      .replace(/\?.*$/, '')
      .replace(/#.*$/, '')
      .toLowerCase()
      .trim();
  }

  async checkDNSRecord(domain, token) {
    try {
      const txtRecordName = `${this.TXT_RECORD_PREFIX}.${domain}`;

      let records = [];
      try {
        // Use longer timeout for DNS queries to handle network issues
        records = await Promise.race([
          dns.resolveTxt(txtRecordName),
          new Promise((_, reject) => 
            setTimeout(() => reject(new Error('DNS timeout')), 10000)
          )
        ]);
      } catch (dnsError) {
        if (dnsError.code === 'ENOTFOUND' || dnsError.code === 'ENODATA') {
          return { found: false, message: 'TXT record not found' };
        }
        if (dnsError.message === 'DNS timeout') {
          return { found: false, message: 'DNS lookup timeout' };
        }
        throw dnsError;
      }

      for (const record of records) {
        const recordValue = Array.isArray(record) ? record.join('') : record;
        if (recordValue === token) {
          return { found: true, message: 'Record verified' };
        }
      }

      return { found: false, message: 'TXT record found but token does not match' };
    } catch (error) {
      this.logger.error('Error checking DNS', error);
      return { found: false, message: 'Error checking DNS', error: error.message };
    }
  }

  async verifyDomain(userId) {
    try {
      const verificationResult = await this.database.query(
        `SELECT * FROM domain_verifications 
         WHERE user_id = ? AND status = 'pending' 
         ORDER BY created_at DESC LIMIT 1`,
        [userId]
      );

      if (verificationResult.rows.length === 0) {
        return { success: false, error: 'No active verification request found' };
      }

      const verification = verificationResult.rows[0];
      const expiresAt = new Date(verification.expires_at);

      if (expiresAt < new Date()) {
        await this.database.query(
          'UPDATE domain_verifications SET status = ? WHERE id = ?',
          ['expired', verification.id]
        );
        return { success: false, error: 'Verification time has expired. Please create a new request' };
      }

      await this.database.query(
        'UPDATE domain_verifications SET last_check_at = ? WHERE id = ?',
        [new Date().toISOString(), verification.id]
      );

      const dnsCheck = await this.checkDNSRecord(verification.domain, verification.verification_token);

      if (dnsCheck.found) {
        await this.database.query(
          'UPDATE domain_verifications SET status = ?, verified_at = ? WHERE id = ?',
          ['verified', new Date().toISOString(), verification.id]
        );

        const normalizedDomain = this.normalizeDomain(verification.domain);
        
        await this.database.query(
          'UPDATE users SET verification_status = ?, domain = ? WHERE id = ?',
          ['verified', normalizedDomain, userId]
        );

        const cleanupResult = await global.userCleanup.deleteUnverifiedUsersWithSameDomain(userId, normalizedDomain);

        this.logger.info('Domain successfully verified', { 
          userId, 
          domain: normalizedDomain,
          deletedUsers: cleanupResult.deletedCount || 0
        });

        return {
          success: true,
          message: 'Your domain has been successfully verified!'
        };
      } else {
        return {
          success: false,
          error: dnsCheck.message,
          details: dnsCheck.error
        };
      }
    } catch (error) {
      this.logger.error('Error verifying domain', error);
      return { success: false, error: 'Error in verification process' };
    }
  }

  async getVerificationStatus(userId) {
    try {
      const userResult = await this.database.query(
        'SELECT domain, verification_status FROM users WHERE id = ?',
        [userId]
      );

      if (userResult.rows.length === 0) {
        return { success: false, error: 'User not found' };
      }

      const user = userResult.rows[0];

      const verificationResult = await this.database.query(
        `SELECT * FROM domain_verifications 
         WHERE user_id = ? 
         ORDER BY created_at DESC LIMIT 1`,
        [userId]
      );

      const subdomainsResult = await this.database.query(
        'SELECT subdomain FROM user_subdomains WHERE user_id = ?',
        [userId]
      );

      return {
        success: true,
        domain: user.domain,
        verificationStatus: user.verification_status,
        activeVerification: verificationResult.rows[0] || null,
        subdomains: subdomainsResult.rows.map(r => r.subdomain)
      };
    } catch (error) {
      this.logger.error('Error retrieving verification status', error);
      return { success: false, error: 'Error retrieving status' };
    }
  }

  async addSubdomain(userId, subdomain) {
    try {
      const userResult = await this.database.query(
        'SELECT domain, verification_status FROM users WHERE id = ?',
        [userId]
      );

      if (userResult.rows.length === 0) {
        return { success: false, error: 'User not found' };
      }

      const user = userResult.rows[0];

      if (user.verification_status !== 'verified') {
        return { success: false, error: 'You must first verify your main domain' };
      }

      if (!user.domain) {
        return { success: false, error: 'No main domain configured' };
      }

      const normalizedSubdomain = this.normalizeDomain(subdomain);
      const mainDomain = this.normalizeDomain(user.domain);

      // Validate that subdomain belongs to user's main domain
      if (!this.isSubdomainOfMainDomain(normalizedSubdomain, mainDomain)) {
        return { 
          success: false, 
          error: `Subdomain must belong to your main domain (${mainDomain})` 
        };
      }

      const existingResult = await this.database.query(
        'SELECT * FROM user_subdomains WHERE user_id = ? AND subdomain = ?',
        [userId, normalizedSubdomain]
      );

      if (existingResult.rows.length > 0) {
        return { success: false, error: 'This subdomain has already been added' };
      }

      await this.database.query(
        'INSERT INTO user_subdomains (user_id, subdomain) VALUES (?, ?)',
        [userId, normalizedSubdomain]
      );

      this.logger.info('Subdomain added', { userId, subdomain: normalizedSubdomain });

      return {
        success: true,
        message: 'Subdomain successfully added',
        subdomain: normalizedSubdomain
      };
    } catch (error) {
      this.logger.error('Error adding subdomain', error);
      return { success: false, error: 'Error adding subdomain' };
    }
  }

  isSubdomainOfMainDomain(subdomain, mainDomain) {
    // Remove protocol if present
    const cleanSubdomain = subdomain.replace(/^https?:\/\//, '');
    const cleanMainDomain = mainDomain.replace(/^https?:\/\//, '');

    // Extract domain parts
    const subdomainParts = cleanSubdomain.split('.');
    const mainDomainParts = cleanMainDomain.split('.');

    // Subdomain must have more parts than main domain
    if (subdomainParts.length <= mainDomainParts.length) {
      return false;
    }

    // Check if subdomain ends with main domain
    const subdomainSuffix = subdomainParts.slice(-mainDomainParts.length).join('.');
    return subdomainSuffix === cleanMainDomain;
  }

  async removeSubdomain(userId, subdomain) {
    try {
      const normalizedSubdomain = this.normalizeDomain(subdomain);

      const result = await this.database.query(
        'DELETE FROM user_subdomains WHERE user_id = ? AND subdomain = ?',
        [userId, normalizedSubdomain]
      );

      if (result.changes === 0) {
        return { success: false, error: 'Subdomain not found' };
      }

      this.logger.info('Subdomain removed', { userId, subdomain: normalizedSubdomain });

      return {
        success: true,
        message: 'Subdomain successfully removed'
      };
    } catch (error) {
      this.logger.error('Error removing subdomain', error);
      return { success: false, error: 'Error removing subdomain' };
    }
  }
}

module.exports = DomainVerification;