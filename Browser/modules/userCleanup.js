class UserCleanup {
  constructor(database, logger) {
    this.database = database;
    this.logger = logger;
  }

  normalizeDomain(domain) {
    if (!domain) return '';
    return domain
      .replace(/^https?:\/\//, '')
      .replace(/^www\./, '')
      .replace(/\/+$/, '')
      .replace(/\?.*$/, '')
      .replace(/#.*$/, '')
      .toLowerCase()
      .trim();
  }

  isSubdomainOf(subdomain, mainDomain) {
    const cleanSubdomain = this.normalizeDomain(subdomain);
    const cleanMainDomain = this.normalizeDomain(mainDomain);

    if (!cleanSubdomain || !cleanMainDomain) return false;

    const subdomainParts = cleanSubdomain.split('.');
    const mainDomainParts = cleanMainDomain.split('.');

    if (subdomainParts.length <= mainDomainParts.length) {
      return false;
    }

    const subdomainSuffix = subdomainParts.slice(-mainDomainParts.length).join('.');
    return subdomainSuffix === cleanMainDomain;
  }

  async deleteUnverifiedUsersWithSameDomain(verifiedUserId, verifiedDomain) {
    // Use a simple lock mechanism to prevent concurrent cleanup operations
    const lockKey = `cleanup_${this.normalizeDomain(verifiedDomain)}`;
    
    if (this._activeLocks && this._activeLocks.has(lockKey)) {
      this.logger.warn('Cleanup already in progress for domain', { domain: verifiedDomain });
      return { success: false, error: 'Cleanup already in progress' };
    }
    
    if (!this._activeLocks) {
      this._activeLocks = new Set();
    }
    
    this._activeLocks.add(lockKey);
    
    try {
      const normalizedVerifiedDomain = this.normalizeDomain(verifiedDomain);
      
      if (!normalizedVerifiedDomain) {
        return { success: false, error: 'Invalid domain' };
      }

      // Safety check: Verify the user is actually verified
      const verifiedUserCheck = await this.database.query(
        'SELECT verification_status, domain FROM users WHERE id = ?',
        [verifiedUserId]
      );
      
      if (verifiedUserCheck.rows.length === 0) {
        this.logger.error('Cleanup called for non-existent user', { verifiedUserId });
        return { success: false, error: 'User not found' };
      }
      
      if (verifiedUserCheck.rows[0].verification_status !== 'verified') {
        this.logger.error('Cleanup called for unverified user', { 
          verifiedUserId, 
          status: verifiedUserCheck.rows[0].verification_status 
        });
        return { success: false, error: 'User is not verified' };
      }

      const allUsersResult = await this.database.query(
        'SELECT id, domain, verification_status FROM users WHERE id != ?',
        [verifiedUserId]
      );

      const userIdsToDelete = [];
      const deletionDetails = [];
      
      for (const user of allUsersResult.rows) {
        if (user.domain && user.verification_status !== 'verified') {
          const userNormalizedDomain = this.normalizeDomain(user.domain);
          
          // Check exact match
          if (userNormalizedDomain === normalizedVerifiedDomain) {
            userIdsToDelete.push(user.id);
            deletionDetails.push({
              userId: user.id,
              domain: userNormalizedDomain,
              reason: 'exact_match'
            });
          }
          // Check if user's domain is a subdomain of verified domain
          else if (this.isSubdomainOf(userNormalizedDomain, normalizedVerifiedDomain)) {
            userIdsToDelete.push(user.id);
            deletionDetails.push({
              userId: user.id,
              domain: userNormalizedDomain,
              reason: 'subdomain_of_verified'
            });
          }
        }
      }

      let deletedCount = 0;
      if (userIdsToDelete.length > 0) {
        // Log details before deletion
        this.logger.info('Starting cleanup of unverified users', {
          verifiedUserId,
          verifiedDomain: normalizedVerifiedDomain,
          usersToDelete: deletionDetails
        });

        // Delete related data first
        for (const userId of userIdsToDelete) {
          // Delete user crawl requests
          await this.database.query(
            'DELETE FROM user_crawl_requests WHERE user_id = ?',
            [userId]
          );
          
          // Delete sessions (in case CASCADE doesn't work)
          await this.database.query(
            'DELETE FROM sessions WHERE user_id = ?',
            [userId]
          );
          
          // Delete searches (in case CASCADE doesn't work)
          await this.database.query(
            'DELETE FROM searches WHERE user_id = ?',
            [userId]
          );
        }

        // Delete users
        const placeholders = userIdsToDelete.map(() => '?').join(',');
        const deletedUsers = await this.database.query(
          `DELETE FROM users WHERE id IN (${placeholders})`,
          userIdsToDelete
        );
        deletedCount = deletedUsers.changes || 0;

        if (deletedCount > 0) {
          this.logger.info('Successfully deleted unverified users', { 
            verifiedUserId, 
            domain: normalizedVerifiedDomain, 
            deletedCount,
            deletedUsers: deletionDetails
          });
        }
      }

      return {
        success: true,
        deletedCount,
        message: `Successfully deleted ${deletedCount} unverified user(s) with the same domain`
      };
    } catch (error) {
      this.logger.error('Error in cleanup operation', error);
      return { success: false, error: 'Cleanup failed' };
    } finally {
      // Release lock
      const lockKey = `cleanup_${this.normalizeDomain(verifiedDomain)}`;
      if (this._activeLocks) {
        this._activeLocks.delete(lockKey);
      }
    }
  }

  async checkDomainOrSubdomainVerified(domain) {
    try {
      const normalizedDomain = this.normalizeDomain(domain);
      
      if (!normalizedDomain) {
        return { verified: false, verifiedBy: null };
      }

      const allVerifiedUsers = await this.database.query(
        'SELECT id, username, domain FROM users WHERE verification_status = ?',
        ['verified']
      );

      for (const verifiedUser of allVerifiedUsers.rows) {
        if (verifiedUser.domain) {
          const verifiedNormalizedDomain = this.normalizeDomain(verifiedUser.domain);
          
          if (verifiedNormalizedDomain === normalizedDomain) {
            return { 
              verified: true, 
              verifiedBy: verifiedUser.username,
              reason: 'exact_match',
              verifiedDomain: verifiedNormalizedDomain
            };
          }
          
          if (this.isSubdomainOf(normalizedDomain, verifiedNormalizedDomain)) {
            return { 
              verified: true, 
              verifiedBy: verifiedUser.username,
              reason: 'subdomain_of_verified',
              verifiedDomain: verifiedNormalizedDomain
            };
          }
        }
      }

      return { verified: false, verifiedBy: null };
    } catch (error) {
      this.logger.error('Error checking domain verification', error);
      return { verified: false, verifiedBy: null, error: error.message };
    }
  }
}

module.exports = UserCleanup;
