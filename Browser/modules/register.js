
const database = require('../database');
const security = require('./security');
const logger = require('./logger');

class RegisterModule {
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


  async registerUser(username, password, securityQuestion, securityAnswer, domain) {
    try {
      // Enhanced input validation
      const usernameValidation = security.validateInput(username, 'username');
      if (!usernameValidation.isValid) {
        return { success: false, error: usernameValidation.error };
      }
      username = usernameValidation.value;
      
      const passwordValidation = security.validateInput(password, 'password');
      if (!passwordValidation.isValid) {
        return { success: false, error: passwordValidation.error };
      }
      
      securityQuestion = security.sanitizeInput(securityQuestion, { lowercase: false });
      securityAnswer = security.sanitizeInput(securityAnswer, { lowercase: false });
      
      // Validate and sanitize domain
      if (!domain || domain.trim().length === 0) {
        return { success: false, error: 'Domain is required for website owners' };
      }
      domain = security.sanitizeInput(domain.trim(), { lowercase: true });

      // Password validation is already done above
      // Additional username length check (already validated in validateInput)
      if (username.length < 3) {
        return { success: false, error: 'Username must be at least 3 characters long' };
      }

      // Password already validated above

      if (!securityQuestion || securityQuestion.length < 10) {
        return { success: false, error: 'Security question must be at least 10 characters long' };
      }

      if (!securityAnswer || securityAnswer.length < 3) {
        return { success: false, error: 'Security answer must be at least 3 characters long' };
      }
      
      // Validate domain format (basic URL validation)
      try {
        const domainUrl = domain.startsWith('http') ? domain : `https://${domain}`;
        new URL(domainUrl);
      } catch (e) {
        return { success: false, error: 'Invalid domain format. Please enter a valid website domain (e.g., example.com or https://example.com)' };
      }

      const normalizedDomain = this.normalizeDomain(domain);

      // Check if username already exists
      const existingUser = await database.query(
        'SELECT id FROM users WHERE username = ?',
        [username]
      );

      if (existingUser.rows.length > 0) {
        return { success: false, error: 'Username already exists' };
      }

      // Check if domain or its parent domain is already verified by another user
      const allVerifiedUsers = await database.query(
        'SELECT id, username, domain FROM users WHERE verification_status = ?',
        ['verified']
      );

      for (const verifiedUser of allVerifiedUsers.rows) {
        if (verifiedUser.domain) {
          const verifiedNormalizedDomain = this.normalizeDomain(verifiedUser.domain);
          
          if (verifiedNormalizedDomain === normalizedDomain) {
            return { 
              success: false, 
              error: 'This domain has already been verified by another user and cannot be used for new registrations' 
            };
          }
          
          if (this.isSubdomainOf(normalizedDomain, verifiedNormalizedDomain)) {
            return { 
              success: false, 
              error: `This is a subdomain of ${verifiedNormalizedDomain} which has already been verified by another user. Subdomains of verified domains cannot be registered separately.` 
            };
          }
        }
      }

      // Generate salt and hash password and security answer
      const salt = database.generateSalt();
      const passwordHash = database.hashPassword(password, salt);
      const securityAnswerHash = database.hashPassword(securityAnswer, salt);

      // Insert new user with normalized domain and unverified status
      const result = await database.query(
        `INSERT INTO users (username, password_hash, security_question, security_answer_hash, salt, domain, verification_status) 
         VALUES (?, ?, ?, ?, ?, ?, 'unverified')`,
        [username, passwordHash, securityQuestion, securityAnswerHash, salt, normalizedDomain]
      );

      if (result.rows.length > 0) {
        logger.auth('New website owner registered', { userId: result.rows[0].id, username, domain: normalizedDomain, verification_status: 'unverified' });
        return { success: true, message: 'Website owner registered successfully', userId: result.rows[0].id };
      } else {
        logger.error('Error creating new website owner', null, { username, domain: normalizedDomain });
        return { success: false, error: 'Failed to register user' };
      }

    } catch (error) {
      logger.error('Error during registration', error, { username });
      return { success: false, error: 'Registration failed due to server error' };
    }
  }
}

module.exports = new RegisterModule();
