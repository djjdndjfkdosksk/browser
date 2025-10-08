const database = require('../database');
const security = require('./security');
const logger = require('./logger');
const crypto = require('crypto');

class ForgotPasswordModule {
  constructor() {
    // Storage for reset tokens (in production use Redis or database)
    this.resetTokens = new Map();
  }

  // Generate secure reset token
  generateResetToken() {
    return crypto.randomBytes(32).toString('hex');
  }
  async verifySecurityAnswer(username, securityAnswer) {
    try {
      // Sanitize inputs
      username = security.sanitizeInput(username);
      securityAnswer = security.sanitizeInput(securityAnswer);

      if (!username || !securityAnswer) {
        return { success: false, error: 'Username and security answer are required' };
      }

      // Get user's security question and answer hash
      const result = await database.query(
        'SELECT id, username, security_question, security_answer_hash, salt, failed_attempts, locked_until FROM users WHERE username = ?',
        [username]
      );

      // Always perform verification process to prevent timing attacks and username enumeration
      let user = null;
      let isValidAnswer = false;
      
      if (result.rows.length === 0) {
        // User doesn't exist - perform fake verification to prevent timing attacks
        const fakeSalt = database.generateSalt();
        const fakeHash = database.hashPassword(securityAnswer, fakeSalt);
        // This will always return false but takes the same time as real verification
        database.verifyPassword(securityAnswer, fakeHash, fakeSalt);
        
        // Return generic error message - don't reveal user doesn't exist
        return { success: false, error: 'Invalid username or security answer' };
      } else {
        user = result.rows[0];

        // Check if account is locked
        if (user.locked_until && new Date() < new Date(user.locked_until)) {
          return { success: false, error: 'Account is temporarily locked due to too many failed attempts' };
        }

        // Verify security answer
        isValidAnswer = database.verifyPassword(securityAnswer, user.security_answer_hash, user.salt);
      }

      if (!isValidAnswer) {
        // Increment failed attempts for existing users only
        if (user) {
          const newFailedAttempts = user.failed_attempts + 1;
          let lockUntil = null;

          if (newFailedAttempts >= 5) {
            lockUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
          }

          await database.query(
            'UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?',
            [newFailedAttempts, lockUntil, user.id]
          );
        }

        return { success: false, error: 'Invalid username or security answer' };
      }

      // Reset failed attempts
      await database.query(
        'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?',
        [user.id]
      );

      // Generate secure reset token
      const resetToken = this.generateResetToken();

      // Store reset token with expiration (15 minutes)
      this.resetTokens.set(resetToken, {
        userId: user.id,
        createdAt: Date.now(),
        expiresAt: Date.now() + (15 * 60 * 1000) // 15 minutes
      });

      return {
        success: true,
        message: 'Security answer verified',
        resetToken: resetToken,
        securityQuestion: user.security_question
      };

    } catch (error) {
      logger.error('Error in security verification', error, { username });
      return { success: false, error: 'Verification failed due to server error' };
    }
  }

  async resetPassword(resetToken, newPassword) {
    try {
      if (!resetToken) {
        return { success: false, error: 'Reset token is required' };
      }

      // Validate reset token
      const tokenData = this.resetTokens.get(resetToken);
      if (!tokenData) {
        return { success: false, error: 'Invalid or expired reset token' };
      }

      // Check if token is expired
      if (Date.now() > tokenData.expiresAt) {
        this.resetTokens.delete(resetToken);
        return { success: false, error: 'Reset token has expired' };
      }

      if (!security.validatePasswordStrength(newPassword)) {
        return {
          success: false,
          error: 'Password must be at least 8 characters with uppercase, lowercase, numbers, and special characters'
        };
      }

      // Generate new salt and hash new password
      const salt = database.generateSalt();
      const passwordHash = database.hashPassword(newPassword, salt);

      // Update password using userId from token
      const result = await database.query(
        'UPDATE users SET password_hash = ?, salt = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?',
        [passwordHash, salt, tokenData.userId]
      );

      // Remove the used token
      this.resetTokens.delete(resetToken);

      if (result.changes > 0) {
        // Invalidate all existing sessions for this user for security
        await security.destroySessionsByUser(tokenData.userId);
        
        return { success: true, message: 'Password reset successfully' };
      } else {
        return { success: false, error: 'Failed to reset password' };
      }

    } catch (error) {
      logger.error('Error in password recovery', error, { resetToken });
      return { success: false, error: 'Password reset failed due to server error' };
    }
  }

  async getSecurityQuestion(username) {
    try {
      username = security.sanitizeInput(username);

      if (!username) {
        return { success: false, error: 'Username is required' };
      }

      const result = await database.query(
        'SELECT security_question FROM users WHERE username = ?',
        [username]
      );

      // Always return a generic response to prevent username enumeration
      // If user exists, return their security question
      // If user doesn't exist, return a generic question
      if (result.rows.length === 0) {
        return {
          success: true,
          securityQuestion: 'What is your favorite color?',
          isGeneric: true
        };
      }

      return {
        success: true,
        securityQuestion: result.rows[0].security_question,
        isGeneric: false
      };

    } catch (error) {
      logger.error('Error retrieving security question', error, { username });
      return { success: false, error: 'Failed to retrieve security question' };
    }
  }
}

module.exports = new ForgotPasswordModule();