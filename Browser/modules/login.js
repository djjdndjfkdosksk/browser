const database = require('../database');
const security = require('./security');
const logger = require('./logger');

class LoginModule {
  async authenticateUser(username, password, req = null) {
    try {
      // Sanitize input
      username = security.sanitizeInput(username);

      if (!username || !password) {
        return { success: false, error: 'Username and password are required' };
      }

      // Get user from database
      const result = await database.query(
        'SELECT id, username, password_hash, salt, failed_attempts, locked_until FROM users WHERE username = ?',
        [username]
      );

      if (result.rows.length === 0) {
        return { success: false, error: 'Invalid username or password' };
      }

      const user = result.rows[0];

      // Check if account is locked
      if (user.locked_until && new Date() < new Date(user.locked_until)) {
        return { success: false, error: 'Account is temporarily locked due to too many failed attempts' };
      }

      // Verify password
      const isValidPassword = database.verifyPassword(password, user.password_hash, user.salt);

      if (!isValidPassword) {
        // Increment failed attempts
        const newFailedAttempts = user.failed_attempts + 1;
        let lockUntil = null;

        // Lock account after 5 failed attempts for 30 minutes
        if (newFailedAttempts >= 5) {
          lockUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
        }

        await database.query(
          'UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?',
          [newFailedAttempts, lockUntil, user.id]
        );

        return { success: false, error: 'Invalid username or password' };
      }

      // Reset failed attempts and update last login
      await database.query(
        'UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE id = ?',
        [user.id]
      );

      // Create secure session
      const session = await security.createSession(user.id, req?.ip, req?.get('User-Agent'));

      return {
        success: true,
        message: 'Login successful',
        user: { id: user.id, username: user.username },
        session: session
      };

    } catch (error) {
      console.error('Login error:', error);
      return { success: false, error: 'Login failed due to server error' };
    }
  }

  async logout(sessionId) {
    try {
      await security.destroySession(sessionId);
      logger.auth('کاربر با موفقیت خروج کرد', { sessionId });
      return { success: true, message: 'Logged out successfully' };
    } catch (error) {
      logger.error('خطا در خروج', error, { sessionId });
      return { success: false, error: 'Logout failed' };
    }
  }
}

module.exports = new LoginModule();
