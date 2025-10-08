
const security = require('./security');
const logger = require('./logger');

class SessionCheckModule {
  // Check if user already has active session
  async checkActiveSession(req, res, next) {
    try {
      const sessionId = req.headers['x-session-id'] || req.cookies?.sessionId;
      const csrfToken = req.headers['x-csrf-token'] || req.cookies?.csrfToken;

      if (!sessionId || !csrfToken) {
        return next();
      }

      const session = await security.validateSession(sessionId);
      if (!session) {
        return next();
      }

      const isValidCSRF = await security.validateCSRF(csrfToken, sessionId);
      if (!isValidCSRF) {
        return next();
      }

      // User has valid session, attach to request
      req.user = { id: session.userId };
      req.userId = session.userId;
      req.hasActiveSession = true;
      
      next();
    } catch (error) {
      logger.error('Error in session check middleware', error);
      next();
    }
  }

  // Redirect to dashboard if already authenticated
  redirectIfAuthenticated(req, res, next) {
    if (req.hasActiveSession) {
      logger.info('User already authenticated, redirecting to dashboard', { userId: req.userId });
      return res.redirect('/dashboard');
    }
    next();
  }
}

module.exports = new SessionCheckModule();
