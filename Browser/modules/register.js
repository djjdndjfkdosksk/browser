
const database = require('../database');
const security = require('./security');
const logger = require('./logger');

class RegisterModule {
  async registerUser(username, password, securityQuestion, securityAnswer) {
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

      // Check if username already exists
      const existingUser = await database.query(
        'SELECT id FROM users WHERE username = ?',
        [username]
      );

      if (existingUser.rows.length > 0) {
        return { success: false, error: 'Username already exists' };
      }

      // Generate salt and hash password and security answer
      const salt = database.generateSalt();
      const passwordHash = database.hashPassword(password, salt);
      const securityAnswerHash = database.hashPassword(securityAnswer, salt);

      // Insert new user
      const result = await database.query(
        `INSERT INTO users (username, password_hash, security_question, security_answer_hash, salt) 
         VALUES (?, ?, ?, ?, ?)`,
        [username, passwordHash, securityQuestion, securityAnswerHash, salt]
      );

      if (result.rows.length > 0) {
        logger.auth('کاربر جدید ثبت شد', { userId: result.rows[0].id, username });
        return { success: true, message: 'User registered successfully', userId: result.rows[0].id };
      } else {
        logger.error('خطا در ایجاد کاربر جدید', null, { username });
        return { success: false, error: 'Failed to register user' };
      }

    } catch (error) {
      logger.error('خطا در ثبت نام', error, { username });
      return { success: false, error: 'Registration failed due to server error' };
    }
  }
}

module.exports = new RegisterModule();
