const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

class Database {
  constructor() {
    this.dbPath = path.join(__dirname, 'data', 'users.db');
    this.db = null;
    this.isInitialized = false;
  }

  async init() {
    try {
      if (this.isInitialized) return;

      // Create data directory if it doesn't exist
      const dataDir = path.dirname(this.dbPath);
      if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
      }

      // Create SQLite database connection
      this.db = new sqlite3.Database(this.dbPath);

      // Wait for database to be ready
      await new Promise((resolve, reject) => {
        this.db.serialize(() => {
          resolve();
        });
      });

      // Create users table
      await this.query(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username VARCHAR(50) UNIQUE NOT NULL,
          password_hash VARCHAR(255) NOT NULL,
          security_question TEXT,
          security_answer_hash VARCHAR(255),
          salt VARCHAR(255) NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          last_login DATETIME,
          failed_attempts INTEGER DEFAULT 0,
          locked_until DATETIME
        )
      `);

      // Create sessions table
      await this.query(`
        CREATE TABLE IF NOT EXISTS sessions (
          session_id VARCHAR(64) PRIMARY KEY,
          user_id INTEGER NOT NULL,
          csrf_token VARCHAR(64) NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
          expires_at DATETIME NOT NULL,
          is_active BOOLEAN DEFAULT 1,
          ip_address VARCHAR(45),
          user_agent TEXT,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `);

      // Create searches table
      await this.query(`
        CREATE TABLE IF NOT EXISTS searches (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          request_id VARCHAR(64) UNIQUE NOT NULL,
          user_id INTEGER NOT NULL,
          query TEXT NOT NULL,
          result TEXT,
          result_urls TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `);

      // Create index for better performance
      await this.query(`
        CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)
      `);

      await this.query(`
        CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)
      `);

      await this.query(`
        CREATE INDEX IF NOT EXISTS idx_searches_user_id ON searches(user_id)
      `);

      await this.query(`
        CREATE INDEX IF NOT EXISTS idx_searches_request_id ON searches(request_id)
      `);

      this.isInitialized = true;
      console.log('📊 SQLite database initialized successfully at:', this.dbPath);
    } catch (error) {
      console.error('Database initialization error:', error);
      throw error;
    }
  }

  async query(sql, params = []) {
    return new Promise((resolve, reject) => {
      if (!this.db) {
        return reject(new Error('Database not initialized'));
      }

      if (sql.trim().toUpperCase().startsWith('SELECT')) {
        this.db.all(sql, params, (err, rows) => {
          if (err) {
            reject(err);
          } else {
            resolve({ rows });
          }
        });
      } else if (sql.trim().toUpperCase().startsWith('INSERT')) {
        this.db.run(sql, params, function(err) {
          if (err) {
            reject(err);
          } else {
            resolve({
              rows: [{ id: this.lastID }],
              insertId: this.lastID,
              changes: this.changes
            });
          }
        });
      } else {
        this.db.run(sql, params, function(err) {
          if (err) {
            reject(err);
          } else {
            resolve({
              changes: this.changes,
              rows: []
            });
          }
        });
      }
    });
  }

  generateSalt() {
    return crypto.randomBytes(32).toString('hex');
  }

  hashPassword(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  }

  verifyPassword(password, hash, salt) {
    const hashedPassword = this.hashPassword(password, salt);
    return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(hashedPassword));
  }

  async close() {
    return new Promise((resolve) => {
      if (this.db) {
        this.db.close((err) => {
          if (err) {
            console.error('Error closing database:', err);
          }
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  // Additional method to backup data (optional)
  async exportData() {
    try {
      const result = await this.query('SELECT * FROM users');
      return result.rows;
    } catch (error) {
      console.error('Export data error:', error);
      return [];
    }
  }

  // Method to get database statistics
  async getStats() {
    try {
      const result = await this.query('SELECT COUNT(*) as user_count FROM users');
      return {
        totalUsers: parseInt(result.rows[0].user_count),
        databaseType: 'SQLite Local Database',
        databasePath: this.dbPath,
        status: 'Connected'
      };
    } catch (error) {
      return {
        totalUsers: 0,
        databaseType: 'SQLite Local Database',
        databasePath: this.dbPath,
        status: 'Error'
      };
    }
  }
}

module.exports = new Database();