const fs = require('fs');
const path = require('path');

class Logger {
  constructor() {
    this.logDir = path.join(__dirname, '..', 'logs');
    this.ensureLogDirectory();
  }

  ensureLogDirectory() {
    if (!fs.existsSync(this.logDir)) {
      fs.mkdirSync(this.logDir, { recursive: true });
    }
  }

  formatMessage(level, message, metadata = {}) {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      level,
      message,
      ...metadata,
      pid: process.pid
    };
    return JSON.stringify(logEntry);
  }

  writeToFile(filename, message) {
    const logPath = path.join(this.logDir, filename);
    const logLine = message + '\n';
    
    fs.appendFile(logPath, logLine, (err) => {
      if (err) {
        console.error('Error saving log:', err);
      }
    });
  }

  info(message, metadata = {}) {
    const formattedMessage = this.formatMessage('INFO', message, metadata);
    console.log(`ℹ️  ${message}`);
    this.writeToFile('app.log', formattedMessage);
  }

  warn(message, metadata = {}) {
    const formattedMessage = this.formatMessage('WARN', message, metadata);
    console.warn(`⚠️  ${message}`);
    this.writeToFile('app.log', formattedMessage);
  }

  error(message, error = null, metadata = {}) {
    const errorData = error ? {
      errorMessage: error.message,
      errorStack: error.stack,
      ...metadata
    } : metadata;
    
    const formattedMessage = this.formatMessage('ERROR', message, errorData);
    console.error(`❌ ${message}`);
    this.writeToFile('error.log', formattedMessage);
    this.writeToFile('app.log', formattedMessage);
  }

  security(message, metadata = {}) {
    const formattedMessage = this.formatMessage('SECURITY', message, metadata);
    console.warn(`🔒 SECURITY: ${message}`);
    this.writeToFile('security.log', formattedMessage);
    this.writeToFile('app.log', formattedMessage);
  }

  auth(message, metadata = {}) {
    const formattedMessage = this.formatMessage('AUTH', message, metadata);
    console.log(`🔐 AUTH: ${message}`);
    this.writeToFile('auth.log', formattedMessage);
    this.writeToFile('app.log', formattedMessage);
  }

  database(message, metadata = {}) {
    const formattedMessage = this.formatMessage('DATABASE', message, metadata);
    console.log(`🗄️  DB: ${message}`);
    this.writeToFile('database.log', formattedMessage);
    this.writeToFile('app.log', formattedMessage);
  }

  // Monitoring helper
  logRequest(req, res, next) {
    const start = Date.now();
    const { method, url, ip } = req;
    
    res.on('finish', () => {
      const duration = Date.now() - start;
      const { statusCode } = res;
      
      const logLevel = statusCode >= 400 ? 'WARN' : 'INFO';
      const message = `${method} ${url} - ${statusCode} - ${duration}ms`;
      
      if (logLevel === 'WARN') {
        this.warn(message, { method, url, statusCode, duration, ip });
      } else {
        this.info(message, { method, url, statusCode, duration, ip });
      }
    });
    
    next();
  }

  // Performance monitoring
  startTimer(label) {
    return {
      label,
      startTime: process.hrtime()
    };
  }

  endTimer(timer) {
    const [seconds, nanoseconds] = process.hrtime(timer.startTime);
    const milliseconds = Math.round((seconds * 1000) + (nanoseconds / 1000000));
    
    this.info(`Operation ${timer.label} completed in ${milliseconds}ms`, {
      operation: timer.label,
      duration: milliseconds
    });
    
    return milliseconds;
  }
}

module.exports = new Logger();