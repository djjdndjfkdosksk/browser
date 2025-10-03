
const fs = require('fs');
const path = require('path');

class ClientFileManager {
  constructor() {
    this.baseDir = path.join(__dirname, '../../');
    this.contentDir = path.join(this.baseDir, 'client_content');
    this.initializeDirectories();
  }

  // Initialize required directories
  initializeDirectories() {
    if (!fs.existsSync(this.contentDir)) {
      fs.mkdirSync(this.contentDir, { recursive: true });
      console.log(`📁 Created directory: ${this.contentDir}`);
    }
  }

  // Load content by request ID
  loadContent(requestId) {
    try {
      const firstTwo = requestId.substring(0, 2);
      const secondTwo = requestId.substring(2, 4);
      const fileName = `${requestId}.json`;
      const filePath = path.join(this.contentDir, firstTwo, secondTwo, fileName);
      
      if (fs.existsSync(filePath)) {
        const fileData = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(fileData);
      }
      return null;
    } catch (error) {
      console.error(`❌ Error loading content: ${error.message}`);
      return null;
    }
  }

  // Get file statistics
  getFileStats(requestId) {
    try {
      const firstTwo = requestId.substring(0, 2);
      const secondTwo = requestId.substring(2, 4);
      const fileName = `${requestId}.json`;
      const filePath = path.join(this.contentDir, firstTwo, secondTwo, fileName);
      
      return {
        exists: fs.existsSync(filePath),
        size: fs.existsSync(filePath) ? fs.statSync(filePath).size : 0,
        path: filePath
      };
    } catch (error) {
      console.error(`❌ Error getting file stats: ${error.message}`);
      return null;
    }
  }

  // Delete file by request ID
  deleteFile(requestId) {
    try {
      const firstTwo = requestId.substring(0, 2);
      const secondTwo = requestId.substring(2, 4);
      const fileName = `${requestId}.json`;
      const filePath = path.join(this.contentDir, firstTwo, secondTwo, fileName);
      
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        console.log(`🗑️ Deleted file: ${filePath}`);
        return true;
      }
      return false;
    } catch (error) {
      console.error(`❌ Error deleting file: ${error.message}`);
      throw error;
    }
  }
}

module.exports = ClientFileManager;
