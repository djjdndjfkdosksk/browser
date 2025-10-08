
const archiver = require('archiver');
const path = require('path');
const fs = require('fs');
const logger = require('./logger');
const crypto = require('crypto');

class AdminDownloadModule {
  constructor() {
    this.allowedDirectories = ['client_content', 'data'];
    this.baseDir = path.join(__dirname, '../');
  }

  // Validate directory name against allowed list
  validateDirectory(dirName) {
    return this.allowedDirectories.includes(dirName);
  }

  // Generate secure download token
  generateDownloadToken(userId, dirName) {
    const timestamp = Date.now();
    const data = `${userId}-${dirName}-${timestamp}`;
    const token = crypto.createHash('sha256').update(data).digest('hex');
    
    return {
      token,
      timestamp,
      dirName,
      userId,
      expiresAt: timestamp + (5 * 60 * 1000) // 5 minutes expiry
    };
  }

  // Verify download token
  verifyDownloadToken(token, tokenData) {
    if (!tokenData) return false;
    
    const now = Date.now();
    if (now > tokenData.expiresAt) {
      logger.security('Download token expired', { token });
      return false;
    }
    
    const expectedToken = crypto.createHash('sha256')
      .update(`${tokenData.userId}-${tokenData.dirName}-${tokenData.timestamp}`)
      .digest('hex');
    
    return token === expectedToken;
  }

  // Create zip archive of directory
  async createZipArchive(dirName, res) {
    return new Promise((resolve, reject) => {
      try {
        if (!this.validateDirectory(dirName)) {
          logger.security('Attempt to download unauthorized directory', { dirName });
          return reject(new Error('Invalid directory'));
        }

        const dirPath = path.join(this.baseDir, dirName);
        
        if (!fs.existsSync(dirPath)) {
          logger.error('Directory not found', null, { dirPath });
          return reject(new Error('Directory not found'));
        }

        // Set response headers
        const zipFileName = `${dirName}_${Date.now()}.zip`;
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename="${zipFileName}"`);
        res.setHeader('Cache-Control', 'no-cache');

        // Create archiver instance
        const archive = archiver('zip', {
          zlib: { level: 9 } // Maximum compression
        });

        // Handle archive events
        archive.on('error', (err) => {
          logger.error('Error creating archive', err);
          reject(err);
        });

        archive.on('end', () => {
          logger.info(`Archive ${dirName} created successfully`, { 
            bytes: archive.pointer() 
          });
          resolve();
        });

        // Pipe archive data to response
        archive.pipe(res);

        // Add directory to archive - files are placed in a folder named dirName
        archive.directory(dirPath, dirName);

        // Finalize archive
        archive.finalize();

      } catch (error) {
        logger.error('Error in createZipArchive', error);
        reject(error);
      }
    });
  }

  // Get directory statistics
  async getDirectoryStats(dirName) {
    try {
      if (!this.validateDirectory(dirName)) {
        return null;
      }

      const dirPath = path.join(this.baseDir, dirName);
      
      if (!fs.existsSync(dirPath)) {
        return null;
      }

      const stats = await this.calculateDirSize(dirPath);
      
      return {
        name: dirName,
        path: dirPath,
        size: stats.size,
        sizeFormatted: this.formatBytes(stats.size),
        fileCount: stats.fileCount,
        dirCount: stats.dirCount
      };
    } catch (error) {
      logger.error('Error retrieving directory statistics', error, { dirName });
      return null;
    }
  }

  // Calculate directory size recursively
  async calculateDirSize(dirPath) {
    let size = 0;
    let fileCount = 0;
    let dirCount = 0;

    const items = fs.readdirSync(dirPath);
    
    for (const item of items) {
      const itemPath = path.join(dirPath, item);
      const stats = fs.statSync(itemPath);
      
      if (stats.isFile()) {
        size += stats.size;
        fileCount++;
      } else if (stats.isDirectory()) {
        dirCount++;
        const subDirStats = await this.calculateDirSize(itemPath);
        size += subDirStats.size;
        fileCount += subDirStats.fileCount;
        dirCount += subDirStats.dirCount;
      }
    }
    
    return { size, fileCount, dirCount };
  }

  // Format bytes to human readable
  formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  // Extract uploaded zip file to restore backup
  async extractZipBackup(zipBuffer, targetDirectory) {
    return new Promise(async (resolve, reject) => {
      try {
        if (!this.validateDirectory(targetDirectory)) {
          logger.security('Attempt to restore to unauthorized directory', { targetDirectory });
          return reject(new Error('Invalid target directory'));
        }

        const AdmZip = require('adm-zip');
        const zip = new AdmZip(zipBuffer);
        const entries = zip.getEntries();
        
        if (entries.length === 0) {
          return reject(new Error('Zip file is empty'));
        }

        // Analyze zip structure
        let rootFolders = new Set();
        let hasTargetFolder = false;
        let wrapperFolder = null;
        
        // Identify root folders in zip
        for (const entry of entries) {
          const parts = entry.entryName.split('/').filter(p => p);
          if (parts.length > 0) {
            const firstPart = parts[0];
            rootFolders.add(firstPart);
            
            // Check if target folder is directly in root
            if (firstPart === targetDirectory) {
              hasTargetFolder = true;
            }
            
            // Check if target folder is in second level (client-content-ID/client_content/)
            if (parts.length > 1 && parts[1] === targetDirectory) {
              wrapperFolder = firstPart;
            }
          }
        }

        const targetPath = path.join(this.baseDir, targetDirectory);
        
        logger.info('Zip structure analyzed', { 
          rootFolders: Array.from(rootFolders),
          hasTargetFolder,
          wrapperFolder,
          targetDirectory
        });

        // Mode 1: Zip directly contains target folder (client_content/...)
        if (hasTargetFolder) {
          logger.info('Mode 1: Direct extraction - target folder in zip root');
          
          for (const entry of entries) {
            if (entry.entryName.startsWith(targetDirectory + '/')) {
              const relativePath = entry.entryName.substring(targetDirectory.length + 1);
              
              if (relativePath) {
                const extractPath = path.join(targetPath, relativePath);
                
                if (entry.isDirectory) {
                  if (!fs.existsSync(extractPath)) {
                    fs.mkdirSync(extractPath, { recursive: true });
                  }
                } else {
                  const dirName = path.dirname(extractPath);
                  if (!fs.existsSync(dirName)) {
                    fs.mkdirSync(dirName, { recursive: true });
                  }
                  fs.writeFileSync(extractPath, entry.getData());
                }
              }
            }
          }
        }
        // Mode 2: Zip contains wrapper folder (client-content-ID/client_content/...)
        else if (wrapperFolder) {
          logger.info('Mode 2: Extract from wrapper - wrapper folder:', wrapperFolder);
          
          const prefix = wrapperFolder + '/' + targetDirectory + '/';
          
          for (const entry of entries) {
            if (entry.entryName.startsWith(prefix)) {
              const relativePath = entry.entryName.substring(prefix.length);
              
              if (relativePath) {
                const extractPath = path.join(targetPath, relativePath);
                
                if (entry.isDirectory) {
                  if (!fs.existsSync(extractPath)) {
                    fs.mkdirSync(extractPath, { recursive: true });
                  }
                } else {
                  const dirName = path.dirname(extractPath);
                  if (!fs.existsSync(dirName)) {
                    fs.mkdirSync(dirName, { recursive: true });
                  }
                  fs.writeFileSync(extractPath, entry.getData());
                }
              }
            }
          }
        }
        // Mode 3: Contents directly without folder
        else {
          logger.info('Mode 3: Direct extraction of contents without main folder');
          
          // If there's only one folder in root and it's a wrapper
          if (rootFolders.size === 1) {
            const singleRoot = Array.from(rootFolders)[0];
            const prefix = singleRoot + '/';
            
            for (const entry of entries) {
              if (entry.entryName.startsWith(prefix)) {
                const relativePath = entry.entryName.substring(prefix.length);
                
                if (relativePath) {
                  const extractPath = path.join(targetPath, relativePath);
                  
                  if (entry.isDirectory) {
                    if (!fs.existsSync(extractPath)) {
                      fs.mkdirSync(extractPath, { recursive: true });
                    }
                  } else {
                    const dirName = path.dirname(extractPath);
                    if (!fs.existsSync(dirName)) {
                      fs.mkdirSync(dirName, { recursive: true });
                    }
                    fs.writeFileSync(extractPath, entry.getData());
                  }
                }
              }
            }
          } else {
            // Extract everything directly
            zip.extractAllTo(targetPath, true);
          }
        }

        logger.info('Backup restored successfully', { 
          targetDirectory,
          extractedTo: targetPath,
          mode: hasTargetFolder ? 'direct' : (wrapperFolder ? 'wrapped' : 'plain')
        });

        resolve({
          success: true,
          message: 'Backup restored successfully',
          extractedTo: targetPath
        });

      } catch (error) {
        logger.error('Error restoring backup', error, { targetDirectory });
        reject(error);
      }
    });
  }

  // Get list of files in uploaded zip
  async getZipContents(zipBuffer) {
    try {
      const AdmZip = require('adm-zip');
      const zip = new AdmZip(zipBuffer);
      const entries = zip.getEntries();

      return entries.map(entry => ({
        name: entry.entryName,
        isDirectory: entry.isDirectory,
        size: entry.header.size,
        compressedSize: entry.header.compressedSize
      }));
    } catch (error) {
      logger.error('Error reading zip contents', error);
      throw error;
    }
  }
}

module.exports = new AdminDownloadModule();
