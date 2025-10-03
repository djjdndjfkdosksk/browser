const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');

// Migration script to consolidate agent-client data into Browser database
// This implements the architect's data migration strategy

async function migrateAgentClientData() {
  console.log('🔄 Starting agent-client data migration...');
  
  // Initialize Browser database (singleton instance)
  const browserDB = require('./database');
  const ClientDatabase = require('./modules/client/database');
  
  await browserDB.init();
  
  const clientDB = new ClientDatabase();
  await clientDB.initClientTables();
  
  // Connect to agent-client database
  const agentClientDbPath = path.join(__dirname, '../agent-client/client.db');
  if (!fs.existsSync(agentClientDbPath)) {
    console.log('⚠️ Agent-client database not found, skipping migration');
    return;
  }
  
  const agentClientDB = new sqlite3.Database(agentClientDbPath);
  
  try {
    console.log('📂 Step 1: Moving JSON files from agent-client to Browser/client_content...');
    await moveJsonFiles();
    
    console.log('📊 Step 2: Scanning and indexing all JSON files...');
    await scanAndIndexJsonFiles(clientDB);
    
    console.log('🔄 Step 3: Migrating agent-client database records...');
    await migrateAgentClientDatabase(agentClientDB, clientDB);
    
    console.log('✅ Migration completed successfully!');
    await verifyMigration(clientDB);
    
  } catch (error) {
    console.error('❌ Migration failed:', error);
    throw error;
  } finally {
    agentClientDB.close();
  }
}

// Move JSON files from agent-client directory to Browser/client_content
async function moveJsonFiles() {
  const agentClientDir = path.join(__dirname, '../agent-client');
  const browserContentDir = path.join(__dirname, 'client_content');
  
  if (!fs.existsSync(browserContentDir)) {
    fs.mkdirSync(browserContentDir, { recursive: true });
  }
  
  let movedCount = 0;
  let skippedCount = 0;
  
  // Scan agent-client directory for JSON files
  function scanDirectory(dirPath) {
    const items = fs.readdirSync(dirPath);
    
    for (const item of items) {
      const fullPath = path.join(dirPath, item);
      const stat = fs.statSync(fullPath);
      
      if (stat.isDirectory() && item.length === 2 && item.match(/^[a-f0-9]{2}$/)) {
        // This is a hex directory (like '30', '77', etc.)
        scanDirectory(fullPath);
      } else if (stat.isFile() && item.endsWith('.json')) {
        // This is a JSON file
        const relativePath = path.relative(agentClientDir, fullPath);
        const targetPath = path.join(browserContentDir, relativePath);
        
        // Create target directory if needed
        const targetDir = path.dirname(targetPath);
        if (!fs.existsSync(targetDir)) {
          fs.mkdirSync(targetDir, { recursive: true });
        }
        
        // Check if file already exists in Browser
        if (fs.existsSync(targetPath)) {
          console.log(`⏭️ Skipping ${relativePath} - already exists in Browser`);
          skippedCount++;
        } else {
          // Copy file to Browser directory
          fs.copyFileSync(fullPath, targetPath);
          console.log(`📁 Moved ${relativePath} to Browser/client_content`);
          movedCount++;
        }
      }
    }
  }
  
  scanDirectory(agentClientDir);
  console.log(`📁 File migration summary: ${movedCount} moved, ${skippedCount} skipped`);
}

// Scan all JSON files and index them in the Browser database
async function scanAndIndexJsonFiles(clientDB) {
  const contentDir = path.join(__dirname, 'client_content');
  let indexedCount = 0;
  
  function scanDirectory(dirPath) {
    if (!fs.existsSync(dirPath)) return [];
    
    const items = fs.readdirSync(dirPath);
    const jsonFiles = [];
    
    for (const item of items) {
      const fullPath = path.join(dirPath, item);
      const stat = fs.statSync(fullPath);
      
      if (stat.isDirectory()) {
        jsonFiles.push(...scanDirectory(fullPath));
      } else if (item.endsWith('.json')) {
        jsonFiles.push(fullPath);
      }
    }
    return jsonFiles;
  }
  
  const jsonFiles = scanDirectory(contentDir);
  console.log(`🔍 Found ${jsonFiles.length} JSON files to index`);
  
  for (const filePath of jsonFiles) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const jsonData = JSON.parse(content);
      
      if (jsonData.urlHash && jsonData.url) {
        const urlHash = jsonData.urlHash;
        const originalUrl = jsonData.url;
        const relativePath = path.relative(path.join(__dirname), filePath);
        
        // Extract word counts from filtered data
        const totalWords = jsonData.filteredData?.totalWords || 0;
        const mainContentWords = jsonData.filteredData?.mainContentWords || 0;
        
        // Insert or update URL hash with file metadata
        await clientDB.database.query(`
          INSERT OR REPLACE INTO url_hashes (
            url_hash, original_url, last_seen, access_count, 
            crawl_status, json_file_path, total_words, main_content_words,
            summary_status
          ) VALUES (?, ?, CURRENT_TIMESTAMP, 
            COALESCE((SELECT access_count FROM url_hashes WHERE url_hash = ?) + 1, 1),
            'completed', ?, ?, ?,
            COALESCE((SELECT summary_status FROM url_hashes WHERE url_hash = ?), 'pending')
          )
        `, [urlHash, originalUrl, urlHash, relativePath, totalWords, mainContentWords, urlHash]);
        
        indexedCount++;
        if (indexedCount % 10 === 0) {
          console.log(`📊 Indexed ${indexedCount} files...`);
        }
      }
    } catch (error) {
      console.error(`❌ Error processing file ${filePath}:`, error.message);
    }
  }
  
  console.log(`✅ Indexed ${indexedCount} JSON files`);
}

// Migrate data from agent-client database to Browser database
async function migrateAgentClientDatabase(agentClientDB, clientDB) {
  return new Promise((resolve, reject) => {
    // Get all json_files from agent-client database
    agentClientDB.all(
      `SELECT * FROM json_files`,
      [],
      async (err, jsonFiles) => {
        if (err) {
          reject(err);
          return;
        }
        
        console.log(`📋 Found ${jsonFiles.length} records in agent-client json_files table`);
        
        try {
          // Update url_hashes with status information from agent-client
          for (const file of jsonFiles) {
            const urlHash = file.id; // In agent-client, id is the urlHash
            
            // Map agent-client status to summary_status
            let summaryStatus = 'pending';
            if (file.status === 'summarized') summaryStatus = 'summarized';
            else if (file.status === 'queued') summaryStatus = 'queued';
            
            await clientDB.database.query(`
              UPDATE url_hashes 
              SET summary_status = ?, summary_attempts = ?
              WHERE url_hash = ?
            `, [summaryStatus, 0, urlHash]);
            
            if (summaryStatus === 'summarized') {
              await clientDB.database.query(`
                UPDATE url_hashes 
                SET summary_completed_at = ?
                WHERE url_hash = ?
              `, [file.processed_at || new Date().toISOString(), urlHash]);
            }
          }
          
          // Get all summaries from agent-client database
          agentClientDB.all(
            `SELECT * FROM summaries`,
            [],
            async (err, summaries) => {
              if (err) {
                reject(err);
                return;
              }
              
              console.log(`📝 Found ${summaries.length} summaries in agent-client database`);
              
              // Migrate summaries to Browser database
              for (const summary of summaries) {
                const urlHash = summary.file_id; // file_id is the urlHash
                
                // Check if summary already exists
                const existingResult = await clientDB.database.query(`
                  SELECT id FROM summaries WHERE url_hash = ?
                `, [urlHash]);
                
                if (existingResult.rows.length === 0) {
                  // Insert new summary
                  await clientDB.database.query(`
                    INSERT INTO summaries (url_hash, summary_text, created_at)
                    VALUES (?, ?, ?)
                  `, [urlHash, summary.summary_text, summary.created_at]);
                  
                  console.log(`📝 Migrated summary for ${urlHash}`);
                } else {
                  console.log(`⏭️ Summary for ${urlHash} already exists`);
                }
              }
              
              resolve();
            }
          );
        } catch (error) {
          reject(error);
        }
      }
    );
  });
}

// Verify migration results
async function verifyMigration(clientDB) {
  console.log('\n📊 =============== MIGRATION VERIFICATION ===============');
  
  // Get statistics from Browser database
  const urlStats = await clientDB.database.query(`
    SELECT 
      COUNT(*) as total_urls,
      SUM(CASE WHEN crawl_status = 'completed' THEN 1 ELSE 0 END) as crawled_urls,
      SUM(CASE WHEN json_file_path IS NOT NULL THEN 1 ELSE 0 END) as urls_with_files,
      SUM(CASE WHEN summary_status = 'summarized' THEN 1 ELSE 0 END) as summarized_urls,
      SUM(CASE WHEN summary_status = 'pending' THEN 1 ELSE 0 END) as pending_summary_urls
    FROM url_hashes
  `);
  
  const summaryStats = await clientDB.database.query(`
    SELECT COUNT(*) as total_summaries FROM summaries
  `);
  
  const stats = urlStats.rows[0];
  const summaryCount = summaryStats.rows[0].total_summaries;
  
  console.log(`🔗 Total URLs: ${stats.total_urls}`);
  console.log(`✅ Crawled URLs: ${stats.crawled_urls}`);
  console.log(`📁 URLs with JSON files: ${stats.urls_with_files}`);
  console.log(`📝 Summarized URLs: ${stats.summarized_urls}`);
  console.log(`⏳ Pending summary URLs: ${stats.pending_summary_urls}`);
  console.log(`📋 Total summaries: ${summaryCount}`);
  console.log('========================================================\n');
  
  if (stats.urls_with_files > 0) {
    console.log('✅ Migration successful - JSON files are indexed');
  }
  
  if (summaryCount > 0) {
    console.log('✅ Migration successful - Summaries migrated');
  }
}

// Run migration if called directly
if (require.main === module) {
  migrateAgentClientData().catch(console.error);
}

module.exports = { migrateAgentClientData };
