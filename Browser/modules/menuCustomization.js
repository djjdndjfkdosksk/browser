class MenuCustomization {
  constructor(database, logger) {
    this.database = database;
    this.logger = logger;
    this.MAX_ITEMS = 10;
    this.MAX_TEXT_LENGTH = 25;
    this.MAX_URL_LENGTH = 500;
  }

  async initialize() {
    try {
      await this.database.query(`
        CREATE TABLE IF NOT EXISTS user_menu_items (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          text VARCHAR(25) NOT NULL,
          url VARCHAR(500) NOT NULL,
          position INTEGER NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `);

      await this.database.query(`
        CREATE INDEX IF NOT EXISTS idx_menu_items_user_id 
        ON user_menu_items(user_id, position)
      `);

      this.logger.info('Menu customization module initialized');
    } catch (error) {
      this.logger.error('Error initializing menu customization module', error);
      throw error;
    }
  }

  async getMenuItems(userId) {
    try {
      const result = await this.database.query(`
        SELECT id, text, url, position
        FROM user_menu_items
        WHERE user_id = ?
        ORDER BY position ASC
      `, [userId]);

      return {
        success: true,
        items: result.rows || []
      };
    } catch (error) {
      this.logger.error('Error fetching menu items', error);
      return {
        success: false,
        error: 'Failed to fetch menu items',
        items: []
      };
    }
  }

  async saveMenuItems(userId, items) {
    try {
      if (!Array.isArray(items)) {
        return {
          success: false,
          error: 'Invalid items format'
        };
      }

      if (items.length > this.MAX_ITEMS) {
        return {
          success: false,
          error: `Maximum ${this.MAX_ITEMS} items allowed`
        };
      }

      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        
        if (!item.text || typeof item.text !== 'string') {
          return {
            success: false,
            error: `Invalid text for item ${i + 1}`
          };
        }

        if (!item.url || typeof item.url !== 'string') {
          return {
            success: false,
            error: `Invalid URL for item ${i + 1}`
          };
        }

        if (item.text.length > this.MAX_TEXT_LENGTH) {
          return {
            success: false,
            error: `Text for item ${i + 1} is too long (max ${this.MAX_TEXT_LENGTH} characters)`
          };
        }

        if (item.url.length > this.MAX_URL_LENGTH) {
          return {
            success: false,
            error: `URL for item ${i + 1} is too long (max ${this.MAX_URL_LENGTH} characters)`
          };
        }
      }

      await this.database.query('BEGIN TRANSACTION');

      try {
        await this.database.query(`
          DELETE FROM user_menu_items WHERE user_id = ?
        `, [userId]);

        for (let i = 0; i < items.length; i++) {
          const item = items[i];
          await this.database.query(`
            INSERT INTO user_menu_items (user_id, text, url, position)
            VALUES (?, ?, ?, ?)
          `, [userId, item.text.trim(), item.url.trim(), i]);
        }

        await this.database.query('COMMIT');

        return {
          success: true,
          message: 'Menu items saved successfully'
        };
      } catch (error) {
        await this.database.query('ROLLBACK');
        throw error;
      }
    } catch (error) {
      this.logger.error('Error saving menu items', error);
      return {
        success: false,
        error: 'Failed to save menu items'
      };
    }
  }

  async getMenuItemsByDomain(domain) {
    try {
      const result = await this.database.query(`
        SELECT m.text, m.url, m.position
        FROM user_menu_items m
        INNER JOIN users u ON m.user_id = u.id
        WHERE u.domain = ?
        ORDER BY m.position ASC
      `, [domain]);

      return {
        success: true,
        items: result.rows || []
      };
    } catch (error) {
      this.logger.error('Error fetching menu items by domain', error);
      return {
        success: false,
        error: 'Failed to fetch menu items',
        items: []
      };
    }
  }
}

module.exports = MenuCustomization;
