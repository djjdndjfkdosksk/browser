
// Search History Management Module
class SearchHistoryManager {
    constructor() {
        this.SEARCH_HISTORY_KEY = 'searchHistory';
        this.MAX_HISTORY_ITEMS = 15;
    }

    getSearchHistory() {
        try {
            const history = localStorage.getItem(this.SEARCH_HISTORY_KEY);
            return history ? JSON.parse(history) : [];
        } catch (error) {
            console.error('Error loading search history:', error);
            return [];
        }
    }

    hashQuery(query) {
        // Simple hash function for query deduplication
        let hash = 0;
        for (let i = 0; i < query.length; i++) {
            const char = query.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return Math.abs(hash).toString();
    }

    saveSearchToHistory(query, requestId) {
        if (!query || typeof query !== 'string') return;
        
        // Sanitize query before saving
        const sanitizedQuery = this.sanitizeQuery(query);
        if (!sanitizedQuery) return;

        try {
            const history = this.getSearchHistory();
            const queryHash = this.hashQuery(sanitizedQuery.toLowerCase().trim());
            const timestamp = Date.now();
            
            // Check if query already exists
            const existingIndex = history.findIndex(item => item.queryHash === queryHash);
            
            if (existingIndex !== -1) {
                // Update existing entry timestamp and move to top
                history[existingIndex].timestamp = timestamp;
                history[existingIndex].requestId = this.sanitizeRequestId(requestId);
                const updatedItem = history.splice(existingIndex, 1)[0];
                history.unshift(updatedItem);
            } else {
                // Add new search to the beginning
                history.unshift({ 
                    query: sanitizedQuery, 
                    queryHash, 
                    requestId: this.sanitizeRequestId(requestId), 
                    timestamp 
                });
            }
            
            // Keep only last items
            const newHistory = history.slice(0, this.MAX_HISTORY_ITEMS);
            localStorage.setItem(this.SEARCH_HISTORY_KEY, JSON.stringify(newHistory));
            this.renderSearchHistory();
        } catch (error) {
            console.error('Error saving search history:', error);
        }
    }

    clearSearchHistory() {
        try {
            localStorage.removeItem(this.SEARCH_HISTORY_KEY);
            this.renderSearchHistory();
        } catch (error) {
            console.error('Error clearing search history:', error);
        }
    }

    formatTimeAgo(timestamp) {
        const now = Date.now();
        const diff = now - timestamp;
        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(diff / 3600000);
        const days = Math.floor(diff / 86400000);
        
        if (minutes < 1) return 'Just now';
        if (minutes < 60) return `${minutes}m ago`;
        if (hours < 24) return `${hours}h ago`;
        if (days < 7) return `${days}d ago`;
        return new Date(timestamp).toLocaleDateString();
    }

    renderSearchHistory() {
        const historyItemsDiv = document.getElementById('historyItems');
        if (!historyItemsDiv) return;

        const history = this.getSearchHistory();

        if (history.length === 0) {
            historyItemsDiv.innerHTML = '<div class="no-history">No search history yet.</div>';
            return;
        }

        let html = '';
        history.forEach((item, index) => {
            if (!item.query) return; // Skip invalid items
            
            const timeAgo = this.formatTimeAgo(item.timestamp);
            const searchNumber = String(index + 1).padStart(2, '0');
            const escapedQuery = this.escapeHtml(item.query);
            
            html += `
                <div class="history-item" onclick="window.searchHistory.performSearchFromHistory('${escapedQuery.replace(/'/g, "\\'")}')">
                    <div class="history-item-icon">${searchNumber}</div>
                    <div class="history-content">
                        <div class="history-query">${escapedQuery}</div>
                        <div class="history-date">${this.escapeHtml(timeAgo)}</div>
                    </div>
                </div>
            `;
        });
        historyItemsDiv.innerHTML = html;
    }

    performSearchFromHistory(query) {
        if (!query || typeof query !== 'string') return;
        
        // Close dropdown first
        this.toggleSearchHistory();
        
        // Set search input
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.value = query;
            // Perform search using search manager
            if (window.searchManager) {
                window.searchManager.performSearch(query);
            }
        }
    }

    toggleSearchHistory() {
        const dropdown = document.getElementById('searchHistoryDropdown');
        if (!dropdown) return;

        const isShowing = dropdown.classList.contains('show');
        
        if (isShowing) {
            dropdown.classList.remove('show');
        } else {
            dropdown.classList.add('show');
            this.renderSearchHistory();
        }
    }

    // Security functions
    sanitizeQuery(query) {
        if (typeof query !== 'string') return '';
        
        let sanitized = query.trim();
        
        // Remove dangerous characters
        sanitized = sanitized.replace(/<script[^>]*>.*?<\/script>/gi, '');
        sanitized = sanitized.replace(/<[^>]*>/g, '');
        
        // Limit length
        if (sanitized.length > 200) {
            sanitized = sanitized.substring(0, 200);
        }
        
        return sanitized;
    }

    sanitizeRequestId(requestId) {
        if (typeof requestId !== 'string') return '';
        
        // Only allow alphanumeric characters and dashes
        return requestId.replace(/[^a-zA-Z0-9-]/g, '').substring(0, 100);
    }

    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Global functions for inline event handlers
function toggleSearchHistory() {
    if (window.searchHistory) {
        window.searchHistory.toggleSearchHistory();
    }
}

function clearSearchHistory() {
    if (window.searchHistory) {
        window.searchHistory.clearSearchHistory();
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.searchHistory = new SearchHistoryManager();
});
