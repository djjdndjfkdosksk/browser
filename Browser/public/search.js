
// Search functionality module
class SearchManager {
    constructor() {
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        // Search input event listeners
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.addEventListener('focus', this.handleSearchInputFocus.bind(this));
            searchInput.addEventListener('input', this.handleSearchInputChange.bind(this));
        }

        // Click outside to close dropdown
        document.addEventListener('click', this.handleDocumentClick.bind(this));
    }

    // Real-time validation as user types
    handleSearchInputChange(event) {
        const input = event.target.value;
        const searchWrapper = document.querySelector('.search-wrapper');
        let validationMessage = document.getElementById('searchValidationMessage');
        
        if (!validationMessage) {
            // Create validation message element if it doesn't exist
            const msgDiv = document.createElement('div');
            msgDiv.id = 'searchValidationMessage';
            searchWrapper.appendChild(msgDiv);
        }

        validationMessage = document.getElementById('searchValidationMessage');
        const searchBox = event.target.closest('.search-box');
        
        if (input.trim().length > 0) {
            const validation = this.validateSearchInput(input);
            if (!validation.valid) {
                validationMessage.textContent = validation.messageEn || validation.message;
                validationMessage.style.display = 'block';
                searchBox.classList.add('invalid');
            } else {
                validationMessage.style.display = 'none';
                searchBox.classList.remove('invalid');
            }
        } else {
            validationMessage.style.display = 'none';
            searchBox.classList.remove('invalid');
        }
    }

    // Perform search with security checks
    async performSearch(query) {
        if (!query || query.trim().length === 0) return;

        // Validate input first
        const validation = this.validateSearchInput(query);
        if (!validation.valid) {
            this.showError(validation.message);
            return;
        }

        // Sanitize input
        const sanitizedQuery = this.sanitizeSearchQuery(query);
        if (!sanitizedQuery) {
            this.showError('Invalid search query');
            return;
        }

        const resultsDiv = document.getElementById('searchResults');
        const containerDiv = document.getElementById('resultsContainer');

        // Show loading
        containerDiv.innerHTML = '<div class="loading">Searching...</div>';
        resultsDiv.style.display = 'block';

        try {
            const response = await fetch('/api/search', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-session-id': localStorage.getItem('sessionId'),
                    'x-csrf-token': localStorage.getItem('csrfToken')
                },
                body: JSON.stringify({ query: sanitizedQuery })
            });

            const result = await response.json();

            if (result.success && result.data) {
                this.displaySearchResults(result.data, result.requestId);
                // Save search to history
                window.searchHistory.saveSearchToHistory(sanitizedQuery, result.requestId);
            } else {
                containerDiv.innerHTML = '<div class="error">Search failed. Please try again.</div>';
            }
        } catch (error) {
            console.error('Search error:', error);
            containerDiv.innerHTML = '<div class="error">Network error. Please check your connection.</div>';
        }
    }

    // Sanitize search query for security
    sanitizeSearchQuery(query) {
        if (typeof query !== 'string') return '';
        
        // Remove dangerous characters and patterns
        let sanitized = query.trim();
        
        // Remove script tags and dangerous HTML
        sanitized = sanitized.replace(/<script[^>]*>.*?<\/script>/gi, '');
        sanitized = sanitized.replace(/<[^>]*>/g, '');
        
        // Limit length
        if (sanitized.length > 500) {
            sanitized = sanitized.substring(0, 500);
        }
        
        return sanitized;
    }

    // Validate input: only English letters, numbers, and limited special characters
    validateSearchInput(query) {
        if (!query || typeof query !== 'string') {
            return { valid: false, message: 'Search is empty', messageEn: 'Search is empty' };
        }

        // Check for non-English characters (Persian, Arabic, etc.)
        const nonEnglishPattern = /[^\x00-\x7F]/;
        if (nonEnglishPattern.test(query)) {
            return { 
                valid: false, 
                message: 'Only English characters are supported',
                messageEn: 'Only English characters are supported'
            };
        }

        // Allowed characters: a-z, A-Z, 0-9, space, and limited special chars: . , ? ! - _ + @ # 
        const allowedPattern = /^[a-zA-Z0-9\s.,?!\-_+@#]+$/;
        if (!allowedPattern.test(query)) {
            return { 
                valid: false, 
                message: 'Only English letters, numbers, and limited special characters (.,?!-_+@#) are allowed',
                messageEn: 'Only English letters, numbers, and limited special characters (.,?!-_+@#) are allowed'
            };
        }

        return { valid: true };
    }

    displaySearchResults(data, requestId) {
        const containerDiv = document.getElementById('resultsContainer');
        let html = '';

        if (data.organic && data.organic.length > 0) {
            html += '<h3>Search Results:</h3>';
            html += `
                <div class="summaries-section">
                    <button id="viewSummariesBtn" onclick="window.summaryManager.loadSummaries('${this.escapeHtml(requestId)}')" class="summaries-btn">
                        View AI Summaries
                    </button>
                    <div id="summariesContainer" style="display: none;">
                        <div class="loading">Loading summaries...</div>
                    </div>
                </div>
            `;

            html += '<div class="original-results" style="margin-top: 20px;">';
            data.organic.forEach(result => {
                const url = result.link || '#';
                const title = this.escapeHtml(result.title || 'No title');
                const snippet = this.escapeHtml(result.snippet || '');
                
                html += `
                    <div class="search-result">
                        <h4><a href="${this.escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${title}</a></h4>
                        <p class="result-snippet">${snippet}</p>
                        <p class="result-url">${this.escapeHtml(url)}</p>
                    </div>
                `;
            });
            html += '</div>';
        } else {
            html = '<div class="no-results">No results found.</div>';
        }

        containerDiv.innerHTML = html;
    }

    handleSearchKeyPress(event) {
        const dropdown = document.getElementById('searchHistoryDropdown');
        
        if (event.key === 'Enter') {
            const query = document.getElementById('searchInput').value;
            if (query.trim()) {
                dropdown.classList.remove('show');
                this.performSearch(query);
            }
        } else if (event.key === 'Escape') {
            dropdown.classList.remove('show');
        } else if (event.key === 'ArrowDown') {
            event.preventDefault();
            if (!dropdown.classList.contains('show')) {
                window.searchHistory.toggleSearchHistory();
            }
        }
    }

    handleSearchInputFocus() {
        const searchInput = document.getElementById('searchInput');
        if (!searchInput.value.trim()) {
            const dropdown = document.getElementById('searchHistoryDropdown');
            if (!dropdown.classList.contains('show')) {
                setTimeout(() => window.searchHistory.toggleSearchHistory(), 150);
            }
        }
    }

    handleDocumentClick(event) {
        const dropdown = document.getElementById('searchHistoryDropdown');
        const searchContainer = document.querySelector('.search-container');
        
        if (!searchContainer.contains(event.target)) {
            dropdown.classList.remove('show');
        }
    }

    // Security: Escape HTML to prevent XSS
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    showError(message) {
        const containerDiv = document.getElementById('resultsContainer');
        containerDiv.innerHTML = `<div class="error">${this.escapeHtml(message)}</div>`;
    }
}

// Global search handler function for inline events (secure wrapper)
function handleSearchKeyPress(event) {
    if (window.searchManager) {
        window.searchManager.handleSearchKeyPress(event);
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.searchManager = new SearchManager();
});
