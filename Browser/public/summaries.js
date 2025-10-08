// AI Summaries Management Module
class SummaryManager {
    constructor() {
        this.pollInterval = 5000; // 5 seconds
        this.maxPollTime = 60000; // 1 minute max polling
        this.waitTime = 20000; // 20 seconds wait for < 3 summaries
    }

    // Load summaries for a search request with auto-refresh
    async loadSummaries(requestId) {
        if (!requestId || typeof requestId !== 'string') {
            console.error('Invalid request ID');
            return;
        }

        // Sanitize request ID
        const sanitizedRequestId = this.sanitizeRequestId(requestId);
        if (!sanitizedRequestId) {
            console.error('Invalid request ID format');
            return;
        }

        const summariesContainer = document.getElementById('summariesContainer');
        const btn = document.getElementById('viewSummariesBtn');

        if (!summariesContainer || !btn) return;

        // Show container immediately with loading state
        summariesContainer.style.display = 'block';
        
        // Generate random target number between 4000-7000
        const targetNumber = Math.floor(Math.random() * (7000 - 4000 + 1)) + 4000;
        
        summariesContainer.innerHTML = `
            <div class="loading-state">
                <div class="loading-spinner"></div>
                <div class="loading-text">Loading AI summaries...</div>
                <div class="loading-subtext">Processing content, please wait</div>
                <div class="loading-progress">
                    <span id="progressCounter">0</span> / ${targetNumber}
                </div>
            </div>
        `;
        btn.disabled = true;
        btn.textContent = 'Loading...';
        
        // Start polling with timeout
        const pollStartTime = Date.now();
        
        // Animate counter from 0 to target in 15 seconds
        const duration = 15000; // 15 seconds
        const counterElement = document.getElementById('progressCounter');
        
        const animateCounter = () => {
            const elapsed = Date.now() - pollStartTime;
            const progress = Math.min(elapsed / duration, 1);
            const currentValue = Math.floor(progress * targetNumber);
            
            if (counterElement) {
                counterElement.textContent = currentValue;
            }
            
            if (progress < 1) {
                requestAnimationFrame(animateCounter);
            }
        };
        
        animateCounter();

        this.pollForSummaries(sanitizedRequestId, btn, pollStartTime);
    }

    // Auto-refresh function that runs continuously with timeout
    async pollForSummaries(requestId, btn, startTime) {
        try {
            // Check if we've exceeded max poll time
            if (Date.now() - startTime > this.maxPollTime) {
                this.showPollTimeout(btn);
                return;
            }

            const response = await fetch(`/api/search/${encodeURIComponent(requestId)}/summaries`, {
                method: 'GET',
                headers: {
                    'x-session-id': localStorage.getItem('sessionId'),
                    'x-csrf-token': localStorage.getItem('csrfToken')
                }
            });

            // Check for rate limit directly from response status
            if (response.status === 429) {
                const errorData = await response.json().catch(() => ({})); // Attempt to get JSON error details
                this.showRateLimitError(btn, errorData);
                return; // Stop polling completely
            }

            // Check for other HTTP errors
            if (!response.ok) {
                const error = new Error(`HTTP error! status: ${response.status}`);
                error.response = response; // Attach response for potential further inspection
                throw error;
            }

            const result = await response.json();

            if (result.success && result.summaries && result.summaries.length > 0) {
                // Check if we have actual summary content
                const validSummaries = result.summaries.filter(s => 
                    s.summary && s.summary.trim().length > 0
                );

                if (validSummaries.length > 0) {
                    // If we have less than 3 summaries, wait 20 seconds before displaying
                    if (validSummaries.length < 3) {
                        const elapsedTime = Date.now() - startTime;
                        if (elapsedTime < this.waitTime) {
                            // Continue polling until 20 seconds have passed
                            setTimeout(() => {
                                this.pollForSummaries(requestId, btn, startTime);
                            }, this.pollInterval);
                            return;
                        }
                    }
                    
                    // Found valid summaries - display them and stop polling
                    this.displaySummaries(validSummaries);
                    btn.disabled = false;
                    btn.textContent = 'AI Summaries Ready';
                    return; // Stop the polling
                }
            }

            // No summaries yet, continue polling after interval
            setTimeout(() => {
                this.pollForSummaries(requestId, btn, startTime);
            }, this.pollInterval);

        } catch (error) {
            console.error('Polling error:', error);

            // Handle rate limit errors (429) - stop polling and show appropriate message
            if (error.message && error.message.includes('429')) {
                this.showRateLimitError(btn);
                return; // Stop polling completely
            }

            // Handle HTTP errors from response
            if (error.response && error.response.status === 429) {
                this.showRateLimitError(btn);
                return; // Stop polling completely
            }

            // Continue polling on network errors (but respect max time)
            if (Date.now() - startTime < this.maxPollTime) {
                setTimeout(() => {
                    this.pollForSummaries(requestId, btn, startTime);
                }, this.pollInterval + 1000); // Wait longer on error
            } else {
                this.showPollTimeout(btn);
            }
        }
    }

    // Display summaries with links to public pages
    displaySummaries(summaries) {
        const summariesContainer = document.getElementById('summariesContainer');
        if (!summariesContainer) return;

        let html = '';

        summaries.forEach((summary, index) => {
            if (summary.summary) {
                const mainTitle = this.extractMainTitle(summary.summary);
                const shortTitle = this.truncateTitle(mainTitle);
                const escapedUrl = this.escapeHtml(summary.originalUrl);
                const escapedTitle = this.escapeHtml(shortTitle);
                
                // Create public summary link by removing protocol
                const publicPath = summary.originalUrl.replace(/^https?:\/\//, '');
                const summaryLink = `/${publicPath}`;

                html += `
                    <div class="summary-item">
                        <div class="summary-link-container">
                            <div class="summary-title">
                                <span class="summary-url-title">${escapedTitle}</span>
                            </div>
                            <div class="summary-actions">
                                <a href="${summaryLink}" target="_blank" class="view-summary-btn" title="View full summary">
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                                        <polyline points="15 3 21 3 21 9"></polyline>
                                        <line x1="10" y1="14" x2="21" y2="3"></line>
                                    </svg>
                                    View Summary
                                </a>
                                <a href="${escapedUrl}" target="_blank" class="source-link-btn" title="View original source">
                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path>
                                        <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path>
                                    </svg>
                                    Source
                                </a>
                            </div>
                        </div>
                    </div>
                `;
            }
        });

        if (summaries.filter(s => s.summary).length === 0) {
            html += '<div class="no-summaries">Summaries are still being generated. Please wait a moment and try again.</div>';
        }

        summariesContainer.innerHTML = html;
    }

    // Utility functions
    extractMainTitle(markdown) {
        if (!markdown || typeof markdown !== 'string') return 'Untitled Summary';
        
        // Extract first heading from markdown (# Title or ## Title or ### Title)
        const lines = markdown.split('\n');
        for (const line of lines) {
            const trimmedLine = line.trim();
            // Check for markdown headings
            if (trimmedLine.startsWith('# ')) {
                return trimmedLine.substring(2).trim();
            } else if (trimmedLine.startsWith('## ')) {
                return trimmedLine.substring(3).trim();
            } else if (trimmedLine.startsWith('### ')) {
                return trimmedLine.substring(4).trim();
            }
        }
        
        // If no heading found, use first non-empty line
        for (const line of lines) {
            const trimmedLine = line.trim();
            if (trimmedLine.length > 0) {
                return trimmedLine;
            }
        }
        
        return 'Untitled Summary';
    }

    truncateTitle(title) {
        if (!title || typeof title !== 'string') return 'Untitled Summary';
        return title.length > 50 ? title.substring(0, 50) + '...' : title;
    }

    truncateUrl(url) {
        if (!url || typeof url !== 'string') return 'Unknown URL';
        return url.length > 50 ? url.substring(0, 50) + '...' : url;
    }

    sanitizeRequestId(requestId) {
        // Only allow alphanumeric characters, dashes, and underscores
        return requestId.replace(/[^a-zA-Z0-9-_]/g, '').substring(0, 100);
    }

    // Security: Escape HTML to prevent XSS
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    showPollTimeout(btn) {
        const summariesContainer = document.getElementById('summariesContainer');
        summariesContainer.innerHTML = `
            <div class="error-state">
                <div class="error-icon">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="10"></circle>
                        <polyline points="12 6 12 12 16 14"></polyline>
                    </svg>
                </div>
                <div class="error-title">Processing Timeout</div>
                <div class="error-message">Summary generation is taking longer than expected. Please try again later.</div>
                <button onclick="location.reload()" class="retry-btn">Refresh Page</button>
            </div>
        `;
        btn.disabled = false;
        btn.textContent = 'Timed Out - Refresh to Retry';
    }

    showRateLimitError(btn, errorData = null) {
        const summariesContainer = document.getElementById('summariesContainer');
        const errorMessage = errorData?.error || 'Daily search limit reached. Please try again tomorrow.';
        const currentCount = errorData?.currentCount || 'N/A';
        const limit = errorData?.limit || 'N/A';

        summariesContainer.innerHTML = `
            <div class="error-state rate-limit-error">
                <div class="error-icon">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="10"></circle>
                        <line x1="15" y1="9" x2="9" y2="15"></line>
                        <line x1="9" y1="9" x2="15" y2="15"></line>
                    </svg>
                </div>
                <div class="error-title">Daily Limit Reached</div>
                <div class="error-message">${this.escapeHtml(errorMessage)}</div>
                <div class="limit-info">
                    <small>Usage: ${currentCount}/${limit} searches today</small>
                </div>
                <div class="error-note">
                    <small>Your daily search limit will reset tomorrow. Summaries for previous searches remain available.</small>
                </div>
            </div>
        `;
        btn.disabled = true;
        btn.textContent = 'Daily Limit Reached';
        btn.style.opacity = '0.6';
    }
}

// Global function for inline event handlers
function loadSummaries(requestId) {
    if (window.summaryManager) {
        window.summaryManager.loadSummaries(requestId);
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.summaryManager = new SummaryManager();
});