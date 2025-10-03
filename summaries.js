// AI Summaries Management Module
class SummaryManager {
    constructor() {
        this.pollInterval = 2000; // 2 seconds
        this.maxPollTime = 60000; // 1 minute max polling
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

    // Display summaries with markdown conversion and collapsible sections
    displaySummaries(summaries) {
        const summariesContainer = document.getElementById('summariesContainer');
        if (!summariesContainer) return;

        let html = '<h4>AI Generated Summaries:</h4>';

        summaries.forEach((summary, index) => {
            if (summary.summary) {
                const summaryId = `summary-${index}`;
                const shortUrl = this.truncateUrl(summary.originalUrl);
                const escapedUrl = this.escapeHtml(summary.originalUrl);
                const escapedShortUrl = this.escapeHtml(shortUrl);

                html += `
                    <div class="summary-item">
                        <div class="summary-header" onclick="window.summaryManager.toggleSummary('${summaryId}')">
                            <div class="summary-title">
                                <span class="summary-url-title">${escapedShortUrl}</span>
                                <span class="toggle-icon" id="icon-${summaryId}">+</span>
                            </div>
                        </div>
                        <div class="summary-content" id="${summaryId}" style="display: none;">
                            ${this.markdownToHtml(summary.summary)}
                            <div class="summary-source">
                                <strong>Source:</strong> <a href="${escapedUrl}" target="_blank" rel="noopener noreferrer">${escapedUrl}</a>
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

    // Toggle individual summary display
    toggleSummary(summaryId) {
        if (!summaryId || typeof summaryId !== 'string') return;

        const content = document.getElementById(summaryId);
        const icon = document.getElementById(`icon-${summaryId}`);

        if (!content || !icon) return;

        if (content.style.display === 'none') {
            content.style.display = 'block';
            icon.textContent = '-';
        } else {
            content.style.display = 'none';
            icon.textContent = '+';
        }
    }

    // Safe markdown to HTML converter with sanitization
    markdownToHtml(markdown) {
        if (!markdown || typeof markdown !== 'string') return '';

        // First escape HTML to prevent XSS
        let html = this.escapeHtml(markdown);

        // Convert headers (after escaping)
        html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
        html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
        html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');

        // Convert bullet points with single asterisk (must be before bold conversion)
        html = html.replace(/^\* (.*$)/gim, '<li>$1</li>');
        html = html.replace(/^\- (.*$)/gim, '<li>$1</li>');

        // Convert bold (double asterisk)
        html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');

        // Wrap lists
        html = html.replace(/(<li>.*<\/li>)/gs, '<ul>$1</ul>');

        // Convert line breaks
        html = html.replace(/\n\n/g, '</p><p>');
        html = html.replace(/\n/g, '<br>');

        // Wrap in paragraphs
        html = '<p>' + html + '</p>';

        return html;
    }

    // Utility functions
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