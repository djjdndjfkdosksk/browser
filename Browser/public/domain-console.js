
class DomainConsole {
    constructor() {
        this.currentRequestId = null;
        this.currentPage = 1;
        this.currentFilter = 'all';
        this.currentStatus = 'all';
    }

    async init() {
        await this.loadUserDomain();
        await this.loadDomainSummaries();
        this.setupEventListeners();
    }

    setupEventListeners() {
        const form = document.getElementById('urlSubmissionForm');
        if (form) {
            form.addEventListener('submit', this.handleSubmitUrl.bind(this));
        }

        // Filter buttons
        const filterButtons = document.querySelectorAll('.filter-btn');
        filterButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.currentFilter = e.target.dataset.filter;
                this.currentPage = 1;
                this.loadDomainSummaries();
            });
        });

        // Status filter
        const statusSelect = document.getElementById('statusFilter');
        if (statusSelect) {
            statusSelect.addEventListener('change', (e) => {
                this.currentStatus = e.target.value;
                this.currentPage = 1;
                this.loadDomainSummaries();
            });
        }
    }

    async loadUserDomain() {
        try {
            const sessionId = localStorage.getItem('sessionId');
            const csrfToken = localStorage.getItem('csrfToken');

            const response = await fetch('/api/profile', {
                headers: {
                    'x-session-id': sessionId,
                    'x-csrf-token': csrfToken
                }
            });

            const result = await response.json();

            if (result.success && result.user) {
                const domainDisplay = document.getElementById('userDomain');
                if (domainDisplay) {
                    domainDisplay.textContent = `Your Domain: ${result.user.domain || 'Not configured'}`;
                }

                const dailyLimit = document.getElementById('dailyLimit');
                if (dailyLimit) {
                    const status = result.user.verification_status || 'unverified';
                    if (status === 'verified') {
                        dailyLimit.textContent = `Status: Verified ✓`;
                        dailyLimit.style.color = '#34a853';
                    } else {
                        dailyLimit.textContent = `Daily Limit: 10 URLs (Status: ${status})`;
                    }
                }
            }
        } catch (error) {
            console.error('Error loading user domain:', error);
        }
    }

    async loadDomainSummaries(page = 1) {
        try {
            const sessionId = localStorage.getItem('sessionId');
            const csrfToken = localStorage.getItem('csrfToken');

            const params = new URLSearchParams({
                page: page,
                limit: 20,
                type: this.currentFilter,
                status: this.currentStatus
            });

            const response = await fetch(`/api/domain-summaries?${params}`, {
                headers: {
                    'x-session-id': sessionId,
                    'x-csrf-token': csrfToken
                }
            });

            const result = await response.json();

            if (result.success) {
                this.displayDomainSummaries(result.data);
                this.currentPage = page;
            }
        } catch (error) {
            console.error('Error loading domain summaries:', error);
            const container = document.getElementById('urlHistoryContainer');
            if (container) {
                container.innerHTML = '<p class="error-text">Failed to load summaries</p>';
            }
        }
    }

    displayDomainSummaries(data) {
        const container = document.getElementById('urlHistoryContainer');

        if (!data.items || data.items.length === 0) {
            container.innerHTML = '<p class="no-history">No summaries found</p>';
            return;
        }

        const itemsHtml = data.items.map(item => {
            const statusText = item.summary_status === 'summarized' ? 'Ready' : 'Processing';
            const typeText = item.crawl_type === 'manual' ? 'Manual' : 'Auto';
            const summaryLink = item.original_url.replace(/^https?:\/\//, '/');

            return `
                <div class="summary-item" data-url-hash="${item.url_hash}">
                    <div class="summary-header">
                        <a href="${this.escapeHtml(item.original_url)}" target="_blank" class="summary-url">
                            ${this.escapeHtml(item.original_url)}
                        </a>
                        <span class="summary-meta">${typeText} • ${statusText} • ${this.formatTimeAgo(item.crawl_completed_at)}</span>
                    </div>
                    ${item.summary_status === 'summarized' ? `
                        <a href="${summaryLink}" class="view-summary-btn" target="_blank">
                            View Summary
                        </a>
                    ` : `
                        <span class="processing-text">Processing...</span>
                    `}
                </div>
            `;
        }).join('');

        const paginationHtml = this.createPaginationHtml(data.pagination);

        container.innerHTML = `
            <div class="summaries-list">${itemsHtml}</div>
            ${paginationHtml}
        `;
    }

    createPaginationHtml(pagination) {
        if (pagination.totalPages <= 1) return '';

        return `
            <div class="pagination">
                <button 
                    class="pagination-btn" 
                    ${!pagination.hasPrev ? 'disabled' : ''} 
                    onclick="domainConsole.loadDomainSummaries(${pagination.page - 1})">
                    ← Previous
                </button>
                <span class="pagination-info">Page ${pagination.page} of ${pagination.totalPages}</span>
                <button 
                    class="pagination-btn" 
                    ${!pagination.hasNext ? 'disabled' : ''} 
                    onclick="domainConsole.loadDomainSummaries(${pagination.page + 1})">
                    Next →
                </button>
            </div>
        `;
    }

    formatTimeAgo(dateString) {
        if (!dateString) return 'N/A';
        
        const date = new Date(dateString);
        
        if (isNaN(date.getTime())) return 'N/A';
        
        const now = new Date();
        const seconds = Math.floor((now.getTime() - date.getTime()) / 1000);
        
        if (seconds < 0) return 'just now';
        if (seconds < 60) return 'just now';
        if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes ago`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours ago`;
        if (seconds < 604800) return `${Math.floor(seconds / 86400)} days ago`;
        if (seconds < 2592000) return `${Math.floor(seconds / 604800)} weeks ago`;
        if (seconds < 31536000) return `${Math.floor(seconds / 2592000)} months ago`;
        return `${Math.floor(seconds / 31536000)} years ago`;
    }

    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    async handleSubmitUrl(e) {
        e.preventDefault();
        this.clearMessages();

        const urlInput = document.getElementById('urlInput');
        const submitBtn = document.getElementById('submitBtn');
        const url = urlInput.value.trim();

        if (!url) return;

        submitBtn.disabled = true;
        submitBtn.textContent = 'Submitting...';

        try {
            const sessionId = localStorage.getItem('sessionId');
            const csrfToken = localStorage.getItem('csrfToken');

            const response = await fetch('/api/submit-url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-session-id': sessionId,
                    'x-csrf-token': csrfToken
                },
                body: JSON.stringify({ url })
            });

            const result = await response.json();

            if (result.success) {
                this.showSuccess('URL submitted successfully! Processing...');
                urlInput.value = '';
                
                setTimeout(() => {
                    this.loadDomainSummaries();
                }, 1000);
            } else if (response.status === 409 && result.alreadyExists) {
                this.showError(result.message || result.error);
                urlInput.value = '';
                await this.loadDomainSummaries();
            } else {
                this.showError(result.error || 'Failed to submit URL');
            }
        } catch (error) {
            this.showError(error.message || 'Network error');
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Submit URL';
        }
    }

    clearMessages() {
        const errorMsg = document.getElementById('errorMessage');
        const successMsg = document.getElementById('successMessage');

        if (errorMsg) {
            errorMsg.textContent = '';
            errorMsg.style.display = 'none';
        }
        if (successMsg) {
            successMsg.textContent = '';
            successMsg.style.display = 'none';
        }
    }

    showError(message) {
        const errorMsg = document.getElementById('errorMessage');
        if (errorMsg) {
            errorMsg.textContent = message;
            errorMsg.style.display = 'block';
        }
    }

    showSuccess(message) {
        const successMsg = document.getElementById('successMessage');
        if (successMsg) {
            successMsg.textContent = message;
            successMsg.style.display = 'block';
        }
    }
}

document.addEventListener('DOMContentLoaded', function() {
    window.domainConsole = new DomainConsole();
});
