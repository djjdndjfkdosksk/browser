
class AdminPanel {
    constructor() {
        this.isAuthenticated = false;
        this.lastUpdate = null;
        this.init();
    }

    init() {
        this.bindEvents();
        this.checkAuthentication();
    }

    bindEvents() {
        // فرم ورود
        document.getElementById('loginForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.login();
        });

        // دکمه خروج
        document.getElementById('logoutBtn').addEventListener('click', () => {
            this.logout();
        });

        // دکمه بروزرسانی
        document.getElementById('refreshBtn').addEventListener('click', () => {
            this.refreshData();
        });
    }

    checkAuthentication() {
        const token = localStorage.getItem('adminToken');
        if (token) {
            this.isAuthenticated = true;
            this.showDashboard();
            this.loadInitialData();
        } else {
            this.showLogin();
        }
    }

    async login() {
        const password = document.getElementById('adminPassword').value;
        const errorElement = document.getElementById('loginError');

        try {
            const response = await fetch('/api/admin/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password })
            });

            const result = await response.json();

            if (result.success) {
                localStorage.setItem('adminToken', result.token);
                this.isAuthenticated = true;
                this.showDashboard();
                this.loadInitialData();
                errorElement.style.display = 'none';
            } else {
                errorElement.textContent = result.error || 'رمز عبور نادرست';
                errorElement.style.display = 'block';
            }
        } catch (error) {
            errorElement.textContent = 'خطا در اتصال به سرور';
            errorElement.style.display = 'block';
        }
    }

    logout() {
        localStorage.removeItem('adminToken');
        this.isAuthenticated = false;
        this.showLogin();
    }

    showLogin() {
        document.getElementById('adminLogin').style.display = 'block';
        document.getElementById('adminDashboard').style.display = 'none';
    }

    showDashboard() {
        document.getElementById('adminLogin').style.display = 'none';
        document.getElementById('adminDashboard').style.display = 'block';
    }

    async makeAuthenticatedRequest(url, options = {}) {
        const token = localStorage.getItem('adminToken');
        if (!token) {
            this.logout();
            return null;
        }

        const headers = {
            ...options.headers,
            'Authorization': `Bearer ${token}`
        };

        if (!(options.body instanceof FormData)) {
            headers['Content-Type'] = 'application/json';
        }

        const response = await fetch(url, {
            ...options,
            headers
        });

        if (response.status === 401) {
            this.logout();
            return null;
        }

        return response;
    }

    async loadInitialData() {
        await this.refreshData();
    }

    async refreshData() {
        const refreshBtn = document.getElementById('refreshBtn');
        refreshBtn.disabled = true;
        refreshBtn.textContent = '🔄 در حال بروزرسانی...';

        try {
            await Promise.all([
                this.loadStats(),
                this.loadUsers(),
                this.loadDownloadStats()
            ]);

            this.lastUpdate = new Date();
            document.getElementById('lastUpdated').textContent = 
                `آخرین بروزرسانی: ${this.lastUpdate.toLocaleString('fa-IR')}`;

        } catch (error) {
            this.showError('خطا در بارگیری اطلاعات');
        } finally {
            refreshBtn.disabled = false;
            refreshBtn.textContent = '🔄 بروزرسانی اطلاعات';
        }
    }

    async loadStats() {
        try {
            const response = await this.makeAuthenticatedRequest('/api/admin/stats');
            if (!response) return;

            const stats = await response.json();
            if (stats.success) {
                this.renderStats(stats.data);
            } else {
                this.showError('خطا در دریافت آمار');
            }
        } catch (error) {
            this.showError('خطا در دریافت آمار');
        }
    }

    async loadUsers() {
        try {
            const response = await this.makeAuthenticatedRequest('/api/admin/users');
            if (!response) return;

            const users = await response.json();
            if (users.success) {
                this.renderUsers(users.data);
            } else {
                this.showError('خطا در دریافت لیست کاربران');
            }
        } catch (error) {
            this.showError('خطا در دریافت لیست کاربران');
        }
    }

    renderStats(stats) {
        const container = document.getElementById('statsContainer');
        
        container.innerHTML = `
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>👥 آمار کاربران</h3>
                    <div class="stat-row">
                        <span class="stat-label">کل کاربران:</span>
                        <span class="stat-value">${stats.users.total_users || 0}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">کاربران فعال:</span>
                        <span class="stat-value">${stats.users.active_users || 0}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">کاربران جدید (هفته):</span>
                        <span class="stat-value">${stats.users.new_users_week || 0}</span>
                    </div>
                </div>

                <div class="stat-card">
                    <h3>🔐 آمار جلسات</h3>
                    <div class="stat-row">
                        <span class="stat-label">کل جلسات:</span>
                        <span class="stat-value">${stats.sessions.total_sessions || 0}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">جلسات فعال:</span>
                        <span class="stat-value">${stats.sessions.active_sessions || 0}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">جلسات امروز:</span>
                        <span class="stat-value">${stats.sessions.sessions_today || 0}</span>
                    </div>
                </div>

                <div class="stat-card">
                    <h3>🔗 آمار URL ها</h3>
                    <div class="stat-row">
                        <span class="stat-label">کل لینک‌ها:</span>
                        <span class="stat-value">${stats.urls.total_urls || 0}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">خزش شده:</span>
                        <span class="stat-value">${stats.urls.crawled_urls || 0}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">در انتظار:</span>
                        <span class="stat-value">${stats.urls.pending_urls || 0}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">ناموفق:</span>
                        <span class="stat-value">${stats.urls.failed_urls || 0}</span>
                    </div>
                </div>

                <div class="stat-card">
                    <h3>🔍 آمار جستجوها</h3>
                    <div class="stat-row">
                        <span class="stat-label">کل جستجوها:</span>
                        <span class="stat-value">${stats.searches.total_searches || 0}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">جستجوهای امروز:</span>
                        <span class="stat-value">${stats.searches.searches_today || 0}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">جستجوهای هفته:</span>
                        <span class="stat-value">${stats.searches.searches_week || 0}</span>
                    </div>
                </div>

                <div class="stat-card">
                    <h3>📄 آمار محتوا</h3>
                    <div class="stat-row">
                        <span class="stat-label">کل درخواست‌ها:</span>
                        <span class="stat-value">${stats.content.total_requests || 0}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">کل بلوک‌ها:</span>
                        <span class="stat-value">${stats.content.total_blocks || 0}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">کل کلمات:</span>
                        <span class="stat-value">${stats.content.total_words || 0}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">متوسط زمان پردازش:</span>
                        <span class="stat-value">${stats.content.avg_processing_time ? parseFloat(stats.content.avg_processing_time).toFixed(2) + ' ثانیه' : 'N/A'}</span>
                    </div>
                </div>

                <div class="stat-card">
                    <h3>💾 آمار دیتابیس</h3>
                    <div class="stat-row">
                        <span class="stat-label">حجم دیتابیس:</span>
                        <span class="stat-value">${stats.database.sizeFormatted}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">کل خلاصه‌ها:</span>
                        <span class="stat-value">${stats.summaries.total_summaries || 0}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">خلاصه‌های کامل:</span>
                        <span class="stat-value">${stats.summaries.completed_summaries || 0}</span>
                    </div>
                </div>
            </div>
        `;
    }

    renderUsers(users) {
        const container = document.getElementById('usersTableContainer');
        
        if (!users || users.length === 0) {
            container.innerHTML = '<div class="loading">هیچ کاربری یافت نشد</div>';
            return;
        }

        const tableHTML = `
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>نام کاربری</th>
                        <th>تاریخ عضویت</th>
                        <th>آخرین ورود</th>
                        <th>جلسات</th>
                        <th>جستجوها</th>
                        <th>جستجوهای امروز</th>
                        <th>وضعیت</th>
                    </tr>
                </thead>
                <tbody>
                    ${users.map(user => `
                        <tr>
                            <td>${user.id}</td>
                            <td>${user.username}</td>
                            <td>${new Date(user.created_at).toLocaleDateString('fa-IR')}</td>
                            <td>${user.last_login ? new Date(user.last_login).toLocaleDateString('fa-IR') : 'هرگز'}</td>
                            <td>${user.total_sessions || 0}</td>
                            <td>${user.total_searches || 0}</td>
                            <td>${user.searches_today || 0}</td>
                            <td>${user.locked_until ? '🔒 مسدود' : '✅ فعال'}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;

        container.innerHTML = tableHTML;
    }

    async loadDownloadStats() {
        try {
            const response = await this.makeAuthenticatedRequest('/api/admin/download-stats');
            if (!response) return;

            const result = await response.json();
            if (result.success) {
                this.renderDownloadStats(result.data);
            }
        } catch (error) {
            this.showError('خطا در دریافت آمار دانلود');
        }
    }

    renderDownloadStats(stats) {
        const container = document.getElementById('downloadStatsContainer');
        const buttonsContainer = document.getElementById('downloadButtonsContainer');
        
        if (!stats.client_content || !stats.data) {
            container.innerHTML = '<div class="error">خطا در دریافت آمار</div>';
            return;
        }

        container.innerHTML = `
            <div class="stats-grid" style="grid-template-columns: repeat(2, 1fr);">
                <div class="stat-card">
                    <h3>📁 Client Content</h3>
                    <div class="stat-row">
                        <span class="stat-label">حجم:</span>
                        <span class="stat-value">${stats.client_content.sizeFormatted}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">تعداد فایل:</span>
                        <span class="stat-value">${stats.client_content.fileCount}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">تعداد فولدر:</span>
                        <span class="stat-value">${stats.client_content.dirCount}</span>
                    </div>
                </div>
                <div class="stat-card">
                    <h3>🗄️ Data</h3>
                    <div class="stat-row">
                        <span class="stat-label">حجم:</span>
                        <span class="stat-value">${stats.data.sizeFormatted}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">تعداد فایل:</span>
                        <span class="stat-value">${stats.data.fileCount}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">تعداد فولدر:</span>
                        <span class="stat-value">${stats.data.dirCount}</span>
                    </div>
                </div>
            </div>
        `;

        buttonsContainer.style.display = 'block';
        this.bindDownloadButtons();
    }

    bindDownloadButtons() {
        const clientContentBtn = document.getElementById('downloadClientContentBtn');
        const dataBtn = document.getElementById('downloadDataBtn');

        if (clientContentBtn) {
            clientContentBtn.onclick = () => this.downloadDirectory('client_content');
        }
        if (dataBtn) {
            dataBtn.onclick = () => this.downloadDirectory('data');
        }

        // Bind upload buttons
        this.bindUploadButtons();
    }

    bindUploadButtons() {
        const backupFileInput = document.getElementById('backupFile');
        const restoreBtn = document.getElementById('restoreBackupBtn');
        
        if (backupFileInput) {
            backupFileInput.onchange = (e) => this.handleFileSelection(e);
        }
        
        if (restoreBtn) {
            restoreBtn.onclick = () => this.restoreBackup();
        }
    }

    async handleFileSelection(event) {
        const file = event.target.files[0];
        if (!file) return;

        const fileNameDiv = document.getElementById('selectedFileName');
        const previewDiv = document.getElementById('backupPreview');
        const previewContent = document.getElementById('previewContent');
        const restoreBtn = document.getElementById('restoreBackupBtn');

        fileNameDiv.textContent = `فایل انتخاب شده: ${file.name} (${this.formatBytes(file.size)})`;

        try {
            const formData = new FormData();
            formData.append('backup', file);

            const response = await this.makeAuthenticatedRequest('/api/admin/preview-backup', {
                method: 'POST',
                body: formData,
                headers: {} // Let browser set Content-Type for FormData
            });

            if (!response) return;

            const result = await response.json();
            
            if (result.success) {
                previewContent.innerHTML = `
                    <div style="margin-bottom: 10px;">
                        <strong>تعداد فایل‌ها:</strong> ${result.totalFiles}<br>
                        <strong>تعداد پوشه‌ها:</strong> ${result.totalDirs}<br>
                        <strong>حجم کل:</strong> ${result.fileSizeFormatted}
                    </div>
                    <div style="max-height: 200px; overflow-y: auto; font-size: 12px;">
                        ${result.contents.slice(0, 20).map(c => 
                            `<div>${c.isDirectory ? '📁' : '📄'} ${c.name}</div>`
                        ).join('')}
                        ${result.contents.length > 20 ? `<div>... و ${result.contents.length - 20} مورد دیگر</div>` : ''}
                    </div>
                `;
                previewDiv.style.display = 'block';
                restoreBtn.style.display = 'inline-block';
            } else {
                this.showUploadError(result.error || 'خطا در پیش‌نمایش فایل');
                previewDiv.style.display = 'none';
                restoreBtn.style.display = 'none';
            }
        } catch (error) {
            this.showUploadError('خطا در پیش‌نمایش فایل');
            previewDiv.style.display = 'none';
            restoreBtn.style.display = 'none';
        }
    }

    async restoreBackup() {
        const fileInput = document.getElementById('backupFile');
        const targetSelect = document.getElementById('targetDirectorySelect');
        const restoreBtn = document.getElementById('restoreBackupBtn');
        
        if (!fileInput.files[0]) {
            this.showUploadError('لطفا ابتدا یک فایل انتخاب کنید');
            return;
        }

        const confirmed = confirm(`آیا مطمئن هستید که می‌خواهید بک‌آپ را در پوشه "${targetSelect.value}" بازیابی کنید؟\n\nتوجه: فایل‌های موجود ممکن است بازنویسی شوند.`);
        
        if (!confirmed) return;

        try {
            restoreBtn.disabled = true;
            restoreBtn.textContent = '⏳ در حال بازیابی...';

            const formData = new FormData();
            formData.append('backup', fileInput.files[0]);
            formData.append('targetDirectory', targetSelect.value);

            const response = await this.makeAuthenticatedRequest('/api/admin/restore-backup', {
                method: 'POST',
                body: formData,
                headers: {} // Let browser set Content-Type for FormData
            });

            if (!response) {
                throw new Error('Authentication failed');
            }

            const result = await response.json();

            if (result.success) {
                this.showUploadSuccess(`بازیابی موفق! ${result.fileSize} در ${result.extractedTo} استخراج شد.`);
                
                // Reset form
                fileInput.value = '';
                document.getElementById('selectedFileName').textContent = '';
                document.getElementById('backupPreview').style.display = 'none';
                restoreBtn.style.display = 'none';
                
                // Refresh stats
                await this.refreshData();
            } else {
                this.showUploadError(result.error || 'خطا در بازیابی بک‌آپ');
            }
        } catch (error) {
            this.showUploadError('خطا در بازیابی بک‌آپ: ' + error.message);
        } finally {
            restoreBtn.disabled = false;
            restoreBtn.textContent = '✅ بازیابی بک‌آپ';
        }
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    showUploadError(message) {
        const statusDiv = document.getElementById('uploadStatus');
        statusDiv.innerHTML = `<div class="error">${message}</div>`;
        setTimeout(() => { statusDiv.innerHTML = ''; }, 5000);
    }

    showUploadSuccess(message) {
        const statusDiv = document.getElementById('uploadStatus');
        statusDiv.innerHTML = `<div class="success">${message}</div>`;
        setTimeout(() => { statusDiv.innerHTML = ''; }, 5000);
    }

    async downloadDirectory(directory) {
        try {
            const btn = directory === 'client_content' ? 
                document.getElementById('downloadClientContentBtn') : 
                document.getElementById('downloadDataBtn');
            
            btn.disabled = true;
            btn.textContent = '⏳ در حال آماده‌سازی...';

            // Generate download token
            const tokenResponse = await this.makeAuthenticatedRequest('/api/admin/generate-download-token', {
                method: 'POST',
                body: JSON.stringify({ directory })
            });

            if (!tokenResponse) {
                throw new Error('Failed to generate token');
            }

            const tokenResult = await tokenResponse.json();
            
            if (!tokenResult.success) {
                throw new Error(tokenResult.error || 'Token generation failed');
            }

            btn.textContent = '⬇️ در حال دانلود...';

            // Download file using token
            const downloadUrl = `/api/admin/download/${tokenResult.token}`;
            const link = document.createElement('a');
            link.href = downloadUrl;
            link.download = `${directory}_${Date.now()}.zip`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);

            setTimeout(() => {
                btn.disabled = false;
                btn.textContent = directory === 'client_content' ? 
                    '📥 دانلود Client Content' : 
                    '📥 دانلود Data';
            }, 2000);

        } catch (error) {
            console.error('خطا در دانلود:', error);
            this.showError('خطا در دانلود فایل');
            
            const btn = directory === 'client_content' ? 
                document.getElementById('downloadClientContentBtn') : 
                document.getElementById('downloadDataBtn');
            
            btn.disabled = false;
            btn.textContent = directory === 'client_content' ? 
                '📥 دانلود Client Content' : 
                '📥 دانلود Data';
        }
    }

    showError(message) {
        // نمایش پیام خطا در کنسول و یا به شکل مناسب
        console.error(message);
    }
}

// شروع اپلیکیشن
document.addEventListener('DOMContentLoaded', () => {
    new AdminPanel();
});
