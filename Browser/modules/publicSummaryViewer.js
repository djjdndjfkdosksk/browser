const crypto = require('crypto');
const path = require('path');

class PublicSummaryViewer {
  constructor(clientDatabase, logger) {
    this.clientDatabase = clientDatabase;
    this.logger = logger;
  }

  // Hash URL to match database records
  hashUrl(url) {
    return crypto.createHash('md5').update(url).digest('hex');
  }

  // Extract original URL from path (e.g., /site.com/1/2 -> https://site.com/1/2)
  extractUrlFromPath(urlPath) {
    // Remove leading slash
    const cleanPath = urlPath.replace(/^\/+/, '');

    if (!cleanPath) {
      return null;
    }

    // Add https:// protocol if not present
    let fullUrl = cleanPath;
    if (!fullUrl.startsWith('http://') && !fullUrl.startsWith('https://')) {
      fullUrl = 'https://' + fullUrl;
    }

    return fullUrl;
  }

  // Get summary data by URL path
  async getSummaryByPath(urlPath) {
    try {
      const originalUrl = this.extractUrlFromPath(urlPath);

      if (!originalUrl) {
        return {
          success: false,
          error: 'Invalid URL path'
        };
      }

      const urlHash = this.hashUrl(originalUrl);

      // Get summary from database using existing method
      const summaryData = await this.clientDatabase.getSummaryByUrlHash(urlHash);

      if (!summaryData) {
        return {
          success: false,
          error: 'Summary not found',
          notFound: true
        };
      }

      if (!summaryData.summary_text) {
        return {
          success: false,
          error: 'Summary not yet generated',
          pending: true,
          status: summaryData.summary_status
        };
      }

      return {
        success: true,
        data: {
          url: originalUrl,
          urlHash: urlHash,
          summary: summaryData.summary_text,
          status: summaryData.summary_status,
          processedAt: summaryData.summary_completed_at,
          createdAt: summaryData.summary_date
        }
      };

    } catch (error) {
      this.logger.error('Error retrieving public summary', error);
      return {
        success: false,
        error: 'Failed to retrieve summary'
      };
    }
  }

  // Convert markdown to HTML (same as summaries.js)
  markdownToHtml(markdown) {
    if (!markdown || typeof markdown !== 'string') return '';

    let html = this.escapeHtml(markdown);

    // Convert headers
    html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
    html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
    html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');

    // Convert bullet points
    html = html.replace(/^\* (.*$)/gim, '<li>$1</li>');
    html = html.replace(/^\- (.*$)/gim, '<li>$1</li>');

    // Convert bold
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

  // Escape HTML to prevent XSS
  escapeHtml(text) {
    if (!text) return '';
    const map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
  }

  // Generate menu items HTML from custom user menu
  async generateMenuItems(domain) {
    if (!domain || !global.menuCustomization) {
      return '';
    }

    try {
      const result = await global.menuCustomization.getMenuItemsByDomain(domain);

      if (!result.success || !result.items || result.items.length === 0) {
        return '';
      }

      let html = '';
      for (const item of result.items) {
        const escapedText = this.escapeHtml(item.text);
        const escapedUrl = this.escapeHtml(item.url);

        const textLength = item.text.length;
        const fontSize = textLength > 45 ? '11px' : textLength > 35 ? '12px' : textLength > 25 ? '13px' : '14px';

        html += `<div class="drawer-item" onclick="window.open('${escapedUrl}', '_blank')" style="font-size: ${fontSize};">${escapedText}</div>`;
      }

      return html;
    } catch (error) {
      this.logger.error('Error generating menu items', error);
      return '';
    }
  }

  // Generate HTML page for public summary view
  async generateSummaryPage(summaryData, domain = null) {
    const htmlContent = this.markdownToHtml(summaryData.summary);
    const escapedUrl = this.escapeHtml(summaryData.url);

    const menuItemsHtml = await this.generateMenuItems(domain);

    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Summary - ${escapedUrl}</title>
    <link rel="icon" type="image/png" href="/favicon.png">
    <link rel="shortcut icon" type="image/png" href="/favicon.png">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e1e2e 0%, #2d2d3f 100%);
            color: rgba(240, 240, 240, 0.95);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 900px;
            margin: 0 auto;
            background: rgba(30, 30, 40, 0.95);
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }

        .header {
            background: rgba(30, 30, 40, 0.3);
            padding: 16px 20px 0;
            border-bottom: none;
        }

        .header-top {
            display: flex;
            align-items: center;
            gap: 20px;
            margin-bottom: 10px;
        }

        .header-separator {
            height: 1px;
            background: rgba(80, 80, 100, 0.2);
            margin: 0 -20px 12px;
        }

        .menu-btn {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 10px 16px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            color: rgba(240, 240, 240, 0.9);
            font-size: 14px;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 6px;
            flex-shrink: 0;
        }

        .menu-btn:hover {
            background: rgba(255, 255, 255, 0.1);
            border-color: rgba(255, 255, 255, 0.2);
        }

        .menu-btn::before {
            content: "☰";
            font-size: 16px;
        }

        .search-box-header {
            flex: 1;
            max-width: 600px;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 24px;
            padding: 10px 20px;
            font-size: 15px;
            color: rgba(240, 240, 240, 0.7);
            transition: all 0.3s ease;
        }

        .search-box-header:focus {
            outline: none;
            background: rgba(255, 255, 255, 0.08);
            border-color: rgba(255, 255, 255, 0.2);
        }

        .source-btn {
            display: block;
            width: fit-content;
            margin: 16px auto 4px auto;
            padding: 8px 16px;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 6px;
            color: rgba(240, 240, 240, 0.9);
            text-decoration: none;
            font-size: 13px;
            font-weight: 500;
            transition: all 0.3s ease;
        }

        .source-btn:hover {
            background: rgba(255, 255, 255, 0.1);
            border-color: rgba(255, 255, 255, 0.2);
        }

        .source-btn svg {
            width: 14px;
            height: 14px;
            vertical-align: middle;
            margin-left: 6px;
        }

        .drawer-menu {
            position: fixed;
            top: 0;
            left: -280px;
            width: 280px;
            height: 100%;
            background: linear-gradient(135deg, #1e1e2e 0%, #2d2d3f 100%);
            box-shadow: 4px 0 20px rgba(0, 0, 0, 0.5);
            transition: left 0.3s ease;
            z-index: 1000;
            display: flex;
            flex-direction: column;
        }

        .drawer-menu.open {
            left: 0;
        }

        .drawer-header {
            padding: 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .drawer-header h3 {
            color: rgba(240, 240, 240, 0.95);
            margin: 0;
            font-size: 18px;
        }

        .close-drawer {
            background: none;
            border: none;
            color: rgba(240, 240, 240, 0.9);
            font-size: 24px;
            cursor: pointer;
            padding: 5px;
            line-height: 1;
        }

        .drawer-content {
            flex: 1;
            padding: 0;
            overflow-y: auto;
        }

        .drawer-item {
            padding: 16px 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            color: rgba(240, 240, 240, 0.9);
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .drawer-item:hover {
            background: rgba(255, 255, 255, 0.05);
        }

        .drawer-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.5);
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s ease;
            z-index: 999;
        }

        .drawer-overlay.show {
            opacity: 1;
            visibility: visible;
        }

        @media (max-width: 768px) {
            .header {
                padding: 12px 16px 0;
            }

            .header-top {
                gap: 10px;
                margin-bottom: 8px;
            }

            .header-separator {
                margin: 0 -16px 10px;
            }

            .menu-btn {
                padding: 8px 14px;
                font-size: 13px;
            }

            .search-box-header {
                font-size: 14px;
                padding: 9px 16px;
            }

            .source-btn {
                font-size: 12px;
                padding: 7px 14px;
                margin: 14px auto 4px auto;
            }

            .source-btn svg {
                width: 12px;
                height: 12px;
            }

            .drawer-menu {
                width: 250px;
                left: -250px;
            }
        }

        .content {
            padding: 16px 40px 30px 40px;
            line-height: 1.8;
        }

        .content h1, .content h2, .content h3 {
            color: #667eea;
            margin-top: 25px;
            margin-bottom: 15px;
        }

        .content h1 {
            font-size: 26px;
            border-bottom: 2px solid rgba(102, 126, 234, 0.3);
            padding-bottom: 10px;
        }

        .content h2 {
            font-size: 22px;
        }

        .content h3 {
            font-size: 18px;
        }

        .content p {
            margin-bottom: 15px;
            color: rgba(240, 240, 240, 0.9);
        }

        .content ul {
            margin: 15px 0;
            padding-left: 30px;
        }

        .content li {
            margin-bottom: 8px;
            color: rgba(240, 240, 240, 0.85);
        }

        .content strong {
            color: rgba(255, 255, 255, 0.95);
            font-weight: 600;
        }

        .footer {
            background: rgba(20, 20, 30, 0.95);
            padding: 20px;
            text-align: center;
            color: rgba(255, 255, 255, 0.5);
            font-size: 13px;
            border-top: 1px solid rgba(80, 80, 100, 0.3);
        }

        @media (max-width: 768px) {
            .container {
                border-radius: 0;
            }

            .header h1 {
                font-size: 22px;
            }

            .content {
                padding: 12px 20px 25px 20px;
            }
        }
    </style>
</head>
<body>
    <div class="drawer-overlay" id="drawerOverlay" onclick="closeDrawer()"></div>

    <div class="drawer-menu" id="drawerMenu">
        <div class="drawer-header">
            <h3>Menu</h3>
            <button class="close-drawer" onclick="closeDrawer()">×</button>
        </div>
        <div class="drawer-content">
            ${menuItemsHtml}
        </div>
    </div>

    <div class="container">
        <div class="header">
            <div class="header-top">
                <button class="menu-btn" onclick="toggleMenu()">Menu</button>
                <input type="text" class="search-box-header" placeholder="Search..." readonly>
            </div>
            <div class="header-separator"></div>
            <a href="${escapedUrl}" target="_blank" rel="noopener noreferrer" class="source-btn" title="${escapedUrl}">
                View Source
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path>
                    <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path>
                </svg>
            </a>
        </div>
        <div class="content">
            ${htmlContent}
        </div>
        <div class="footer">
            Generated on ${new Date(summaryData.createdAt).toLocaleString()}
        </div>
    </div>
    <script>
        function toggleMenu() {
            const drawer = document.getElementById('drawerMenu');
            const overlay = document.getElementById('drawerOverlay');
            drawer.classList.add('open');
            overlay.classList.add('show');
        }

        function closeDrawer() {
            const drawer = document.getElementById('drawerMenu');
            const overlay = document.getElementById('drawerOverlay');
            drawer.classList.remove('open');
            overlay.classList.remove('show');
        }
    </script>
</body>
</html>
    `.trim();
  }

  // Generate 404 error page
  generate404Page(urlPath) {
    return `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Page Not Found - 404</title>
        <link rel="icon" type="image/png" href="/favicon.png">
        <link rel="shortcut icon" type="image/png" href="/favicon.png">
        <style>
          * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
          }
          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e1e2e 0%, #2d2d3f 100%);
            color: rgba(240, 240, 240, 0.95);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
          }
          .content {
            max-width: 700px;
            width: 100%;
            text-align: center;
          }
          .error-code {
            font-size: 120px;
            font-weight: bold;
            color: rgba(255, 100, 100, 0.8);
            margin-bottom: 20px;
            text-shadow: 0 0 30px rgba(255, 100, 100, 0.3);
          }
          h1 {
            color: rgba(255, 255, 255, 0.95);
            margin-bottom: 15px;
            font-size: 28px;
            font-weight: 500;
          }
          p {
            color: rgba(240, 240, 240, 0.8);
            line-height: 1.8;
            margin-bottom: 25px;
            font-size: 16px;
          }
          .url {
            background: rgba(30, 30, 40, 0.6);
            padding: 12px 16px;
            border-radius: 6px;
            word-break: break-all;
            font-family: monospace;
            font-size: 13px;
            color: rgba(200, 200, 220, 0.9);
            margin-top: 20px;
          }
        </style>
      </head>
      <body>
        <div class="content">
          <div class="error-code">404</div>
          <h1>Page Not Found</h1>
          <p>The page you are looking for does not exist or has been removed. No summary is available for this URL.</p>
          ${urlPath ? `<div class="url">${this.escapeHtml(urlPath)}</div>` : ''}
        </div>
      </body>
      </html>
    `;
  }

  // Generate error page
  generateErrorPage(message, urlPath, isPending = false) {
    if (isPending) {
      // Auto-refreshing pending page with polling
      return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Generating Summary...</title>
          <link rel="icon" type="image/png" href="/favicon.png">
          <link rel="shortcut icon" type="image/png" href="/favicon.png">
          <style>
            * {
              margin: 0;
              padding: 0;
              box-sizing: border-box;
            }
            body {
              font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
              background: linear-gradient(135deg, #1e1e2e 0%, #2d2d3f 100%);
              color: rgba(240, 240, 240, 0.95);
              min-height: 100vh;
              display: flex;
              align-items: center;
              justify-content: center;
              padding: 20px;
            }
            .content {
              max-width: 700px;
              width: 100%;
              text-align: center;
            }
            h1 {
              color: rgba(255, 255, 255, 0.95);
              margin-bottom: 15px;
              font-size: 24px;
              font-weight: 500;
            }
            p {
              color: rgba(240, 240, 240, 0.8);
              line-height: 1.6;
              margin-bottom: 25px;
              font-size: 16px;
            }
            .url {
              background: rgba(30, 30, 40, 0.6);
              padding: 12px 16px;
              border-radius: 6px;
              word-break: break-all;
              font-family: monospace;
              font-size: 13px;
              color: rgba(200, 200, 220, 0.9);
              margin-top: 20px;
            }
            .dots {
              display: inline-block;
              min-width: 20px;
            }
          </style>
        </head>
        <body>
          <div class="content">
            <h1>Generating Summary<span class="dots" id="dots"></span></h1>
            <p>Your content is being processed. The summary will appear automatically when ready.</p>
            ${urlPath ? `<div class="url">${this.escapeHtml(urlPath)}</div>` : ''}
          </div>
          <script>
            let dotCount = 0;
            const dotsEl = document.getElementById('dots');

            // Animate dots
            setInterval(() => {
              dotCount = (dotCount + 1) % 4;
              dotsEl.textContent = '.'.repeat(dotCount);
            }, 500);

            // Poll every 3 seconds
            setInterval(() => {
              window.location.reload();
            }, 3000);
          </script>
        </body>
        </html>
      `;
    }

    // Static error page (no polling)
    return `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Summary Not Available</title>
        <link rel="icon" type="image/png" href="/favicon.png">
        <link rel="shortcut icon" type="image/png" href="/favicon.png">
        <style>
          * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
          }
          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e1e2e 0%, #2d2d3f 100%);
            color: rgba(240, 240, 240, 0.95);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
          }
          .content {
            max-width: 700px;
            width: 100%;
            text-align: center;
          }
          h1 {
            color: rgba(255, 255, 255, 0.95);
            margin-bottom: 15px;
            font-size: 24px;
            font-weight: 500;
          }
          p {
            color: rgba(240, 240, 240, 0.8);
            line-height: 1.6;
            margin-bottom: 25px;
            font-size: 16px;
          }
          .url {
            background: rgba(30, 30, 40, 0.6);
            padding: 12px 16px;
            border-radius: 6px;
            word-break: break-all;
            font-family: monospace;
            font-size: 13px;
            color: rgba(200, 200, 220, 0.9);
            margin-top: 20px;
          }
        </style>
      </head>
      <body>
        <div class="content">
          <h1>Summary Not Available</h1>
          <p>${this.escapeHtml(message)}</p>
          ${urlPath ? `<div class="url">${this.escapeHtml(urlPath)}</div>` : ''}
        </div>
      </body>
      </html>
    `;
  }
}

module.exports = PublicSummaryViewer;