let currentUser = null;
let userToken = null;

function checkAuthentication() {
    const sessionId = localStorage.getItem('sessionId');
    const csrfToken = localStorage.getItem('csrfToken');

    if (!sessionId || !csrfToken) {
        return false;
    }

    userToken = { sessionId, csrfToken };
    return true;
}


function showError(elementId, message) {
    const errorElement = document.getElementById(elementId);
    if (errorElement) {
        errorElement.textContent = message;
        errorElement.style.display = 'block';
    }
}


function showSuccess(elementId, message) {
    const successElement = document.getElementById(elementId);
    if (successElement) {
        successElement.textContent = message;
        successElement.style.display = 'block';
    }
}


function clearMessages() {
    const errorElements = document.querySelectorAll('.error-message');
    const successElements = document.querySelectorAll('.success-message');

    errorElements.forEach(el => el.style.display = 'none');
    successElements.forEach(el => el.style.display = 'none');
}

async function makeRequest(url, method = 'GET', data = null) {
    const options = {
        method,
        headers: {
            'Content-Type': 'application/json',
        }
    };

    
    if (userToken) {
        options.headers['x-session-id'] = userToken.sessionId;
        options.headers['x-csrf-token'] = userToken.csrfToken;
    } 
    if (data) {
        options.body = JSON.stringify(data);
    }

    try {
        const response = await fetch(url, options);
        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Server connection error');
        }

        return result;
    } catch (error) {
        throw new Error(error.message || 'Server connection error');
    }
}

if (document.getElementById('loginForm')) {
    document.getElementById('loginForm').addEventListener('submit', async function(e) {
        e.preventDefault();
        clearMessages();

        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        try {
            const result = await makeRequest('/api/login', 'POST', {
                username,
                password
            });

            if (result.success) {
                // ذخیره توکن‌ها
                localStorage.setItem('sessionId', result.session.sessionId);
                localStorage.setItem('csrfToken', result.session.csrfToken);
                localStorage.setItem('user', JSON.stringify(result.user));

                showSuccess('successMessage', 'Login successful. Redirecting...');

                setTimeout(() => {
                    window.location.href = 'index.html';
                }, 1000);
            }
        } catch (error) {
            showError('errorMessage', error.message);
        }
    });
}


if (document.getElementById('registerForm')) {
    document.getElementById('registerForm').addEventListener('submit', async function(e) {
        e.preventDefault();
        clearMessages();

        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const securityQuestion = document.getElementById('securityQuestion').value;
        const securityAnswer = document.getElementById('securityAnswer').value;

        try {
            const result = await makeRequest('/api/register', 'POST', {
                username,
                password,
                securityQuestion,
                securityAnswer
            });

            if (result.success) {
                showSuccess('successMessage', 'Registration successful. Redirecting to login page...');

                setTimeout(() => {
                    window.location.href = 'login.html';
                }, 2000);
            }
        } catch (error) {
            showError('errorMessage', error.message);
        }
    });
}

let currentResetToken = null; 

if (document.getElementById('verifyForm')) {

    
    document.getElementById('getQuestionBtn').addEventListener('click', async function() {
        clearMessages();

        const username = document.getElementById('username').value;
        if (!username) {
            showError('errorMessage', 'Please enter a username');
            return;
        }

        try {
            const result = await makeRequest(`/api/security-question/${username}`);

            if (result.success) {
                document.getElementById('questionSection').style.display = 'block';
                document.getElementById('securityQuestion').textContent = result.securityQuestion;
                showSuccess('successMessage', 'Security question retrieved');
            }
        } catch (error) {
            showError('errorMessage', error.message);
        }
    });

    
    document.getElementById('answerForm').addEventListener('submit', async function(e) {
        e.preventDefault();
        clearMessages();

        const username = document.getElementById('username').value;
        const securityAnswer = document.getElementById('securityAnswer').value;

        try {
            const result = await makeRequest('/api/forgot-password/verify', 'POST', {
                username,
                securityAnswer
            });

            if (result.success) {
                currentResetToken = result.resetToken;
                document.getElementById('verifyStep').style.display = 'none';
                document.getElementById('resetStep').style.display = 'block';
                showSuccess('successMessage', 'Answer verified. Please set your new password.');
            }
        } catch (error) {
            showError('errorMessage', error.message);
        }
    });
} 
if (document.getElementById('resetForm')) {
    document.getElementById('resetForm').addEventListener('submit', async function(e) {
        e.preventDefault();
        clearMessages();

        const newPassword = document.getElementById('newPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;

        if (newPassword !== confirmPassword) {
            showError('errorMessage', 'Passwords do not match');
            return;
        }

        try {
            const result = await makeRequest('/api/forgot-password/reset', 'POST', {
                resetToken: currentResetToken,
                newPassword
            });

            if (result.success) {
                showSuccess('successMessage', 'Password changed successfully. Redirecting to login page...');

                setTimeout(() => {
                    window.location.href = 'login.html';
                }, 2000);
            }
        } catch (error) {
            showError('errorMessage', error.message);
        }
    });
}

// Main pag e
async function loadUserProfile() {
    try {
        const result = await makeRequest('/api/profile');

        if (result.success) {
            const user = result.user;
            document.getElementById('welcomeMessage').textContent = `Welcome, ${user.username}`;

            // Set user avatar initial
            const userAvatar = document.getElementById('userAvatar');
            if (userAvatar) {
                userAvatar.textContent = user.username.charAt(0).toUpperCase();
            }

            // Update other profile elements if they exist (for other pages)
            const userUsernameEl = document.getElementById('userUsername');
            const userCreatedAtEl = document.getElementById('userCreatedAt');
            const userLastLoginEl = document.getElementById('userLastLogin');

            if (userUsernameEl) userUsernameEl.textContent = user.username;
            if (userCreatedAtEl) userCreatedAtEl.textContent = new Date(user.created_at).toLocaleDateString('en-US');
            if (userLastLoginEl) userLastLoginEl.textContent = user.last_login ? 
                new Date(user.last_login).toLocaleDateString('en-US') : 'First login';
        }
    } catch (error) {
        console.error('Error loading user profile:', error);
        // Redirect to login on error
        localStorage.clear();
        window.location.href = 'login.html';
    }
}


if (document.getElementById('userInfo')) {
    const userInfo = document.getElementById('userInfo');
    const dropdownMenu = document.getElementById('dropdownMenu');

    userInfo.addEventListener('click', function(e) {
        e.stopPropagation();
        dropdownMenu.classList.toggle('show');
    });
    document.addEventListener('click', function() {
        dropdownMenu.classList.remove('show');
    });

    
    dropdownMenu.addEventListener('click', function(e) {
        e.stopPropagation();
    });
}


if (document.getElementById('logoutBtn')) {
    document.getElementById('logoutBtn').addEventListener('click', async function() {
        try {
            await makeRequest('/api/logout', 'POST');
        } catch (error) {
            console.error('Logout error:', error);
        } finally { 
            localStorage.clear();
            window.location.href = 'login.html';
        }
    });
}
