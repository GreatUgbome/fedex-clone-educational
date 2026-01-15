
const AUTH_API = 'https://fedex-clone-educational.onrender.com/api';
let authMode = 'login'; // 'login' or 'signup'

document.addEventListener('DOMContentLoaded', () => {
    checkLoginState();
    checkResetToken();
    checkVerificationToken();
});

function checkLoginState() {
    const authButtons = document.getElementById('authButtons');
    const userStr = localStorage.getItem('fedexUser') || sessionStorage.getItem('fedexUser');

    if (userStr) {
        const user = JSON.parse(userStr);
        authButtons.innerHTML = `
            <span class="text-sm font-medium">Hello, ${user.username}</span>
            <button onclick="openProfileModal()" class="text-sm font-medium hover:text-gray-200 ml-4">Profile</button>
            <button onclick="openUserDashboard()" class="text-sm font-medium hover:text-gray-200 ml-4">Dashboard</button>
            <button onclick="logout()" class="text-sm font-medium hover:text-gray-200 ml-4">Log Out</button>
        `;
    } else {
        authButtons.innerHTML = `
            <button onclick="openAuthModal('signup')" class="text-sm font-medium hover:text-gray-200">Sign Up</button>
            <button onclick="openAuthModal('login')" class="text-sm font-medium hover:text-gray-200 ml-4">Log In</button>
        `;
    }
}

function logout() {
    localStorage.removeItem('fedexUser');
    sessionStorage.removeItem('fedexUser');
    window.location.reload();
}

function openAuthModal(mode) {
    authMode = mode;
    document.getElementById('authModal').classList.remove('hidden');
    updateAuthUI();
}

function closeAuthModal() {
    document.getElementById('authModal').classList.add('hidden');
}

function toggleAuthMode() {
    authMode = authMode === 'login' ? 'signup' : 'login';
    updateAuthUI();
}

function updateAuthUI() {
    const title = document.getElementById('authTitle');
    const switchText = document.getElementById('authSwitchText');
    const switchBtn = document.getElementById('authSwitchBtn');
    const rememberMeContainer = document.getElementById('rememberMeContainer');
    const termsContainer = document.getElementById('termsContainer');
    const forgotPasswordContainer = document.getElementById('forgotPasswordContainer');
    const emailContainer = document.getElementById('emailContainer');

    if (authMode === 'login') {
        title.textContent = 'Log In';
        switchText.textContent = "Don't have an account?";
        switchBtn.textContent = 'Sign Up';
        rememberMeContainer.classList.remove('hidden');
        termsContainer.classList.add('hidden');
        forgotPasswordContainer.classList.remove('hidden');
        emailContainer.classList.add('hidden');
    } else {
        title.textContent = 'Sign Up';
        switchText.textContent = "Already have an account?";
        switchBtn.textContent = 'Log In';
        rememberMeContainer.classList.add('hidden');
        termsContainer.classList.remove('hidden');
        forgotPasswordContainer.classList.add('hidden');
        emailContainer.classList.remove('hidden');
    }
}

async function submitAuth() {
    const username = document.getElementById('authUsername').value;
    const password = document.getElementById('authPassword').value;
    const email = document.getElementById('authEmail').value;
    const rememberMe = document.getElementById('rememberMe').checked;
    const termsAccepted = document.getElementById('termsCheckbox').checked;
    const endpoint = authMode === 'login' ? '/login' : '/signup';

    if (authMode === 'signup' && !termsAccepted) {
        return showToast("You must agree to the Terms & Conditions", "error");
    }
    
    if (authMode === 'signup' && !email) {
        return showToast("Email is required for signup", "error");
    }

    let data;
    try {
        const res = await fetch(`${AUTH_API}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, email })
        });
        data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Request failed');
    } catch (e) {
        return showToast(e.message || "Connection error", "error");
    }

    if (data) {
        if (authMode === 'signup') {
            showToast(data.message, 'success');
            closeAuthModal();
            return;
        }

        // Handle Remember Me
        if (rememberMe) {
            localStorage.setItem('fedexUser', JSON.stringify(data));
        } else {
            sessionStorage.setItem('fedexUser', JSON.stringify(data));
        }

        closeAuthModal();
        checkLoginState();
        if (data.role === 'admin') {
            showToast("Welcome Admin! Access panel in footer.", 'success');
        }
    }
}

// --- Forgot Password Logic ---

function checkResetToken() {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('resetToken');
    if (token) {
        document.getElementById('resetTokenInput').value = token;
        document.getElementById('resetPasswordModal').classList.remove('hidden');
        // Clean URL
        window.history.replaceState({}, document.title, "/");
    }
}

async function checkVerificationToken() {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('verifyToken');
    if (token) {
        try {
            const res = await fetch(`${AUTH_API}/verify-email`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token })
            });
            const data = await res.json();
            if (res.ok) {
                showToast(data.message, 'success');
                if (data.user) {
                    localStorage.setItem('fedexUser', JSON.stringify(data.user));
                    checkLoginState();
                    if (typeof openUserDashboard === 'function') {
                        openUserDashboard();
                    }
                }
            } else {
                showToast(data.error, 'error');
            }
        } catch (e) {
            showToast("Verification failed: Connection error", 'error');
        }
        window.history.replaceState({}, document.title, "/");
    }
}

function openForgotPasswordModal() {
    closeAuthModal();
    document.getElementById('forgotPasswordModal').classList.remove('hidden');
}

function closeForgotPasswordModal() {
    document.getElementById('forgotPasswordModal').classList.add('hidden');
}

async function submitForgotPassword() {
    const email = document.getElementById('forgotEmail').value;
    if (!email) return showToast("Please enter your email", "error");

    try {
        const res = await fetch(`${AUTH_API}/forgot-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        const data = await res.json();
        if (res.ok) {
            showToast(data.message, "success");
            closeForgotPasswordModal();
        } else {
            showToast(data.error, "error");
        }
    } catch (e) {
        showToast("Network error", "error");
    }
}

function openResendVerificationModal() {
    closeAuthModal();
    document.getElementById('resendVerificationModal').classList.remove('hidden');
}

function closeResendVerificationModal() {
    document.getElementById('resendVerificationModal').classList.add('hidden');
}

async function submitResendVerification() {
    const email = document.getElementById('resendVerifyEmail').value;
    if (!email) return showToast("Please enter your email", "error");

    try {
        const res = await fetch(`${AUTH_API}/resend-verification`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        const data = await res.json();
        if (res.ok) {
            showToast(data.message, "success");
            closeResendVerificationModal();
        } else {
            showToast(data.error, "error");
        }
    } catch (e) {
        showToast("Network error", "error");
    }
}

async function deleteProfile() {
    const userStr = localStorage.getItem('fedexUser') || sessionStorage.getItem('fedexUser');
    if (!userStr) return;
    const currentUser = JSON.parse(userStr);

    if (!confirm("Are you sure you want to delete your account? This action cannot be undone.")) return;

    try {
        const res = await fetch(`${AUTH_API}/profile/${currentUser.username}`, {
            method: 'DELETE'
        });
        if (res.ok) {
            showToast("Account deleted successfully", "success");
            logout();
        } else {
            const data = await res.json();
            showToast(data.error || "Failed to delete account", "error");
        }
    } catch (e) {
        showToast("Network error", "error");
    }
}

// --- Profile Logic ---

async function openProfileModal() {
    const userStr = localStorage.getItem('fedexUser') || sessionStorage.getItem('fedexUser');
    if (!userStr) return;
    const user = JSON.parse(userStr);

    // Fetch latest data
    try {
        const res = await fetch(`${AUTH_API}/profile/${user.username}`);
        const profile = await res.json();
        
        document.getElementById('profileUsername').value = profile.username;
        document.getElementById('profileEmail').value = profile.email || '';
        document.getElementById('profilePassword').value = '';
        document.getElementById('profileModal').classList.remove('hidden');
    } catch (e) {
        showToast("Error loading profile", "error");
    }
}

function closeProfileModal() {
    document.getElementById('profileModal').classList.add('hidden');
}

async function saveProfile() {
    const userStr = localStorage.getItem('fedexUser') || sessionStorage.getItem('fedexUser');
    const currentUser = JSON.parse(userStr);
    
    const newUsername = document.getElementById('profileUsername').value;
    const email = document.getElementById('profileEmail').value;
    const password = document.getElementById('profilePassword').value;

    try {
        const res = await fetch(`${AUTH_API}/profile/${currentUser.username}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ newUsername, email, password })
        });
        const data = await res.json();
        if (res.ok) {
            showToast(data.message, "success");
            const storage = localStorage.getItem('fedexUser') ? localStorage : sessionStorage;
            storage.setItem('fedexUser', JSON.stringify(data.user));
            closeProfileModal();
            checkLoginState();
        } else {
            showToast(data.error, "error");
        }
    } catch (e) {
        showToast("Network error", "error");
    }
}

async function submitResetPassword() {
    const token = document.getElementById('resetTokenInput').value;
    const newPassword = document.getElementById('newResetPassword').value;

    try {
        const res = await fetch(`${AUTH_API}/reset-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token, newPassword })
        });
        const data = await res.json();
        if (res.ok) {
            showToast(data.message, "success");
            document.getElementById('resetPasswordModal').classList.add('hidden');
            openAuthModal('login');
        } else {
            showToast(data.error, "error");
        }
    } catch (e) {
        showToast("Network error", "error");
    }
}