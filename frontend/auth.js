// Auth API endpoint
const AUTH_API = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') 
    ? 'http://localhost:5002/api' 
    : 'https://us-central1-fedex-37e89.cloudfunctions.net/api';

console.log('Auth API:', AUTH_API);

// Helper to get auth headers
async function getAuthHeaders() {
    const headers = { 'Content-Type': 'application/json' };
    if (window.firebaseAuth && window.firebaseAuth.auth && window.firebaseAuth.auth.currentUser) {
        try {
            const token = await window.firebaseAuth.auth.currentUser.getIdToken(true);
            headers['Authorization'] = `Bearer ${token}`;
        } catch (e) {
            console.error('Could not get auth token:', e);
        }
    }
    return headers;
}

// Open auth modal
function openAuthModal() {
    const modal = document.getElementById('loginModal');
    if (modal) modal.style.display = 'block';
}

// Close auth modal
function closeAuthModal() {
    const modal = document.getElementById('loginModal');
    if (modal) modal.style.display = 'none';
}

// Open profile modal
function openProfileModal() {
    const modal = document.getElementById('profileModal');
    if (modal) modal.style.display = 'block';
}

// Close profile modal
function closeProfileModal() {
    const modal = document.getElementById('profileModal');
    if (modal) modal.style.display = 'none';
}

// Submit auth (login/signup)
async function submitAuth(e) {
    if (e) e.preventDefault();
    
    const email = document.getElementById('authEmail')?.value;
    const password = document.getElementById('authPassword')?.value;
    const isSignup = document.getElementById('signupForm')?.style.display !== 'none';

    if (!email || !password) {
        showAuthError('Please enter email and password');
        return;
    }

    try {
        const url = isSignup ? `${AUTH_API}/auth/register` : `${AUTH_API}/auth/login`;
        
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Auth failed');
        }

        const data = await response.json();
        localStorage.setItem('authToken', data.token);
        closeAuthModal();
        updateUIAfterAuth();
        
    } catch (error) {
        console.error('Auth error:', error);
        showAuthError(error.message || 'Authentication failed');
    }
}

// Submit forgot password
async function submitForgotPassword(e) {
    if (e) e.preventDefault();
    
    const email = document.getElementById('forgotEmail')?.value;
    if (!email) {
        showAuthError('Please enter your email');
        return;
    }

    try {
        const response = await fetch(`${AUTH_API}/auth/forgot-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });

        if (!response.ok) {
            throw new Error('Could not send reset email');
        }

        showAuthSuccess('Password reset link sent to your email');
        setTimeout(() => closeAuthModal(), 2000);
        
    } catch (error) {
        console.error('Forgot password error:', error);
        showAuthError(error.message);
    }
}

// Toggle auth mode (login vs signup)
function toggleAuthMode() {
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');
    const forgotForm = document.getElementById('forgotForm');
    
    if (!loginForm || !signupForm) return;

    const isLogin = loginForm.style.display !== 'none';
    loginForm.style.display = isLogin ? 'none' : 'block';
    signupForm.style.display = isLogin ? 'block' : 'none';
    if (forgotForm) forgotForm.style.display = 'none';
}

// Show forgot password form
function showForgotPasswordForm() {
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');
    const forgotForm = document.getElementById('forgotForm');
    
    if (loginForm) loginForm.style.display = 'none';
    if (signupForm) signupForm.style.display = 'none';
    if (forgotForm) forgotForm.style.display = 'block';
}

// Back to login
function backToLogin() {
    const loginForm = document.getElementById('loginForm');
    const forgotForm = document.getElementById('forgotForm');
    
    if (loginForm) loginForm.style.display = 'block';
    if (forgotForm) forgotForm.style.display = 'none';
}

// Delete profile
async function deleteProfile() {
    if (!confirm('Are you sure you want to delete your profile? This cannot be undone.')) {
        return;
    }

    try {
        const response = await fetch(`${AUTH_API}/auth/profile`, {
            method: 'DELETE',
            headers: await getAuthHeaders()
        });

        if (!response.ok) {
            throw new Error('Could not delete profile');
        }

        localStorage.removeItem('authToken');
        closeProfileModal();
        updateUIAfterLogout();
        showAuthSuccess('Profile deleted');
        
    } catch (error) {
        console.error('Delete profile error:', error);
        showAuthError(error.message);
    }
}

// Update profile
async function updateProfile(e) {
    if (e) e.preventDefault();

    try {
        const response = await fetch(`${AUTH_API}/auth/profile`, {
            method: 'PUT',
            headers: await getAuthHeaders(),
            body: JSON.stringify(getProfileFormData())
        });

        if (!response.ok) {
            throw new Error('Could not update profile');
        }

        showAuthSuccess('Profile updated');
        closeProfileModal();
        
    } catch (error) {
        console.error('Update profile error:', error);
        showAuthError(error.message);
    }
}

// Get profile form data
function getProfileFormData() {
    return {
        firstName: document.getElementById('profileFirstName')?.value || '',
        lastName: document.getElementById('profileLastName')?.value || '',
        phone: document.getElementById('profilePhone')?.value || '',
        address: document.getElementById('profileAddress')?.value || ''
    };
}

// Logout
function handleLogout() {
    localStorage.removeItem('authToken');
    updateUIAfterLogout();
    showAuthSuccess('Logged out');
}

// Update UI after auth
function updateUIAfterAuth() {
    const authBtn = document.getElementById('authButton');
    const profileBtn = document.getElementById('profileButton');
    
    if (authBtn) {
        authBtn.textContent = 'Logout';
        authBtn.onclick = handleLogout;
    }
    if (profileBtn) profileBtn.style.display = 'block';
}

// Update UI after logout
function updateUIAfterLogout() {
    const authBtn = document.getElementById('authButton');
    const profileBtn = document.getElementById('profileButton');
    
    if (authBtn) {
        authBtn.textContent = 'Login';
        authBtn.onclick = openAuthModal;
    }
    if (profileBtn) profileBtn.style.display = 'none';
}

// Show auth error
function showAuthError(message) {
    const errorEl = document.getElementById('authError');
    if (errorEl) {
        errorEl.textContent = message;
        errorEl.style.display = 'block';
    }
    console.error('Auth error:', message);
}

// Show auth success
function showAuthSuccess(message) {
    const successEl = document.getElementById('authSuccess');
    if (successEl) {
        successEl.textContent = message;
        successEl.style.display = 'block';
        setTimeout(() => {
            successEl.style.display = 'none';
        }, 3000);
    }
    console.log('Auth success:', message);
}

// Google login (stub)
function handleGoogleLogin() {
    console.log('Google login not fully configured yet');
    showAuthError('Google login not available');
}

// DOMContentLoaded setup
document.addEventListener('DOMContentLoaded', function() {
    console.log('Auth module loaded');
    
    // Check if user is logged in
    const token = localStorage.getItem('authToken');
    if (token) {
        updateUIAfterAuth();
    }

    // Setup form submissions
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');
    const forgotForm = document.getElementById('forgotForm');
    const profileForm = document.getElementById('profileForm');

    if (loginForm) {
        loginForm.addEventListener('submit', submitAuth);
    }
    if (signupForm) {
        signupForm.addEventListener('submit', submitAuth);
    }
    if (forgotForm) {
        forgotForm.addEventListener('submit', submitForgotPassword);
    }
    if (profileForm) {
        profileForm.addEventListener('submit', updateProfile);
    }
});
