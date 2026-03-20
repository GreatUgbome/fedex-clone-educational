// Auth API endpoint
const AUTH_API = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') 
    ? 'http://localhost:5002/api' 
    : '/api'; // Firebase Hosting rewrites automatically forward this to your Cloud Function

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
    
    const email = document.getElementById('loginEmail')?.value;
    const password = document.getElementById('loginPassword')?.value;
    const signupName = document.getElementById('signupName')?.value;
    
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');
    const signupNameGroup = document.getElementById('signupNameGroup');
    
    let isSignup = false;
    if (loginForm && signupForm) {
        isSignup = signupForm.style.display !== 'none';
    } else if (signupNameGroup) {
        isSignup = signupNameGroup.style.display !== 'none';
    }

    if (!email || !password) {
        showAuthError('Please enter email and password');
        return;
    }

    if (isSignup) {
        if (!signupName) {
            showAuthError('Please enter your full name');
            return;
        }
        if (password.length < 8) {
        showAuthError('Password must be at least 8 characters and contain uppercase, lowercase, numbers, and symbols');
            return;
        }
    }

    try {
        const url = isSignup ? `${AUTH_API}/auth/signup` : `${AUTH_API}/auth/login`;
        
        const body = isSignup 
            ? { username: signupName, email, password }
            : { username: email, password };
        
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || errorData.message || 'Auth failed');
        }

        const data = await response.json();
        
        // Check if verification is required
        if (data.requiresVerification) {
            showAuthSuccess(data.message);
            // Clear form and close modal after a delay
            setTimeout(() => {
                if (isSignup) {
                    // Clear signup fields
                    const signupName = document.getElementById('signupName');
                    const loginEmail = document.getElementById('loginEmail');
                    const loginPassword = document.getElementById('loginPassword');
                    if (signupName) signupName.value = '';
                    if (loginEmail) loginEmail.value = '';
                    if (loginPassword) loginPassword.value = '';
                }
                closeAuthModal();
            }, 3000);
            return;
        }
        
        // Normal login flow - store token
        localStorage.setItem('authToken', data.token || JSON.stringify(data));
        closeAuthModal();
        showAuthSuccess(data.message || 'Welcome!');
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
    const signupNameGroup = document.getElementById('signupNameGroup');
    const authSubmitBtn = document.getElementById('authSubmitBtn');
    const authModalTitle = document.getElementById('authModalTitle');
    const authToggleText = document.getElementById('authToggleText');
    const authToggleLink = document.getElementById('authToggleLink');
    const forgotPasswordLink = document.getElementById('forgotPasswordLink');
    const loginEmail = document.getElementById('loginEmail');
    const loginPassword = document.getElementById('loginPassword');
    const signupName = document.getElementById('signupName');
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');
    
    if (loginForm && signupForm) {
        const isLogin = loginForm.style.display !== 'none';
        loginForm.style.display = isLogin ? 'none' : 'block';
        signupForm.style.display = isLogin ? 'block' : 'none';
        
        if (authModalTitle) authModalTitle.textContent = isLogin ? 'Sign Up' : 'Log In';
    } else if (signupNameGroup) {
        const isLogin = signupNameGroup.style.display === 'none';
        signupNameGroup.style.display = isLogin ? 'block' : 'none';
        
        if (forgotPasswordLink) forgotPasswordLink.style.display = isLogin ? 'none' : 'block';
        
        if (isLogin) {
            if (authModalTitle) authModalTitle.textContent = 'Sign Up';
            if (authSubmitBtn) authSubmitBtn.textContent = 'Sign Up';
            if (authToggleText) authToggleText.textContent = 'Already have an account?';
            if (authToggleLink) authToggleLink.textContent = 'Log In';
        } else {
            if (authModalTitle) authModalTitle.textContent = 'Log In';
            if (authSubmitBtn) authSubmitBtn.textContent = 'Log In';
            if (authToggleText) authToggleText.textContent = "Don't have an account?";
            if (authToggleLink) authToggleLink.textContent = 'Sign Up';
        }
    }
    
    // Clear form fields
    if (loginEmail) loginEmail.value = '';
    if (loginPassword) loginPassword.value = '';
    if (signupName) signupName.value = '';
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

// Upload Avatar
async function uploadAvatar() {
    const fileInput = document.getElementById('profileAvatarInput');
    if (!fileInput || !fileInput.files || !fileInput.files[0]) {
        showAuthError('Please select an image file first');
        return;
    }

    const username = document.getElementById('profileUsername')?.value || 'me';
    const formData = new FormData();
    formData.append('avatar', fileInput.files[0]);

    try {
        const headers = await getAuthHeaders();
        // Delete Content-Type to let the browser automatically set the multipart boundary
        delete headers['Content-Type'];

        const response = await fetch(`${AUTH_API}/profile/${username}/avatar`, {
            method: 'POST',
            headers: headers,
            body: formData
        });

        if (!response.ok) throw new Error('Could not upload avatar');

        const data = await response.json();
        const avatarPreview = document.getElementById('profileAvatarPreview');
        if (avatarPreview) avatarPreview.src = data.avatarUrl;

        showAuthSuccess('Avatar uploaded successfully');
    } catch (error) {
        console.error('Avatar upload error:', error);
        showAuthError(error.message);
    }
}

// Logout
function handleLogout() {
    localStorage.removeItem('authToken');
    updateUIAfterLogout();
    showAuthSuccess('Logged out');
}

// Update UI after auth
async function updateUIAfterAuth() {
    const authBtn = document.getElementById('authButton');
    const profileBtn = document.getElementById('profileButton');
    const adminDashboardLink = document.getElementById('adminDashboardLink');
    
    if (authBtn) {
        authBtn.textContent = 'Logout';
        authBtn.onclick = handleLogout;
    }
    if (profileBtn) profileBtn.style.display = 'block';

    let isAdmin = false;
    try {
        const storedAuth = localStorage.getItem('authToken');
        if (storedAuth && storedAuth.startsWith('{')) {
            const user = JSON.parse(storedAuth);
            if (user.role === 'admin') isAdmin = true;
        }
    } catch (e) {}

    // Check for Firebase custom claims
    if (window.firebaseAuth && window.firebaseAuth.auth && window.firebaseAuth.auth.currentUser) {
        try {
            const idTokenResult = await window.firebaseAuth.auth.currentUser.getIdTokenResult();
            if (idTokenResult.claims.admin) {
                isAdmin = true;
            }
        } catch (error) {
            console.error('Error fetching custom claims:', error);
        }
    }

    if (adminDashboardLink) adminDashboardLink.style.display = isAdmin ? 'block' : 'none';

    // Fetch and display the user's avatar from the database
    try {
        // Replace 'me' with actual username reference if dynamically managed in your app
        const username = document.getElementById('profileUsername')?.value || 'me';
        const response = await fetch(`${AUTH_API}/profile/${username}/avatar`, {
            headers: await getAuthHeaders()
        });
        if (response.ok) {
            const data = await response.json();
            const avatarPreview = document.getElementById('profileAvatarPreview');
            if (data.avatarUrl && avatarPreview) {
                avatarPreview.src = data.avatarUrl;
            }
        }
    } catch (error) {
        console.error('Error fetching avatar:', error);
    }
}

// Update UI after logout
function updateUIAfterLogout() {
    const authBtn = document.getElementById('authButton');
    const profileBtn = document.getElementById('profileButton');
    const adminDashboardLink = document.getElementById('adminDashboardLink');
    
    if (authBtn) {
        authBtn.textContent = 'Login';
        authBtn.onclick = openAuthModal;
    }
    if (profileBtn) profileBtn.style.display = 'none';
    if (adminDashboardLink) adminDashboardLink.style.display = 'none';
}

// Show auth error
function showAuthError(message) {
    const errorEl = document.getElementById('authError');
    const errorText = document.getElementById('authErrorText');
    if (errorEl && errorText) {
        errorText.textContent = message;
        errorEl.style.display = 'block';
        // Auto-hide after 5 seconds
        setTimeout(() => {
            errorEl.style.display = 'none';
        }, 5000);
    }
    console.error('Auth error:', message);
}

// Show auth success
function showAuthSuccess(message) {
    const successEl = document.getElementById('authSuccess');
    const successText = document.getElementById('authSuccessText');
    if (successEl && successText) {
        successText.textContent = message;
        successEl.style.display = 'block';
        // Auto-hide after 5 seconds
        setTimeout(() => {
            successEl.style.display = 'none';
        }, 5000);
    }
    console.log('Auth success:', message);
}

// Google login (stub)
function handleGoogleLogin() {
    console.log('Google login not fully configured yet');
    showAuthError('Google login not available');
}

// Check for verification token in URL and handle it
function checkVerificationToken() {
    const params = new URLSearchParams(window.location.search);
    const verifyToken = params.get('verifyToken');
    
    if (verifyToken) {
        // Show verification modal with token auto-filled
        openAuthModal();
        showVerificationForm(verifyToken);
    }
}

// Check for password reset token in URL and handle it
function checkResetToken() {
    const params = new URLSearchParams(window.location.search);
    const resetToken = params.get('resetToken');
    
    if (resetToken) {
        // Show password reset form with token
        openAuthModal();
        showPasswordResetForm(resetToken);
    }
}

// Show verification form
function showVerificationForm(token) {
    const modal = document.getElementById('loginModal');
    const authModalTitle = document.getElementById('authModalTitle');
    const formContainer = document.querySelector('.auth-form-container') || modal.querySelector('form');
    
    if (modal) {
        // Hide login form
        const form = modal.querySelector('form');
        if (form) form.style.display = 'none';
        
        // Create or show verification form
        let verificationForm = document.getElementById('verificationForm');
        if (!verificationForm) {
            verificationForm = document.createElement('form');
            verificationForm.id = 'verificationForm';
            verificationForm.className = 'space-y-4';
            verificationForm.innerHTML = `
                <div class="bg-blue-50 border border-blue-200 rounded p-4 mb-4">
                    <p class="text-sm text-blue-800">
                        <i class="fas fa-info-circle mr-2"></i>
                        Click the button below to verify your email address.
                    </p>
                </div>
                <input type="hidden" id="verificationToken" value="${token}">
            <button type="button" onclick="submitVerifyEmail()" class="w-full bg-orange-500 text-white font-bold py-2 rounded hover:bg-orange-600 transition">
                    Verify Email Address
                </button>
                <button type="button" onclick="backToLogin()" class="w-full bg-gray-300 text-gray-700 font-bold py-2 rounded hover:bg-gray-400 transition">
                    Cancel
                </button>
            `;
            const formContainer = modal.querySelector('form').parentElement;
            formContainer.appendChild(verificationForm);
        } else {
            verificationForm.style.display = 'block';
            document.getElementById('verificationToken').value = token;
        }
        
        authModalTitle.textContent = 'Verify Email';
    }
}

// Show password reset form
function showPasswordResetForm(token) {
    const modal = document.getElementById('loginModal');
    const authModalTitle = document.getElementById('authModalTitle');
    
    if (modal) {
        // Hide login form
        const form = modal.querySelector('form');
        if (form) form.style.display = 'none';
        
        // Create or show reset form
        let resetForm = document.getElementById('resetPasswordForm');
        if (!resetForm) {
            resetForm = document.createElement('form');
            resetForm.id = 'resetPasswordForm';
            resetForm.className = 'space-y-4';
            resetForm.innerHTML = `
                <div class="bg-blue-50 border border-blue-200 rounded p-4 mb-4">
                    <p class="text-sm text-blue-800">
                        <i class="fas fa-lock mr-2"></i>
                        Enter your new password below.
                    </p>
                </div>
                <input type="hidden" id="resetToken" value="${token}">
                <div>
                    <label class="block text-gray-700 text-sm font-bold mb-2">New Password</label>
                <input type="password" id="newPassword" placeholder="••••••••" class="w-full border border-gray-300 p-2 rounded focus:outline-none focus:border-purple-600" required>
                <small class="text-gray-500">Must be 8+ chars with uppercase, lowercase, numbers, and symbols.</small>
                </div>
                <div>
                    <label class="block text-gray-700 text-sm font-bold mb-2">Confirm Password</label>
                <input type="password" id="confirmPassword" placeholder="••••••••" class="w-full border border-gray-300 p-2 rounded focus:outline-none focus:border-purple-600" required>
                </div>
            <button type="button" onclick="submitResetPassword()" class="w-full bg-orange-500 text-white font-bold py-2 rounded hover:bg-orange-600 transition">
                    Reset Password
                </button>
                <button type="button" onclick="backToLogin()" class="w-full bg-gray-300 text-gray-700 font-bold py-2 rounded hover:bg-gray-400 transition">
                    Cancel
                </button>
            `;
            const formContainer = modal.querySelector('form').parentElement;
            formContainer.appendChild(resetForm);
        } else {
            resetForm.style.display = 'block';
            document.getElementById('resetToken').value = token;
        }
        
        authModalTitle.textContent = 'Reset Password';
    }
}

// Submit email verification
async function submitVerifyEmail() {
    const token = document.getElementById('verificationToken')?.value;
    if (!token) {
        showAuthError('Verification token not found');
        return;
    }

    try {
        const response = await fetch(`${AUTH_API}/auth/verify-email`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Verification failed');
        }

        const data = await response.json();
        localStorage.setItem('authToken', JSON.stringify(data.user));
        showAuthSuccess(data.message);
        setTimeout(() => {
            closeAuthModal();
            updateUIAfterAuth();
        }, 2000);
        
    } catch (error) {
        console.error('Verification error:', error);
        showAuthError(error.message);
    }
}

// Submit password reset
async function submitResetPassword() {
    const token = document.getElementById('resetToken')?.value;
    const newPassword = document.getElementById('newPassword')?.value;
    const confirmPassword = document.getElementById('confirmPassword')?.value;
    
    if (!token || !newPassword || !confirmPassword) {
        showAuthError('Please fill in all fields');
        return;
    }
    
    if (newPassword.length < 8) {
        showAuthError('Password must be at least 8 characters and contain uppercase, lowercase, numbers, and symbols');
        return;
    }
    
    if (newPassword !== confirmPassword) {
        showAuthError('Passwords do not match');
        return;
    }

    try {
        const response = await fetch(`${AUTH_API}/auth/reset-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token, newPassword })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Password reset failed');
        }

        showAuthSuccess('Password reset successfully! You can now log in.');
        setTimeout(() => {
            backToLogin();
        }, 2000);
        
    } catch (error) {
        console.error('Password reset error:', error);
        showAuthError(error.message);
    }
}

// Back to login form
function backToLogin() {
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');
    const forgotForm = document.getElementById('forgotForm');
    const verificationForm = document.getElementById('verificationForm');
    const resetForm = document.getElementById('resetPasswordForm');
    const signupNameGroup = document.getElementById('signupNameGroup');
    const forgotPasswordLink = document.getElementById('forgotPasswordLink');

    if (verificationForm) verificationForm.style.display = 'none';
    if (resetForm) resetForm.style.display = 'none';
    if (forgotForm) forgotForm.style.display = 'none';
    if (signupForm) signupForm.style.display = 'none';
    
    if (loginForm) {
        loginForm.style.display = 'block';
    } else {
        const modal = document.getElementById('loginModal');
        const firstForm = modal ? modal.querySelector('form') : null;
        if (firstForm) firstForm.style.display = 'block';
    }
    
    if (signupNameGroup) signupNameGroup.style.display = 'none';
    if (forgotPasswordLink) forgotPasswordLink.style.display = 'block';

    const authModalTitle = document.getElementById('authModalTitle');
    const authSubmitBtn = document.getElementById('authSubmitBtn');
    const authToggleText = document.getElementById('authToggleText');
    const authToggleLink = document.getElementById('authToggleLink');

    if (authModalTitle) authModalTitle.textContent = 'Log In';
    if (authSubmitBtn) authSubmitBtn.textContent = 'Log In';
    if (authToggleText) authToggleText.textContent = "Don't have an account?";
    if (authToggleLink) authToggleLink.textContent = 'Sign Up';
}

// DOMContentLoaded setup
document.addEventListener('DOMContentLoaded', function() {
    console.log('Auth module loaded');
    
    // Check for verification token in URL
    checkVerificationToken();
    
    // Check for password reset token in URL
    checkResetToken();
    
    // Monitor authentication state using Firebase's built-in observer
    if (window.firebaseAuth && window.firebaseAuth.auth) {
        window.firebaseAuth.auth.onAuthStateChanged((user) => {
            if (user) {
                updateUIAfterAuth();
            } else if (!localStorage.getItem('authToken')) {
                // Avoid auto-logout if a valid custom JWT token exists in storage
                updateUIAfterLogout();
            }
        });
    } else {
        // Fallback for missing Firebase instance
        const token = localStorage.getItem('authToken');
        if (token) {
            updateUIAfterAuth();
        } else {
            updateUIAfterLogout();
        }
    }

    // Close modals when clicking outside of them
    window.addEventListener('click', function(event) {
        const loginModal = document.getElementById('loginModal');
        const profileModal = document.getElementById('profileModal');
        if (event.target === loginModal) closeAuthModal();
        if (event.target === profileModal) closeProfileModal();
    });

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

    const avatarUploadBtn = document.getElementById('avatarUploadBtn');
    if (avatarUploadBtn) {
        avatarUploadBtn.addEventListener('click', uploadAvatar);
    }
});
