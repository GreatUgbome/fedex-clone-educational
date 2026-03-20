const fs = require('fs');
const path = require('path');

// Mock window location before evaluating the script to prevent immediate undefined errors
Object.defineProperty(window, 'location', {
    value: { hostname: 'localhost' },
    writable: true
});

// Read frontend script from filesystem and evaluate it 
// The appended object correctly returns our targeted functions without exporting them natively
const code = fs.readFileSync(path.resolve(__dirname, './auth.js'), 'utf8');
const { updateUIAfterAuth, updateUIAfterLogout, submitAuth } = eval(code + '\n({ updateUIAfterAuth, updateUIAfterLogout, submitAuth });');

describe('Frontend Auth.js DOM Manipulations', () => {
    beforeEach(() => {
        // Setup the simulated DOM structure
        document.body.innerHTML = `
            <button id="authButton">Login</button>
            <div id="profileButton" style="display: none;"></div>
            <div id="adminDashboardLink" style="display: none;"></div>
        `;
        jest.clearAllMocks();
    });

    test('updateUIAfterAuth shows admin dashboard if user has admin claims', async () => {
        // Mock Firebase Auth global object
        window.firebaseAuth = {
            auth: {
                currentUser: {
                    getIdTokenResult: jest.fn().mockResolvedValue({
                        claims: { admin: true }
                    })
                }
            }
        };

        await updateUIAfterAuth();

        expect(document.getElementById('adminDashboardLink').style.display).toBe('block');
        expect(document.getElementById('profileButton').style.display).toBe('block');
        expect(document.getElementById('authButton').textContent).toBe('Logout');
    });

    test('updateUIAfterAuth hides admin dashboard if user lacks admin claims', async () => {
        window.firebaseAuth = {
            auth: {
                currentUser: {
                    getIdTokenResult: jest.fn().mockResolvedValue({ claims: { admin: false } })
                }
            }
        };

        await updateUIAfterAuth();
        expect(document.getElementById('adminDashboardLink').style.display).toBe('none');
    });
    
    test('updateUIAfterLogout resets the UI elements', () => {
        updateUIAfterLogout();
        
        expect(document.getElementById('authButton').textContent).toBe('Login');
        expect(document.getElementById('profileButton').style.display).toBe('none');
        expect(document.getElementById('adminDashboardLink').style.display).toBe('none');
    });
});

describe('Frontend Auth.js submitAuth API interactions', () => {
    beforeEach(() => {
        // Setup the DOM elements expected by submitAuth
        document.body.innerHTML = `
            <form id="signupForm" style="display: none;"></form>
            <input id="authEmail" value="user@fedex.com" />
            <input id="authPassword" value="securepassword123" />
            <div id="authError"></div>
            <div id="loginModal"></div>
            <div id="authButton"></div>
            <div id="profileButton"></div>
            <div id="adminDashboardLink"></div>
        `;
        // Mock fetch and localStorage
        global.fetch = jest.fn();
        Storage.prototype.setItem = jest.fn();
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    test('submitAuth successfully logs in and sets auth token', async () => {
        // Simulate a successful API response
        global.fetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({ token: 'mock-jwt-token' })
        });

        const mockEvent = { preventDefault: jest.fn() };
        await submitAuth(mockEvent);

        expect(global.fetch).toHaveBeenCalledWith(
            expect.stringContaining('/auth/login'),
            expect.objectContaining({
                method: 'POST',
                body: JSON.stringify({ email: 'user@fedex.com', password: 'securepassword123' })
            })
        );
        
        // Verify UI behaviors and token storage
        expect(localStorage.setItem).toHaveBeenCalledWith('authToken', 'mock-jwt-token');
        expect(document.getElementById('loginModal').style.display).toBe('none');
    });

    test('submitAuth correctly handles API error responses', async () => {
        // Simulate a failed login attempt (e.g., 401 Unauthorized)
        global.fetch.mockResolvedValueOnce({
            ok: false,
            json: async () => ({ message: 'Invalid credentials' })
        });

        const mockEvent = { preventDefault: jest.fn() };
        await submitAuth(mockEvent);

        // Assert the error element is populated and displayed
        expect(document.getElementById('authError').textContent).toBe('Invalid credentials');
        expect(document.getElementById('authError').style.display).toBe('block');
    });

    test('submitAuth blocks signup if password is less than 8 characters', async () => {
        document.getElementById('signupForm').style.display = 'block'; // Simulate signup mode
        document.getElementById('authPassword').value = 'short'; // Set password to < 8 chars

        const mockEvent = { preventDefault: jest.fn() };
        await submitAuth(mockEvent);

        expect(document.getElementById('authError').textContent).toBe('Password must be at least 8 characters long');
        expect(global.fetch).not.toHaveBeenCalled(); // Ensures the API is not hit
    });
});