// Force Firebase URL for production, localhost for local dev
const API_BASE_URL = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') 
    ? 'http://localhost:5002' 
    : 'https://us-central1-fedex-37e89.cloudfunctions.net';

console.log('API Base URL:', API_BASE_URL);

// Example tracking data for demo
const EXAMPLE_TRACKING = {
    trackingNumber: '123456789012',
    status: 'out_for_delivery',
    statusText: 'Out for Delivery',
    statusDetail: 'Package is out for delivery today',
    service: 'FedEx Ground',
    weight: '2.5 lbs',
    estimatedDelivery: 'Today, 5:00 PM',
    deliveryDate: 'Today, 5:00 PM',
    destination: 'San Francisco, CA',
    sender: 'Acme Corp, New York, NY',
    recipient: 'John Doe, San Francisco, CA',
    timeline: [
        { date: new Date(), description: 'Out for delivery', location: 'San Francisco, CA' },
        { date: new Date(Date.now() - 86400000), description: 'In transit', location: 'Los Angeles, CA' },
        { date: new Date(Date.now() - 172800000), description: 'Picked up', location: 'New York, NY' }
    ]
};

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

// Enhanced tracking function
async function trackPackage() {
    const trackingNumber = document.getElementById('trackingInput').value.trim();
    const resultsSection = document.getElementById('resultsSection');
    const errorSection = document.getElementById('errorSection');

    resultsSection.style.display = 'none';
    errorSection.style.display = 'none';

    if (!trackingNumber) {
        showError('Please enter a tracking number');
        return;
    }

    const originalValue = document.getElementById('trackingInput').value;
    document.getElementById('trackingInput').value = 'Tracking...';
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/track/${trackingNumber}`, {
            headers: await getAuthHeaders()
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Tracking not found');
        }

        const packageData = await response.json();
        displayPackageInfo(packageData);
        resultsSection.style.display = 'block';
        hideError();
        
    } catch (error) {
        console.error('Track error:', error);
        showError(error.message || 'Could not track package. Please try again.');
    } finally {
        document.getElementById('trackingInput').value = originalValue;
    }
}

// Enhanced package display
function displayPackageInfo(pkg) {
    document.getElementById('statusTitle').textContent = pkg.statusText || pkg.statusDetail || pkg.status;
    document.getElementById('statusSubtitle').textContent = getStatusSubtitle(pkg.status);
    document.getElementById('displayTracking').textContent = pkg.trackingNumber || pkg.id;
    document.getElementById('displayService').textContent = pkg.service;
    document.getElementById('displayDelivery').textContent = pkg.estimatedDelivery || pkg.deliveryDate;

    const statusIcon = document.getElementById('statusMainIcon');
    statusIcon.className = getStatusIcon(pkg.status);

    document.getElementById('infoTracking').textContent = pkg.trackingNumber || pkg.id;
    document.getElementById('infoStatus').textContent = pkg.statusText || pkg.statusDetail || pkg.status;
    document.getElementById('infoStatus').className = `status-badge ${pkg.status}`;
    document.getElementById('infoService').textContent = pkg.service;
    document.getElementById('infoWeight').textContent = pkg.weight;
    document.getElementById('infoDelivery').textContent = pkg.estimatedDelivery || pkg.deliveryDate;
    document.getElementById('infoDestination').textContent = pkg.destination;

    const timeline = document.getElementById('timeline');
    timeline.innerHTML = '';

    if (pkg.timeline && Array.isArray(pkg.timeline)) {
        pkg.timeline.forEach((event, index) => {
            const timelineItem = document.createElement('div');
            timelineItem.className = `timeline-item ${index === 0 ? 'current' : ''}`;
            
            timelineItem.innerHTML = `
                <div class="timeline-date">${formatDate(event.date)}</div>
                <div class="timeline-description">${event.description}</div>
                <div class="timeline-location">${event.location}</div>
            `;
            
            timeline.appendChild(timelineItem);
        });
    }

    document.getElementById('senderInfo').textContent = pkg.sender;
    document.getElementById('recipientInfo').textContent = pkg.recipient;
    document.getElementById('destinationInfo').textContent = pkg.destination;
}

// Get status icon
function getStatusIcon(status) {
    const icons = {
        'in_transit': 'fas fa-shipping-fast',
        'out_for_delivery': 'fas fa-truck',
        'delivered': 'fas fa-check-circle',
        'picked_up': 'fas fa-box-open',
        'arrived': 'fas fa-warehouse',
        'created': 'fas fa-file-alt'
    };
    return icons[status] || 'fas fa-shipping-fast';
}

// Get status subtitle
function getStatusSubtitle(status) {
    const subtitles = {
        'in_transit': 'Your package is on its way',
        'out_for_delivery': 'Out for delivery today',
        'delivered': 'Delivered',
        'picked_up': 'Picked up',
        'arrived': 'Arrived at facility',
        'created': 'Shipping label created'
    };
    return subtitles[status] || 'Tracking available';
}

// Show error message
function showError(message) {
    const errorSection = document.getElementById('errorSection');
    if (errorSection) {
        const errorMsg = document.getElementById('errorMessage');
        if (errorMsg) errorMsg.textContent = message;
        errorSection.style.display = 'block';
    }
}

// Hide error
function hideError() {
    const errorSection = document.getElementById('errorSection');
    if (errorSection) errorSection.style.display = 'none';
}

// Use example tracking number
function useExample(trackingNumber) {
    document.getElementById('trackingInput').value = trackingNumber;
    trackPackage();
}

// Format date
function formatDate(date) {
    if (typeof date === 'string') date = new Date(date);
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// Modal functions
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.style.display = 'block';
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.style.display = 'none';
}

// Service modal
function showServiceModal(type) {
    const modal = document.getElementById('serviceModal');
    const title = document.querySelector('#serviceModal .modal-title');
    if (title) title.textContent = `${type} Service`;
    if (modal) modal.style.display = 'block';
}

// Info modal
function showInfoModal(info) {
    const modal = document.getElementById('infoModal');
    if (modal) modal.style.display = 'block';
}

// Auth related
function toggleAuthMode() {
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');
    if (loginForm && signupForm) {
        const isLogin = loginForm.style.display !== 'none';
        loginForm.style.display = isLogin ? 'none' : 'block';
        signupForm.style.display = isLogin ? 'block' : 'none';
    }
}

function handleAuth(e) {
    if (e) e.preventDefault();
    console.log('Auth submitted');
}

function handleForgotPassword() {
    alert('Password reset link sent to your email');
}

function handleGoogleLogin() {
    console.log('Google login clicked');
}

function handleLogout() {
    console.log('Logging out');
}

// Admin/Dashboard functions (stubs for now)
function switchAdminView(view) {
    console.log('Switch view to:', view);
    const navItems = document.querySelectorAll('.sidebar-item');
    navItems.forEach(item => item.classList.remove('active'));
    const navId = 'nav-' + view;
    const activeNav = document.getElementById(navId);
    if (activeNav) activeNav.classList.add('active');
}

function renderDashboard() {
    console.log('Rendering dashboard');
}

function downloadDashboardReport() {
    alert('Report download started');
}

function toggleMaintenanceMode() {
    console.log('Toggle maintenance mode');
}

function renderAdminTable() {
    console.log('Rendering admin table');
}

function sortShipments(col) {
    console.log('Sort by:', col);
}

function toggleSelectAll(cb) {
    console.log('Toggle all:', cb.checked);
}

function toggleShipmentSelection(id) {
    console.log('Toggle shipment:', id);
}

function sendSingleNotification(id) {
    console.log('Send notification for:', id);
}

function bulkDeleteShipments() {
    console.log('Bulk delete');
}

function downloadCsvTemplate() {
    alert('CSV template download started');
}

function duplicateShipment(id) {
    console.log('Duplicate shipment:', id);
}

function printLabel(id) {
    console.log('Print label for:', id);
    window.print();
}

function deleteShipment(id) {
    if (confirm('Delete this shipment?')) {
        console.log('Deleted:', id);
    }
}

function openEditModal(id) {
    openModal('adminEditModal');
}

function closeEditModal() {
    closeModal('adminEditModal');
}

function saveEditedShipment() {
    console.log('Save edited shipment');
}

function changeShipmentPage(step) {
    console.log('Change page by:', step);
}

function printManifest() {
    console.log('Print manifest');
    window.print();
}

function bulkChangeStatus() {
    console.log('Bulk change status');
}

function searchShipments() {
    console.log('Search shipments');
}

function filterShipmentsByService() {
    console.log('Filter by service');
}

function renderUsersTable() {
    console.log('Render users');
}

function toggleUserSelection(id) {
    console.log('Toggle user:', id);
}

function deleteUser(id) {
    if (confirm('Delete this user?')) {
        console.log('Deleted user:', id);
    }
}

function changeUserPage(step) {
    console.log('Change user page by:', step);
}

function renderLocationsTable() {
    console.log('Render locations');
}

function deleteLocation(id) {
    if (confirm('Delete this location?')) {
        console.log('Deleted location:', id);
    }
}

function openAddLocationModal() {
    openModal('adminLocationModal');
}

function closeAddLocationModal() {
    closeModal('adminLocationModal');
}

function saveNewLocation() {
    console.log('Save new location');
}

function changeLocationPage(step) {
    console.log('Change location page by:', step);
}

function renderSettings() {
    console.log('Render settings');
}

function saveSetting(key) {
    console.log('Save setting:', key);
}

function resetToDefaults() {
    if (confirm('Reset all to defaults?')) {
        console.log('Reset defaults');
    }
}

function showToast(msg, type = 'info') {
    console.log(type + ':', msg);
}

function renderAuditLogsTable() {
    console.log('Render audit logs');
}

function filterAndSortAuditLogs() {
    console.log('Filter and sort audit logs');
}

function handleAuditSearch() {
    console.log('Audit search');
}

function toggleAuditSort() {
    console.log('Toggle audit sort');
}

function clearAuditLogs() {
    if (confirm('Clear all audit logs?')) {
        console.log('Cleared audit logs');
    }
}

function renderAuditLogsPage() {
    console.log('Render audit page');
}

function changeAuditPage(step) {
    console.log('Change audit page by:', step);
}

function exportAuditLogsToCSV() {
    alert('Exporting audit logs to CSV');
}

function addTimelineEvent() {
    console.log('Add timeline event');
}

function applyBulkStatusUpdate() {
    console.log('Apply bulk status update');
}

function cancelBulkImport() {
    closeModal('bulkStatusModal');
}

function copyToClipboard() {
    const text = document.getElementById('displayTracking').textContent;
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard', 'success');
    });
}

function performSearch() {
    console.log('Perform search');
}

function simulateAction() {
    closeModal('serviceModal');
    trackPackage();
}

function downloadChart(chartId) {
    console.log('Download chart:', chartId);
}

function downloadManifestPDF() {
    alert('Manifest PDF download started');
}

function bulkImportInput(input) {
    console.log('Bulk import file:', input.files[0]);
}

// DOMContentLoaded setup
document.addEventListener('DOMContentLoaded', function() {
    console.log('Page loaded, checking for Firebase auth...');
    
    // Allow Enter key for tracking
    const trackingInput = document.getElementById('trackingInput');
    if (trackingInput) {
        trackingInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                trackPackage();
            }
        });
    }

    // Service tabs
    const serviceTabs = document.querySelectorAll('.service-tab');
    serviceTabs.forEach(tab => {
        tab.addEventListener('click', function() {
            serviceTabs.forEach(t => t.classList.remove('active'));
            this.classList.add('active');
        });
    });
});
