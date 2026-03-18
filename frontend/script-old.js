
    // Force Firebase URL for production, localhost for local dev
const API_BASE_URL = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') 
        ? 'http://localhost:5002' 
        : 'https://us-central1-fedex-37e89.cloudfunctions.net';
    console.log('API Configured to:', API_BASE_URL);

    // Helper to get auth headers with Firebase token
    async function getAuthHeaders() {
        if (!window.firebaseAuth) return { 'Content-Type': 'application/json' };
        const { auth } = window.firebaseAuth;
        const headers = { 'Content-Type': 'application/json' };
        if (auth && auth.currentUser) {
            try {
                const token = await auth.currentUser.getIdToken(true);
                headers['Authorization'] = `Bearer ${token}`;
            } catch (e) {
                console.error("Could not get auth token:", e);
            }
        }
        return headers;
    }

    let isLoggedIn = false;



 

// Enhanced tracking function
async function trackPackage() {
    const trackingNumber = document.getElementById('trackingInput').value.trim();
    const resultsSection = document.getElementById('resultsSection');
    const errorSection = document.getElementById('errorSection');

    // Hide both sections first
    resultsSection.style.display = 'none';
    errorSection.style.display = 'none';

    if (!trackingNumber) {
        showError('Please enter a tracking number');
        return;
    }

    // Show loading state
    const originalValue = document.getElementById('trackingInput').value;
    document.getElementById('trackingInput').value = 'Tracking...';
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/track/${trackingNumber}`);
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message);
        }

        const packageData = await response.json();
        displayPackageInfo(packageData);
        resultsSection.style.display = 'block';
        
    } catch (error) {
        showError(error.message);
    } finally {
        // Restore input value
        document.getElementById('trackingInput').value = originalValue;
    }
}

// Enhanced package display
function displayPackageInfo(pkg) {
    // Update status header
    document.getElementById('statusTitle').textContent = pkg.statusText || pkg.statusDetail || pkg.status;
    document.getElementById('statusSubtitle').textContent = getStatusSubtitle(pkg.status);
    document.getElementById('displayTracking').textContent = pkg.trackingNumber || pkg.id;
    document.getElementById('displayService').textContent = pkg.service;
    document.getElementById('displayDelivery').textContent = pkg.estimatedDelivery || pkg.deliveryDate;

    // Update status icon
    const statusIcon = document.getElementById('statusMainIcon');
    statusIcon.className = getStatusIcon(pkg.status);

    // Update basic info
    document.getElementById('infoTracking').textContent = pkg.trackingNumber || pkg.id;
    document.getElementById('infoStatus').textContent = pkg.statusText || pkg.statusDetail || pkg.status;
    document.getElementById('infoStatus').className = `status-badge ${pkg.status}`;
    document.getElementById('infoService').textContent = pkg.service;
    document.getElementById('infoWeight').textContent = pkg.weight;
    document.getElementById('infoDelivery').textContent = pkg.estimatedDelivery || pkg.deliveryDate;
    document.getElementById('infoDestination').textContent = pkg.destination;

    // Create timeline
    const timeline = document.getElementById('timeline');
    timeline.innerHTML = '';

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

    // Update sender and recipient info
    document.getElementById('senderInfo').textContent = pkg.sender;
    document.getElementById('recipientInfo').textContent = pkg.recipient;
    document.getElementById('destinationInfo').textContent = pkg.destination;
}

// Enhanced status icons
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

// Status subtitles
function getStatusSubtitle(status) {
    const subtitles = {
        'in_transit': 'Your package is on its way to the destination',
        'out_for_delivery': 'Your package is out for delivery today',
        'delivered': 'Your package has been delivered',
        'picked_up': 'Your package has been picked up',
        'arrived': 'Your package has arrived at a FedEx facility',
        'created': 'Shipping label has been created'
    };
    return subtitles[status] || 'Tracking information available';
}

// Show error message
function showError(message) {
    const errorSection = document.getElementById('errorSection');
    document.getElementById('errorMessage').textContent = message;
    errorSection.style.display = 'block';
}

// Hide error
function hideError() {
    document.getElementById('errorSection').style.display = 'none';
}

// Use example tracking number
function useExample(trackingNumber) {
    document.getElementById('trackingInput').value = trackingNumber;
    trackPackage();
}

// Enhanced date formatting
function formatDate(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diffTime = Math.abs(now - date);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    if (diffDays === 1) {
        return 'Yesterday ' + date.toLocaleTimeString('en-US', { 
            hour: '2-digit', 
            minute: '2-digit' 
        });
    } else if (diffDays === 0) {
        return 'Today ' + date.toLocaleTimeString('en-US', { 
            hour: '2-digit', 
            minute: '2-digit' 
        });
    } else {
        return date.toLocaleString('en-US', {
            weekday: 'short',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }
}

// Allow Enter key to trigger tracking
document.getElementById('trackingInput').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        trackPackage();
    }
});

// Add some interactive features
document.addEventListener('DOMContentLoaded', function() {
    // Add hover effects to service tabs
    const serviceTabs = document.querySelectorAll('.service-tab');
    serviceTabs.forEach(tab => {
        tab.addEventListener('click', function() {
            serviceTabs.forEach(t => t.classList.remove('active'));
            this.classList.add('active');
        });
    });
});

// Expose all public functions to global window scope for HTML onclick handlers
window.trackPackage = trackPackage;
window.displayPackageInfo = displayPackageInfo;
window.getStatusIcon = getStatusIcon;
window.getStatusSubtitle = getStatusSubtitle;
window.showError = showError;
window.hideError = hideError;
window.useExample = useExample;
window.formatDate = formatDate;
window.getAuthHeaders = getAuthHeaders;

// Add missing functions as stubs that prevent "not defined" errors
window.fillInput = function(val) { document.getElementById('trackingInput').value = val; trackPackage(); };
window.openModal = function(modalId) { const el = document.getElementById(modalId); if(el) el.style.display = 'block'; };
window.closeModal = function(modalId) { const el = document.getElementById(modalId); if(el) el.style.display = 'none'; };
window.showServiceModal = function(type) { alert('Service Modal: ' + type); };
window.showInfoModal = function(type) { alert('Info Modal: ' + type); };
window.performSearch = function() { alert('Search functionality'); };
window.toggleAuthMode = function() { alert('Toggle auth mode'); };
window.handleAuth = function(e) { e.preventDefault(); alert('Handle auth'); };
window.handleForgotPassword = function() { alert('Forgot password'); };
window.handleGoogleLogin = function() { alert('Google login'); };
window.handleLogout = function() { alert('Logout'); };
window.switchAdminView = function(view) { alert('Switch to ' + view); };
window.renderDashboard = function() { console.log('Render dashboard'); };
window.downloadDashboardReport = function() { alert('Download report'); };
window.toggleMaintenanceMode = function() { alert('Toggle maintenance'); };
window.renderAdminTable = function() { console.log('Render admin table'); };
window.sortShipments = function(col) { alert('Sort by ' + col); };
window.toggleSelectAll = function(cb) { alert('Toggle all'); };
window.toggleShipmentSelection = function(id) { alert('Toggle shipment ' + id); };
window.sendSingleNotification = function(id) { alert('Notify shipment ' + id); };
window.bulkDeleteShipments = function() { alert('Bulk delete'); };
window.downloadCsvTemplate = function() { alert('Download CSV'); };
window.duplicateShipment = function(id) { alert('Duplicate shipment ' + id); };
window.printLabel = function(id) { alert('Print label for ' + id); };
window.deleteShipment = function(id) { alert('Delete shipment ' + id); };
window.openEditModal = function(id) { alert('Edit shipment ' + id); };
window.closeEditModal = function() { alert('Close edit modal'); };
window.saveEditedShipment = function() { alert('Save edited shipment'); };
window.changeShipmentPage = function(step) { alert('Change page by ' + step); };
window.printManifest = function() { alert('Print manifest'); };
window.bulkChangeStatus = function() { alert('Bulk change status'); };
window.searchShipments = function() { alert('Search shipments'); };
window.filterShipmentsByService = function() { alert('Filter by service'); };
window.renderUsersTable = function() { console.log('Render users'); };
window.toggleUserSelection = function(id) { alert('Toggle user ' + id); };
window.deleteUser = function(id) { alert('Delete user ' + id); };
window.changeUserPage = function(step) { alert('Change user page by ' + step); };
window.renderLocationsTable = function() { console.log('Render locations'); };
window.deleteLocation = function(id) { alert('Delete location ' + id); };
window.openAddLocationModal = function() { alert('Add location'); };
window.closeAddLocationModal = function() { alert('Close add location'); };
window.saveNewLocation = function() { alert('Save new location'); };
window.changeLocationPage = function(step) { alert('Change location page'); };
window.renderSettings = function() { console.log('Render settings'); };
window.saveSetting = function(key) { alert('Save setting: ' + key); };
window.resetToDefaults = function() { alert('Reset to defaults'); };
window.showToast = function(msg, type) { console.log((type || 'info') + ': ' + msg); };
window.renderAuditLogsTable = function() { console.log('Render audit logs'); };
window.filterAndSortAuditLogs = function() { alert('Filter and sort'); };
window.handleAuditSearch = function() { alert('Audit search'); };
window.toggleAuditSort = function() { alert('Toggle sort'); };
window.clearAuditLogs = function() { alert('Clear audit logs'); };
window.renderAuditLogsPage = function() { console.log('Render audit page'); };
window.changeAuditPage = function(step) { alert('Change audit page by ' + step); };
window.exportAuditLogsToCSV = function() { alert('Export CSV'); };
window.addTimelineEvent = function() { alert('Add timeline event'); };
window.applyBulkStatusUpdate = function() { alert('Apply bulk status'); };
window.cancelBulkImport = function() { alert('Cancel import'); };
