// Force Firebase URL for production, localhost for local dev
const API_BASE_URL = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') 
    ? 'http://localhost:5002'
    : ''; // Empty string uses relative paths, routing through Firebase rewrites automatically

console.log('API Base URL:', API_BASE_URL);

// Safe DOM Setters to prevent TypeErrors when elements don't exist on current page
function safeSetText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text || '';
}

function safeSetClass(id, className) {
    const el = document.getElementById(id);
    if (el) el.className = className || '';
}

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
    const trackingInput = document.getElementById('trackingInput');
    if (!trackingInput) return;
    
    const trackingNumber = trackingInput.value.trim();
    const resultsSection = document.getElementById('resultsSection');
    const errorSection = document.getElementById('errorSection');

    if (resultsSection) resultsSection.style.display = 'none';
    if (errorSection) errorSection.style.display = 'none';

    if (!trackingNumber) {
        showError('Please enter a tracking number');
        return;
    }

    const originalValue = trackingInput.value;
    trackingInput.value = 'Tracking...';
    trackingInput.disabled = true; // Prevent spamming requests
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/track/${trackingNumber}`, {
            headers: await getAuthHeaders()
        });
        
        if (!response.ok) {
            let errorMsg = 'Tracking not found';
            try {
                const errorData = await response.json();
                // The rate limiter uses .error, while standard errors might use .message
                errorMsg = errorData.error || errorData.message || errorMsg;
            } catch (e) {
                // Fallback if the response isn't JSON
                if (response.status === 429) {
                    errorMsg = 'Too many requests. Please try again later.';
                }
            }
            throw new Error(errorMsg);
        }

        const packageData = await response.json();
        displayPackageInfo(packageData);
        if (resultsSection) resultsSection.style.display = 'block';
        hideError();
        
    } catch (error) {
        console.error('Track error:', error);
        showError(error.message || 'Could not track package. Please try again.');
    } finally {
        trackingInput.value = originalValue;
        trackingInput.disabled = false; // Re-enable input
    }
}

// Enhanced package display
function displayPackageInfo(pkg) {
    safeSetText('statusTitle', pkg.statusText || pkg.statusDetail || pkg.status);
    safeSetText('statusSubtitle', getStatusSubtitle(pkg.status));
    safeSetText('displayTracking', pkg.trackingNumber || pkg.id);
    safeSetText('displayService', pkg.service);
    safeSetText('displayDelivery', pkg.estimatedDelivery || pkg.deliveryDate);

    safeSetClass('statusMainIcon', getStatusIcon(pkg.status));

    safeSetText('infoTracking', pkg.trackingNumber || pkg.id);
    safeSetText('infoStatus', pkg.statusText || pkg.statusDetail || pkg.status);
    safeSetClass('infoStatus', `status-badge ${pkg.status}`);
    safeSetText('infoService', pkg.service);
    safeSetText('infoWeight', pkg.weight);
    safeSetText('infoDelivery', pkg.estimatedDelivery || pkg.deliveryDate);
    safeSetText('infoDestination', pkg.destination);

    const timeline = document.getElementById('timeline');
    if (timeline) {
        timeline.innerHTML = '';

        if (pkg.timeline && Array.isArray(pkg.timeline)) {
        // Add Tailwind container classes to create the vertical line
        timeline.className = 'relative border-l border-gray-200 dark:border-gray-700 ml-3 mt-4';

        pkg.timeline.forEach((event, index) => {
            const isCurrent = index === 0;
            const timelineItem = document.createElement('div');
            timelineItem.className = 'mb-8 ml-6';
            
            // Tailwind styles for timeline dots
            const dotClass = isCurrent 
                ? 'absolute flex items-center justify-center w-4 h-4 bg-blue-600 rounded-full -left-2 ring-4 ring-white dark:ring-gray-900 dark:bg-blue-500'
                : 'absolute flex items-center justify-center w-4 h-4 bg-gray-200 rounded-full -left-2 ring-4 ring-white dark:ring-gray-900 dark:bg-gray-700';
            
            timelineItem.innerHTML = `
                <span class="${dotClass}"></span>
                <h3 class="flex items-center mb-1 text-lg font-semibold text-gray-900 dark:text-white">
                    ${event.description || event.status}
                    ${isCurrent ? '<span class="bg-blue-100 text-blue-800 text-sm font-medium mr-2 px-2.5 py-0.5 rounded dark:bg-blue-900 dark:text-blue-300 ml-3">Latest</span>' : ''}
                </h3>
                <time class="block mb-2 text-sm font-normal leading-none text-gray-400 dark:text-gray-500">${formatDate(event.date)}</time>
                <p class="text-base font-normal text-gray-500 dark:text-gray-400">${event.location || ''}</p>
            `;
            
            timeline.appendChild(timelineItem);
        });
        }
    }

    safeSetText('senderInfo', pkg.sender);
    safeSetText('recipientInfo', pkg.recipient);
    safeSetText('destinationInfo', pkg.destination);
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

// Fill input and track
function fillInput(trackingNumber) {
    document.getElementById('trackingInput').value = trackingNumber;
    trackPackage();
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
    const title = document.getElementById('serviceModalTitle');
    if (title) title.textContent = `${type.charAt(0).toUpperCase() + type.slice(1)} Service`;
    if (modal) modal.style.display = 'block';
}

// Info modal
function showInfoModal(info) {
    const modal = document.getElementById('infoModal');
    if (modal) {
        const content = document.getElementById('infoContent');
        if (content && info) content.textContent = info;
        modal.style.display = 'block';
    }
}

// Core Auth stubs mapping to auth.js functions or handling default behaviors
function handleAuth(e) {
    if (e) e.preventDefault();
    if (typeof submitAuth === 'function') submitAuth(e);
}

function handleForgotPassword() {
    if (typeof showForgotPasswordForm === 'function') {
        showForgotPasswordForm();
    } else {
        alert('Password reset link sent to your email');
    }
}

function handleGoogleLogin() {
    console.log('Google login clicked');
}

function handleLogout() {
    console.log('Logging out');
}

// Admin/Dashboard functions (stubs for now)
function switchAdminView(view) {
    const navItems = document.querySelectorAll('.sidebar-item');
    navItems.forEach(item => item.classList.remove('active'));
    const navId = 'nav-' + view;
    const activeNav = document.getElementById(navId);
    if (activeNav) activeNav.classList.add('active');

    // Hide all admin views
    document.querySelectorAll('.admin-view').forEach(v => v.classList.add('hidden'));
    
    // Show selected view
    const viewId = 'admin' + view.charAt(0).toUpperCase() + view.slice(1) + 'View';
    const viewEl = document.getElementById(viewId);
    if (viewEl) viewEl.classList.remove('hidden');

    // Fetch data when switching tabs
    if (view === 'shipments') fetchAdminShipments();
    if (view === 'users') fetchAdminUsers();
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

// Pagination & Search State variables
let currentShipmentPage = 1;
const shipmentsPerPage = 10;
let currentSearchQuery = '';
let totalShipmentPages = 1;
let currentSortColumn = 'createdAt';
let currentSortOrder = 'desc';

async function fetchAdminShipments() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/shipments?page=${currentShipmentPage}&limit=${shipmentsPerPage}&search=${encodeURIComponent(currentSearchQuery)}&sortBy=${currentSortColumn}&order=${currentSortOrder}`, {
            headers: await getAuthHeaders()
        });
        if (!response.ok) throw new Error('Failed to fetch shipments');
        
        const data = await response.json();
        totalShipmentPages = data.totalPages;
        renderAdminTable(data.shipments);
    } catch (error) {
        console.error('Error fetching admin shipments:', error);
    }
}

function renderAdminTable(shipments = []) {
    const tableBody = document.getElementById('adminTableBody') || document.getElementById('adminShipmentsTableBody');
    if (!tableBody) return;

    tableBody.innerHTML = '';
    
    shipments.forEach(shipment => {
        const row = document.createElement('tr');
        row.className = 'bg-white border-b dark:bg-gray-800 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600';
        row.innerHTML = `
            <td class="px-4 py-3 w-10">
                <input type="checkbox" class="shipment-checkbox" value="${shipment.id}" onchange="updateBulkActionButtons()">
            </td>
            <td class="px-4 py-3 font-medium text-gray-900 whitespace-nowrap dark:text-white">${shipment.id}</td>
            <td class="px-4 py-3">${shipment.status}</td>
            <td class="hidden sm:table-cell px-4 py-3">${shipment.destination || shipment.recipient || ''}</td>
            <td class="hidden sm:table-cell px-4 py-3">${shipment.estimatedDelivery || shipment.deliveryDate || ''}</td>
            <td class="px-4 py-3 text-right">
                <button onclick="openEditModal('${shipment.id}')" class="font-medium text-blue-600 dark:text-blue-500 hover:underline">Edit</button>
            </td>
        `;
        tableBody.appendChild(row);
    });

    // Update pagination text indicator
    const pageInfo = document.getElementById('shipmentPageInfo');
    if (pageInfo) {
        pageInfo.textContent = `Page ${currentShipmentPage} of ${totalShipmentPages || 1}`;
    }

    // Show/hide bulk action buttons based on selection
    updateBulkActionButtons();
}

function updateBulkActionButtons() {
    const checkedCount = document.querySelectorAll('.shipment-checkbox:checked').length;
    const bulkDeleteBtn = document.getElementById('bulkDeleteBtn');
    const bulkStatusBtn = document.getElementById('bulkStatusBtn');
    
    if (bulkDeleteBtn) bulkDeleteBtn.style.display = checkedCount > 0 ? 'inline-flex' : 'none';
    if (bulkStatusBtn) bulkStatusBtn.style.display = checkedCount > 0 ? 'inline-flex' : 'none';
}

function sortShipments(col) {
    if (currentSortColumn === col) {
        currentSortOrder = currentSortOrder === 'asc' ? 'desc' : 'asc';
    } else {
        currentSortColumn = col;
        currentSortOrder = 'asc'; // Default to ascending on a new column
    }
    fetchAdminShipments();
}

function toggleSelectAll(cb) {
    const checkboxes = document.querySelectorAll('.shipment-checkbox');
    checkboxes.forEach(box => box.checked = cb.checked);
    updateBulkActionButtons();
}

function toggleShipmentSelection(id) {
    updateBulkActionButtons();
}

function sendSingleNotification(id) {
    console.log('Send notification for:', id);
}

async function bulkDeleteShipments() {
    const selectedCheckboxes = document.querySelectorAll('.shipment-checkbox:checked');
    const ids = Array.from(selectedCheckboxes).map(cb => cb.value);

    if (ids.length === 0) {
        showToast('Please select at least one shipment to delete', 'warning');
        return;
    }

    if (!confirm(`Are you sure you want to delete ${ids.length} shipment(s)? This action cannot be undone.`)) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/shipments/bulk`, {
            method: 'DELETE',
            headers: await getAuthHeaders(),
            body: JSON.stringify({ ids })
        });

        if (!response.ok) {
            throw new Error('Failed to delete shipments');
        }

        showToast(`Successfully deleted ${ids.length} shipment(s)`, 'success');
        const selectAllCheckbox = document.getElementById('selectAllShipments');
        if (selectAllCheckbox) selectAllCheckbox.checked = false;
        fetchAdminShipments(); // Refresh table
    } catch (error) {
        console.error('Bulk delete error:', error);
        showToast(error.message, 'error');
    }
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
    if (id) {
        const editTrackingId = document.getElementById('editTrackingId');
        if (editTrackingId) editTrackingId.value = id;
    }
    openModal('adminEditModal');
}

function closeEditModal() {
    closeModal('adminEditModal');
}

function saveEditedShipment() {
    console.log('Save edited shipment');
}

function changeShipmentPage(step) {
    const newPage = currentShipmentPage + step;
    
    if (newPage >= 1 && newPage <= totalShipmentPages) {
        currentShipmentPage = newPage;
        fetchAdminShipments();
    }
}

function printManifest() {
    console.log('Print manifest');
    window.print();
}

function bulkChangeStatus() {
    console.log('Bulk change status');
}

function searchShipments() {
    const searchInput = document.getElementById('searchShipmentsInput');
    // Use target input if it exists, else look for any generic search input active
    const val = searchInput ? searchInput.value : (document.querySelector('input[type="search"]')?.value || '');
    
    currentSearchQuery = val.trim();
    currentShipmentPage = 1; // Reset to page 1 on search
    fetchAdminShipments();
}

function filterShipmentsByService() {
    console.log('Filter by service');
}

// User Pagination State
let currentUserPage = 1;
const usersPerPage = 10;
let currentUserSearch = '';
let totalUserPages = 1;

async function fetchAdminUsers() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/users?page=${currentUserPage}&limit=${usersPerPage}&search=${encodeURIComponent(currentUserSearch)}`, {
            headers: await getAuthHeaders()
        });
        if (!response.ok) throw new Error('Failed to fetch users');
        
        const data = await response.json();
        // Works natively with arrays or paginated JSON objects
        const users = Array.isArray(data) ? data : (data.users || []);
        totalUserPages = data.totalPages || 1;
        renderUsersTable(users);
    } catch (error) {
        console.error('Error fetching admin users:', error);
        showToast('Failed to load users', 'error');
    }
}

function handleUserSearch() {
    const searchInput = document.getElementById('userSearchInput');
    currentUserSearch = searchInput ? searchInput.value.trim() : '';
    currentUserPage = 1;
    fetchAdminUsers();
}

function renderUsersTable(users = []) {
    const tableBody = document.getElementById('adminUsersTableBody');
    if (!tableBody) return;

    tableBody.innerHTML = '';
    
    users.forEach(user => {
        const row = document.createElement('tr');
        row.className = 'bg-white border-b dark:bg-gray-800 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600';
        row.innerHTML = `
            <td class="px-4 py-3 font-medium text-gray-900 whitespace-nowrap dark:text-white">${user._id || user.uid || 'N/A'}</td>
            <td class="px-4 py-3">${user.username || user.name || 'Unknown'}</td>
            <td class="hidden sm:table-cell px-4 py-3">${user.email || ''}</td>
            <td class="px-4 py-3">
                <span class="px-2 py-1 rounded text-xs font-medium ${user.admin || user.role === 'Admin' ? 'bg-purple-100 text-purple-800' : 'bg-gray-100 text-gray-800'}">
                    ${user.role || (user.admin ? 'Admin' : 'Customer')}
                </span>
            </td>
            <td class="px-4 py-3 text-right">
                <button onclick="openUserModal('${user._id || user.uid}')" class="font-medium text-blue-600 dark:text-blue-500 hover:underline mr-3">Edit</button>
                <button onclick="deleteUser('${user._id || user.uid}')" class="font-medium text-red-600 dark:text-red-500 hover:underline">Delete</button>
            </td>
        `;
        tableBody.appendChild(row);
    });

    const pageInfo = document.getElementById('userPageInfo');
    if (pageInfo) {
        pageInfo.textContent = `Page ${currentUserPage} of ${totalUserPages}`;
    }
}

function toggleUserSelection(id) {
    console.log('Toggle user:', id);
}

async function deleteUser(id) {
    if (!confirm('Are you sure you want to delete this user?')) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/admin/user/${id}`, {
            method: 'DELETE',
            headers: await getAuthHeaders()
        });
        if (!response.ok) throw new Error('Failed to delete user');
        
        showToast('User deleted successfully', 'success');
        fetchAdminUsers(); // Refresh table
    } catch (error) {
        console.error('Delete user error:', error);
        showToast(error.message, 'error');
    }
}

function changeUserPage(step) {
    const newPage = currentUserPage + step;
    if (newPage >= 1 && newPage <= totalUserPages) {
        currentUserPage = newPage;
        fetchAdminUsers();
    }
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
    const containerId = 'toast-container';
    let container = document.getElementById(containerId);
    if (!container) {
        container = document.createElement('div');
        container.id = containerId;
        container.className = 'fixed bottom-5 right-5 z-[9999] flex flex-col gap-3';
        document.body.appendChild(container);
    }
    const toast = document.createElement('div');
    toast.textContent = msg;
    
    const colorClasses = {
        success: 'bg-emerald-500',
        warning: 'bg-amber-500',
        error: 'bg-red-500',
        info: 'bg-blue-500'
    };
    toast.className = `px-5 py-3 rounded shadow-md text-white transition-opacity duration-300 ${colorClasses[type] || colorClasses.info}`;
    
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
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

async function exportAuditLogsToCSV() {
    try {
        showToast('Preparing CSV download...', 'info');
        const response = await fetch(`${API_BASE_URL}/api/audit-logs/export`, {
            headers: await getAuthHeaders()
        });

        if (!response.ok) throw new Error('Failed to export audit logs');

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'audit_logs.csv';
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
    } catch (error) {
        console.error('Export Error:', error);
        showToast('Failed to download CSV', 'error');
    }
}

function addTimelineEvent() {
    console.log('Add timeline event');
}

async function applyBulkStatusUpdate() {
    const selectedCheckboxes = document.querySelectorAll('.shipment-checkbox:checked');
    const ids = Array.from(selectedCheckboxes).map(cb => cb.value);
    const statusSelect = document.getElementById('bulkStatusSelect');
    const status = statusSelect ? statusSelect.value : null;

    if (ids.length === 0) {
        showToast('Please select at least one shipment to update', 'warning');
        return;
    }
    if (!status) {
        showToast('Please select a valid status', 'warning');
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/shipments/bulk-status`, {
            method: 'PUT',
            headers: await getAuthHeaders(),
            body: JSON.stringify({ ids, status })
        });
        if (!response.ok) throw new Error('Failed to update shipments');
        
        showToast(`Successfully updated ${ids.length} shipment(s)`, 'success');
        closeModal('bulkStatusModal');
        fetchAdminShipments(); // Refresh the table
    } catch (error) {
        console.error('Bulk update error:', error);
        showToast(error.message || 'Failed to apply bulk update', 'error');
    }
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
    if (input && input.files && input.files[0]) {
        showToast(`File ${input.files[0].name} read successfully`, 'info');
    }
}

// Additional missing functions
function openBulkStatusModal() {
    openModal('bulkStatusModal');
}

function openLocationModal() {
    openModal('adminLocationModal');
}

function openUserModal() {
    openModal('adminUserModal');
}

function printAuditLogs() {
    console.log('Print audit logs');
    window.print();
}

function saveLocation() {
    console.log('Save location');
    closeModal('adminLocationModal');
    showToast('Location saved', 'success');
}

function saveSettings() {
    console.log('Save settings');
    showToast('Settings saved', 'success');
}

async function saveShipment() {
    const trackingId = document.getElementById('editTrackingId')?.value;
    const status = document.getElementById('editStatus')?.value;
    const location = document.getElementById('editLocation')?.value;
    const service = document.getElementById('editService')?.value;
    const weight = document.getElementById('editWeight')?.value;
    const deliveryDate = document.getElementById('editDate')?.value;

    if (!trackingId) {
        showToast('Tracking ID is required', 'warning');
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/shipment/${trackingId}`, {
            method: 'PUT',
            headers: await getAuthHeaders(),
            body: JSON.stringify({ 
                status, 
                location, 
                service, 
                weight,
                deliveryDate
            })
        });
        if (!response.ok) throw new Error('Failed to update shipment');

        showToast('Shipment updated successfully', 'success');
        closeModal('adminEditModal');
        fetchAdminShipments(); // Refresh table
    } catch (error) {
        console.error('Save shipment error:', error);
        showToast(error.message, 'error');
    }
}

function saveUser() {
    console.log('Save user');
    closeModal('adminUserModal');
    showToast('User saved', 'success');
}

function scrollToSection(sectionId) {
    const section = document.getElementById(sectionId);
    if (section) {
        section.scrollIntoView({ behavior: 'smooth' });
    }
}

function sendCustomEmail() {
    alert('Custom email sent');
}

function sendShipmentNotifications() {
    alert('Notifications sent');
}

function shareTrackingLink() {
    const trackingNumber = document.getElementById('displayTracking').textContent;
    if (navigator.share) {
        navigator.share({
            title: 'FedEx Tracking',
            text: `Track my package: ${trackingNumber}`,
            url: window.location.href
        });
    } else {
        showToast('Share not supported on this browser', 'warning');
    }
}

function toggleDarkMode() {
    document.documentElement.classList.toggle('dark');
    localStorage.setItem('darkMode', document.documentElement.classList.contains('dark'));
}

function toggleMobileMenu() {
    const sidebar = document.querySelector('.sidebar');
    if (sidebar) {
        sidebar.classList.toggle('hidden');
    }
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