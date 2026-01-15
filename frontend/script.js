
    // Force Render URL for production, localhost for local dev
const API_BASE_URL = (window.location.hostname === 'localhost' || window.locationhostname    === '127.0.0.1') 
        ? 'http://localhost:5002' 
        : 'https://fedex-clone-educational.onrender.com';
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
