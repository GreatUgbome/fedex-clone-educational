require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const os = require('os');
const functions = require('firebase-functions');

const app = express();

app.use(cors({
  origin: '*', // Allow requests from any origin
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Serve static files from the frontend directory
app.use(express.static(path.join(__dirname, '../frontend')));

// Handle favicon requests to prevent 404 errors
app.get('/favicon.ico', (req, res) => res.status(204).end());

// Enhanced test data with more realistic FedEx information
let packages = [
  {
    trackingNumber: "123456789012",
    status: "in_transit",
    statusText: "In transit",
    service: "FedEx Express",
    weight: "2.5 lbs",
    dimensions: "10x8x4 in.",
    pieces: 1,
    estimatedDelivery: "Mon 12/20/2024 by 10:30 am",
    sender: "AMAZON FULFILLMENT SERVICES, INC.",
    recipient: "JOHN DOE",
    destination: "123 MAIN ST, NEW YORK, NY 10001",
    timeline: [
      {
        date: "2024-12-15 14:30:00",
        location: "MEMPHIS, TN",
        description: "In transit to destination facility",
        status: "in_transit"
      },
      {
        date: "2024-12-15 09:15:00",
        location: "MEMPHIS, TN",
        description: "Arrived at FedEx hub",
        status: "arrived"
      },
      {
        date: "2024-12-14 16:45:00",
        location: "INDIANAPOLIS, IN",
        description: "Picked up",
        status: "picked_up"
      },
      {
        date: "2024-12-14 12:00:00",
        location: "INDIANAPOLIS, IN",
        description: "Shipment information sent to FedEx",
        status: "created"
      }
    ]
  },
  {
    trackingNumber: "987654321098",
    status: "out_for_delivery",
    statusText: "Out for delivery",
    service: "FedEx Ground",
    weight: "5.0 lbs",
    dimensions: "12x10x6 in.",
    pieces: 2,
    estimatedDelivery: "Today by 8:00 pm",
    sender: "WALMART DISTRIBUTION CENTER",
    recipient: "JANE SMITH",
    destination: "456 OAK AVENUE, CHICAGO, IL 60601",
    timeline: [
      {
        date: "2024-12-15 08:00:00",
        location: "CHICAGO, IL",
        description: "Out for delivery",
        status: "out_for_delivery"
      },
      {
        date: "2024-12-15 06:30:00",
        location: "CHICAGO, IL",
        description: "At local FedEx facility",
        status: "arrived"
      },
      {
        date: "2024-12-14 20:30:00",
        location: "CHICAGO, IL",
        description: "Arrived at FedEx facility",
        status: "arrived"
      },
      {
        date: "2024-12-13 14:15:00",
        location: "MEMPHIS, TN",
        description: "Departed FedEx location",
        status: "in_transit"
      }
    ]
  },
  {
    trackingNumber: "555555555555",
    status: "delivered",
    statusText: "Delivered",
    service: "FedEx Express",
    weight: "1.8 lbs",
    dimensions: "8x6x2 in.",
    pieces: 1,
    estimatedDelivery: "Delivered on 12/14/2024",
    sender: "APPLE INC.",
    recipient: "ROBERT JOHNSON",
    destination: "789 PINE STREET, SAN FRANCISCO, CA 94102",
    timeline: [
      {
        date: "2024-12-14 14:25:00",
        location: "SAN FRANCISCO, CA",
        description: "Delivered - Left at front door",
        status: "delivered"
      },
      {
        date: "2024-12-14 12:30:00",
        location: "SAN FRANCISCO, CA",
        description: "On FedEx vehicle for delivery",
        status: "out_for_delivery"
      },
      {
        date: "2024-12-14 08:15:00",
        location: "SAN FRANCISCO, CA",
        description: "At local FedEx facility",
        status: "arrived"
      },
      {
        date: "2024-12-13 22:45:00",
        location: "OAKLAND, CA",
        description: "Departed FedEx location",
        status: "in_transit"
      }
    ]
  }
];

// Mock Database for Users
let users = [
  { id: 'U001', name: 'Admin Administrator', email: 'admin@fedex.com', password: 'password123', role: 'Admin' },
  { id: 'U002', name: 'John Doe', email: 'john@example.com', password: 'password123', role: 'Customer' },
  { id: 'U003', name: 'Sarah Connor', email: 'sarah@example.com', password: 'password123', role: 'Support' }
];

// Mock Database for Locations
let locations = [
  { id: 'L001', name: 'Memphis World Hub', address: 'Memphis, TN', type: 'Sort Facility' },
  { id: 'L002', name: 'Downtown Branch', address: '123 Main St, New York, NY', type: 'Retail Store' },
  { id: 'L003', name: 'LAX Distribution', address: 'Los Angeles, CA', type: 'Distribution Center' }
];

// Mock Database for Settings
const DEFAULT_SETTINGS = {
  maintenance: false,
  signups: true,
  api: true,
  email: true,
  sms: false,
  banner: 'Welcome to the new FedEx tracking system.'
};

let settings = { ...DEFAULT_SETTINGS };

// Mock Database for Quotes
const quotes = [
  "The only way to do great work is to love what you do.",
  "Success is not final, failure is not fatal: it is the courage to continue that counts.",
  "Believe you can and you're halfway there.",
  "The future belongs to those who believe in the beauty of their dreams.",
  "Strive not to be a success, but rather to be of value."
];

// Mock Database for Announcements
let announcements = [
  { id: 'A1', title: 'Welcome to FedEx', message: 'We are happy to have you here.', date: new Date().toISOString().split('T')[0] }
];

// Mock Database for Audit Logs
let auditLogs = [];

function logAction(user, action, details) {
  const log = {
    id: `LOG${Date.now()}`,
    timestamp: new Date().toISOString(),
    user: user || 'System',
    action,
    details
  };
  auditLogs.unshift(log);
  if (auditLogs.length > 50) auditLogs.pop();
}

// Routes

app.get('/api/carbon/:id', (req, res) => {
    const trackingId = req.params.id;
    
    // Mock calculation: Generate a random value between 0.5 and 5.0 kg
    // In a real app, you would calculate this based on weight and distance
    const estimatedCarbon = (Math.random() * (5.0 - 0.5) + 0.5).toFixed(1);
    
    res.json({
        trackingNumber: trackingId,
        amount: estimatedCarbon,
        unit: 'kg CO2e'
    });
});

app.get('/api/track/:trackingNumber', (req, res) => {
  const trackingNumber = req.params.trackingNumber;
  if (!/^\d+$/.test(trackingNumber)) {
    return res.status(400).json({ 
      error: true,
      message: "Invalid tracking number format. Only numeric values are allowed."
    });
  }

  const pkg = packages.find(p => p.trackingNumber === trackingNumber);
  
  if (!pkg) {
    return res.status(404).json({ 
      error: true,
      message: "Tracking number not found. Please check the number and try again."
    });
  }
  
  res.json(pkg);
});

app.get('/api/track/:trackingNumber/route', (req, res) => {
  const { trackingNumber } = req.params;
  const pkg = packages.find(p => p.trackingNumber === trackingNumber);
  
  if (!pkg) {
    return res.status(404).json({ error: true, message: "Package not found" });
  }

  // Mock coordinates for major cities to simulate a route
  const cityCoords = {
    "MEMPHIS, TN": { lat: 35.1495, lng: -90.0490 },
    "INDIANAPOLIS, IN": { lat: 39.7684, lng: -86.1581 },
    "NEW YORK, NY": { lat: 40.7128, lng: -74.0060 },
    "CHICAGO, IL": { lat: 41.8781, lng: -87.6298 },
    "SAN FRANCISCO, CA": { lat: 37.7749, lng: -122.4194 },
    "OAKLAND, CA": { lat: 37.8044, lng: -122.2711 }
  };

  const route = pkg.timeline
    .map(event => {
      const city = Object.keys(cityCoords).find(c => event.location.includes(c));
      return city ? { ...cityCoords[city], location: event.location, date: event.date } : null;
    })
    .filter(Boolean);

  res.json(route);
});

// Get all packages (for Admin Dashboard)
app.get('/api/packages', (req, res) => {
  // In a real app, you would implement pagination here
  res.json(packages);
});

// Alias for backward compatibility or testing
app.get('/api/test-packages', (req, res) => res.json(packages));

app.get('/api/search', (req, res) => {
  const sender = req.query.sender;
  
  if (!sender) {
    return res.status(400).json({ 
      error: true, 
      message: "Sender name is required" 
    });
  }

  const results = packages.filter(p => p.sender.toLowerCase().includes(sender.toLowerCase()));
  res.json(results);
});

app.get('/api/user/shipments', (req, res) => {
  const username = req.query.user;
  if (!username) {
    return res.status(400).json({ error: true, message: "User parameter required" });
  }
  
  // Case-insensitive matching for sender or recipient
  const userShipments = packages.filter(p => 
    (p.sender && p.sender.toLowerCase() === username.toLowerCase()) || 
    (p.recipient && p.recipient.toLowerCase() === username.toLowerCase())
  );
  
  res.json(userShipments);
});

app.post('/api/packages', (req, res) => {
  const newPackage = req.body;
  
  // Basic validation
  if (!newPackage.trackingNumber || !newPackage.sender || !newPackage.recipient) {
    return res.status(400).json({ 
      error: true, 
      message: "Missing required fields (trackingNumber, sender, recipient)" 
    });
  }

  // Check for duplicate tracking number
  if (packages.find(p => p.trackingNumber === newPackage.trackingNumber)) {
    return res.status(409).json({ error: true, message: "Tracking number already exists" });
  }

  packages.push(newPackage);
  logAction('Admin', 'CREATE_PACKAGE', `Created package ${newPackage.trackingNumber}`);
  res.status(201).json(newPackage);
});

app.post('/api/packages/bulk', (req, res) => {
  const newPackages = req.body;
  
  if (!Array.isArray(newPackages)) {
    return res.status(400).json({ error: true, message: "Input must be an array of packages" });
  }

  let addedCount = 0;
  let errors = [];

  newPackages.forEach(pkg => {
    // Basic validation
    if (!pkg.trackingNumber || !pkg.sender || !pkg.recipient) {
      errors.push(`Missing fields for ${pkg.trackingNumber || 'unknown'}`);
      return;
    }
    
    // Check duplicate
    if (packages.find(p => p.trackingNumber === pkg.trackingNumber)) {
      errors.push(`Duplicate tracking number: ${pkg.trackingNumber}`);
      return;
    }

    packages.push(pkg);
    addedCount++;
  });

  logAction('Admin', 'BULK_IMPORT', `Imported ${addedCount} packages. Errors: ${errors.length}`);
  res.json({ success: true, added: addedCount, errors: errors });
});

// Update Package
app.put('/api/packages/:trackingNumber', (req, res) => {
  const { trackingNumber } = req.params;
  const index = packages.findIndex(p => p.trackingNumber === trackingNumber);
  
  if (index === -1) {
    return res.status(404).json({ error: true, message: "Package not found" });
  }

  // Merge existing package with updates
  packages[index] = { ...packages[index], ...req.body };
  logAction('Admin', 'UPDATE_PACKAGE', `Updated package ${trackingNumber}`);
  res.json(packages[index]);
});

// Delete Package
app.delete('/api/packages/:trackingNumber', (req, res) => {
  const { trackingNumber } = req.params;
  const initialLength = packages.length;
  packages = packages.filter(p => p.trackingNumber !== trackingNumber);
  
  if (packages.length === initialLength) {
    return res.status(404).json({ error: true, message: "Package not found" });
  }
  
  logAction('Admin', 'DELETE_PACKAGE', `Deleted package ${trackingNumber}`);
  res.json({ success: true, message: "Package deleted successfully" });
});

// --- User Routes ---
app.get('/api/users', (req, res) => res.json(users.map(({password, ...u}) => u)));

app.post('/api/users', (req, res) => {
  const newUser = { id: `U${Date.now()}`, ...req.body };
  users.push(newUser);
  logAction('Admin', 'CREATE_USER', `Created user ${newUser.email}`);
  res.json(newUser);
});

app.put('/api/user/profile', (req, res) => {
  const { id, currentPassword, newPassword } = req.body;
  const user = users.find(u => u.id === id);

  if (!user) return res.status(404).json({ success: false, message: "User not found" });
  
  if (user.password !== currentPassword) {
    return res.status(401).json({ success: false, message: "Incorrect current password" });
  }

  user.password = newPassword;
  logAction(user.name, 'UPDATE_PROFILE', 'User updated password');
  res.json({ success: true, message: "Password updated successfully" });
});

app.put('/api/users/:id', (req, res) => {
  const { id } = req.params;
  const index = users.findIndex(u => u.id === id);
  if (index !== -1) {
    users[index] = { ...users[index], ...req.body };
    logAction('Admin', 'UPDATE_USER', `Updated user ${id}`);
    res.json(users[index]);
  } else {
    res.status(404).json({ message: "User not found" });
  }
});

app.delete('/api/users/:id', (req, res) => {
  users = users.filter(u => u.id !== req.params.id);
  logAction('Admin', 'DELETE_USER', `Deleted user ${req.params.id}`);
  res.json({ success: true });
});

// --- Location Routes ---
app.get('/api/locations', (req, res) => res.json(locations));

app.post('/api/locations', (req, res) => {
  const newLoc = { id: `L${Date.now()}`, ...req.body };
  locations.push(newLoc);
  logAction('Admin', 'CREATE_LOCATION', `Created location ${newLoc.name}`);
  res.json(newLoc);
});

app.put('/api/locations/:id', (req, res) => {
  const { id } = req.params;
  const index = locations.findIndex(l => l.id === id);
  if (index !== -1) {
    locations[index] = { ...locations[index], ...req.body };
    logAction('Admin', 'UPDATE_LOCATION', `Updated location ${id}`);
    res.json(locations[index]);
  } else {
    res.status(404).json({ message: "Location not found" });
  }
});

app.delete('/api/locations/:id', (req, res) => {
  locations = locations.filter(l => l.id !== req.params.id);
  logAction('Admin', 'DELETE_LOCATION', `Deleted location ${req.params.id}`);
  res.json({ success: true });
});

// --- Settings Routes ---
app.get('/api/settings', (req, res) => res.json(settings));

app.post('/api/settings', (req, res) => {
  settings = { ...settings, ...req.body, lastUpdated: new Date().toISOString() };
  logAction('Admin', 'UPDATE_SETTINGS', 'System settings updated');
  res.json(settings);
});

app.post('/api/settings/reset', (req, res) => {
  settings = { ...DEFAULT_SETTINGS, lastUpdated: new Date().toISOString() };
  logAction('Admin', 'RESET_SETTINGS', 'System settings reset');
  res.json(settings);
});

app.post('/api/signup', (req, res) => {
  const { name, email, password } = req.body;
  
  if (!name || !email || !password) {
    return res.status(400).json({ success: false, message: "All fields are required" });
  }

  if (users.find(u => u.email === email)) {
    return res.status(400).json({ success: false, message: "User already exists" });
  }

  const newUser = {
    id: `U${Date.now()}`,
    name,
    email,
    password,
    role: 'Customer'
  };

  users.push(newUser);
  logAction('System', 'SIGNUP', `New user signed up: ${email}`);
  res.json({ success: true, user: { id: newUser.id, name: newUser.name, role: newUser.role } });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  // Mock Admin Credentials
  if (email === 'Admin' && password === 'Admin123') {
    return res.json({ 
      success: true, 
      user: { id: 'ADMIN', name: 'Administrator', role: 'admin' } 
    });
  }

  // Check against mock database
  const user = users.find(u => u.email === email && u.password === password);

  if (user) {
    return res.json({ 
      success: true, 
      user: { id: user.id, name: user.name, role: user.role.toLowerCase() } 
    });
  }

  res.status(401).json({ success: false, message: 'Invalid credentials' });
});

// --- Audit Logs Routes ---
app.get('/api/audit-logs', (req, res) => res.json(auditLogs));

app.delete('/api/audit-logs', (req, res) => {
  auditLogs = [];
  logAction('Admin', 'CLEAR_LOGS', 'All audit logs cleared');
  res.json({ success: true });
});

// --- Statistics Routes ---
app.get('/api/stats/shipments-by-status', (req, res) => {
  const stats = packages.reduce((acc, pkg) => {
    const status = pkg.status || 'unknown';
    acc[status] = (acc[status] || 0) + 1;
    return acc;
  }, {});
  res.json(stats);
});

app.get('/api/stats/shipments-by-service', (req, res) => {
  const stats = packages.reduce((acc, pkg) => {
    const service = pkg.service || 'Unknown';
    acc[service] = (acc[service] || 0) + 1;
    return acc;
  }, {});
  res.json(stats);
});

app.get('/api/stats/average-delivery-time', (req, res) => {
  const deliveredPackages = packages.filter(p => p.status === 'delivered');
  
  if (deliveredPackages.length === 0) {
    return res.json({ averageHours: 0, count: 0 });
  }

  let totalHours = 0;
  let count = 0;

  deliveredPackages.forEach(pkg => {
    const createdEvent = pkg.timeline.find(e => e.status === 'created');
    const deliveredEvent = pkg.timeline.find(e => e.status === 'delivered');

    if (createdEvent && deliveredEvent) {
      const diffMs = new Date(deliveredEvent.date) - new Date(createdEvent.date);
      totalHours += diffMs / (1000 * 60 * 60);
      count++;
    }
  });

  res.json({ 
    averageHours: count > 0 ? Math.round(totalHours / count) : 0, 
    count 
  });
});

app.get('/api/stats/shipments-by-state', (req, res) => {
  const stats = packages.reduce((acc, pkg) => {
    // Simple heuristic to extract state: look for 2 uppercase letters before the zip code
    // e.g., "123 Main St, New York, NY 10001" -> "NY"
    const match = pkg.destination && pkg.destination.match(/,\s*([A-Z]{2})\s+\d{5}/);
    if (match && match[1]) {
      const state = match[1];
      acc[state] = (acc[state] || 0) + 1;
    }
    return acc;
  }, {});
  res.json(stats);
});

app.get('/api/stats/top-users', (req, res) => {
  const userCounts = packages.reduce((acc, pkg) => {
    const user = pkg.sender || 'Unknown';
    acc[user] = (acc[user] || 0) + 1;
    return acc;
  }, {});

  const sortedUsers = Object.entries(userCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
  res.json(sortedUsers.map(([name, count]) => ({ name, count })));
});

app.get('/api/stats/revenue', (req, res) => {
  let totalRevenue = 0;
  
  packages.forEach(pkg => {
    // Mock revenue calculation logic
    const weightNum = parseFloat(String(pkg.weight).replace(/[^0-9.]/g, '')) || 1;
    let baseRate = pkg.service && pkg.service.toLowerCase().includes('express') ? 25 : 10;
    const distanceFactor = (pkg.destination ? pkg.destination.length % 5 : 1) + 1;
    totalRevenue += baseRate + (weightNum * 1.5) * distanceFactor;
  });

  res.json({ total: totalRevenue.toFixed(2), currency: 'USD' });
});

app.get('/api/stats/shipments-last-7-days', (req, res) => {
  const stats = {};
  const today = new Date();
  
  for (let i = 6; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(today.getDate() - i);
    const dayName = d.toLocaleDateString('en-US', { weekday: 'short' });
    stats[dayName] = Math.floor(Math.random() * 8); // Random data for demo
  }
  res.json(stats);
});

app.get('/api/system/health', (req, res) => {
  res.json({
    status: 'UP',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    cpuLoad: os.loadavg(),
    memory: {
      total: os.totalmem(),
      free: os.freemem(),
      used: os.totalmem() - os.freemem()
    }
  });
});

app.post('/api/shipping/estimate', (req, res) => {
  const { weight, destination, service } = req.body;
  
  if (!weight || !destination) {
    return res.status(400).json({ error: true, message: "Weight and destination are required" });
  }

  // Simple mock calculation logic
  const weightNum = parseFloat(String(weight).replace(/[^0-9.]/g, '')) || 1;
  let baseRate = service && service.toLowerCase().includes('express') ? 25 : 10;
  
  // Mock distance factor (randomized slightly based on destination length)
  const distanceFactor = (destination.length % 5) + 1; 
  const total = (baseRate + (weightNum * 1.5) * distanceFactor).toFixed(2);

  res.json({
    estimatedCost: total,
    currency: "USD",
    details: `Estimate for ${weightNum} lbs to ${destination}`
  });
});

app.get('/api/weather', (req, res) => {
  const { location } = req.query;
  if (!location) {
    return res.status(400).json({ error: true, message: "Location parameter is required" });
  }

  // Mock weather data generation
  const conditions = ['Sunny', 'Cloudy', 'Rainy', 'Partly Cloudy', 'Snowy', 'Clear'];
  const condition = conditions[Math.floor(Math.random() * conditions.length)];
  const temp = Math.floor(Math.random() * (95 - 30) + 30); // Random temp between 30-95 F
  
  res.json({
    location: location,
    temperature: `${temp}°F`,
    condition: condition,
    humidity: `${Math.floor(Math.random() * 60 + 20)}%`,
    windSpeed: `${Math.floor(Math.random() * 15 + 2)} mph`
  });
});

app.get('/api/system/time', (req, res) => {
  res.json({ time: new Date().toISOString() });
});

app.get('/api/system/uptime', (req, res) => {
  const uptime = process.uptime();
  const hours = Math.floor(uptime / 3600);
  const minutes = Math.floor((uptime % 3600) / 60);
  const seconds = Math.floor(uptime % 60);
  res.json({ 
    uptime, 
    formatted: `${hours}h ${minutes}m ${seconds}s` 
  });
});

app.get('/api/system/quote', (req, res) => {
  const quote = quotes[Math.floor(Math.random() * quotes.length)];
  res.json({ quote });
});

app.get('/api/system/memory-history', (req, res) => {
  const history = [];
  const now = Date.now();
  // Generate 10 points of mock memory data
  for (let i = 9; i >= 0; i--) {
    history.push({
      time: new Date(now - i * 60000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      usage: Math.floor(Math.random() * 200 + 300) // Random usage between 300-500 MB
    });
  }
  res.json(history);
});

app.get('/api/system/load-history', (req, res) => {
  const history = [];
  const now = Date.now();
  for (let i = 19; i >= 0; i--) {
    history.push({
      time: new Date(now - i * 60000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      load: Math.floor(Math.random() * 40 + 10) // Mock load 10-50%
    });
  }
  res.json(history);
});

// --- Announcement Routes ---
app.get('/api/announcements', (req, res) => res.json(announcements));

app.post('/api/announcements', (req, res) => {
  const { title, message } = req.body;
  if (!title || !message) {
    return res.status(400).json({ error: true, message: "Title and message are required" });
  }
  
  const newAnnouncement = {
    id: `A${Date.now()}`,
    title,
    message,
    date: new Date().toISOString().split('T')[0]
  };
  
  announcements.unshift(newAnnouncement);
  logAction('Admin', 'CREATE_ANNOUNCEMENT', `Created announcement: ${title}`);
  res.status(201).json(newAnnouncement);
});

app.delete('/api/announcements/:id', (req, res) => {
  const { id } = req.params;
  announcements = announcements.filter(a => a.id !== id);
  logAction('Admin', 'DELETE_ANNOUNCEMENT', `Deleted announcement: ${id}`);
  res.json({ success: true });
});

// CHANGED PORT FROM 5000 TO 5002

// Export for Firebase Functions
exports.api = functions.https.onRequest(app);

// Only listen locally if not running in Firebase Functions
if (!process.env.FUNCTION_NAME) {
  const PORT = process.env.PORT || 5002;
  app.listen(PORT, () => {
    console.log(`🚚 FedEx Clone Backend running on port ${PORT}`);
    console.log('📦 Test tracking numbers:');
    packages.forEach(p => {
      console.log(`   ${p.trackingNumber} - ${p.service} (${p.statusText})`);
    });
    console.log(`🌐 Frontend URL: http://localhost:${PORT}`);
  });
}
