# FedEx Clone - Educational Shipping & Tracking Application

> � **[FIREBASE DEPLOYMENT](./FIREBASE_QUICK_START.md)** - Deploy in 10 minutes!
> 
> 👉 **[START_HERE.md](./START_HERE.md)** - Quick overview

## Deployment Options

### 🔥 **Firebase (Recommended)** ⭐
Deploy to Firebase Hosting + Cloud Functions
- **Quick Start:** [FIREBASE_QUICK_START.md](./FIREBASE_QUICK_START.md) (5 min read)
- **Full Guide:** [FIREBASE_DEPLOYMENT.md](./FIREBASE_DEPLOYMENT.md) (detailed)
- **Checklist:** [FIREBASE_DEPLOYMENT_CHECKLIST.md](./FIREBASE_DEPLOYMENT_CHECKLIST.md) (step-by-step)

### 🎯 Render (Alternative)
Deploy to Render.com
- **Guide:** [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md)
- **Checklist:** [DEPLOYMENT_CHECKLIST.md](./DEPLOYMENT_CHECKLIST.md)

---

## Quick Links

| Purpose | Document |
|---------|----------|
| **Quick Firebase Deploy** | [FIREBASE_QUICK_START.md](./FIREBASE_QUICK_START.md) ⭐ |
| **Firebase Full Guide** | [FIREBASE_DEPLOYMENT.md](./FIREBASE_DEPLOYMENT.md) |
| **Firebase Checklist** | [FIREBASE_DEPLOYMENT_CHECKLIST.md](./FIREBASE_DEPLOYMENT_CHECKLIST.md) |
| **Project Overview** | [START_HERE.md](./START_HERE.md) |
| **Quick Commands** | [QUICK_REFERENCE.md](./QUICK_REFERENCE.md) |
| **Complete Docs** | [README_FULL.md](./README_FULL.md) |

---

## What is This?

A full-stack educational project demonstrating a FedEx-like shipment tracking and management system built with modern technologies.

## Technology Stack

- **Backend:** Node.js + Express.js (Cloud Functions compatible)
- **Database:** MongoDB Atlas
- **Frontend:** Vanilla JavaScript + Tailwind CSS
- **Authentication:** Firebase + Email
- **Hosting:** Firebase (or Render.com)

## Getting Started (30 seconds)

### Option A: Deploy to Firebase (Recommended)
```bash
# 1. Install and login
npm install -g firebase-tools
firebase login && firebase use fedex-37e89

# 2. Set environment variables
firebase functions:config:set mongo.uri="YOUR_URI" email.user="email@gmail.com" email.pass="app_password"

# 3. Deploy
firebase deploy

# Visit: https://fedex-37e89.web.app
```

👉 **[Full Firebase Guide](./FIREBASE_QUICK_START.md)**

### Option B: Test Locally
```bash
cd backend
npm install
npm start
# Visit: http://localhost:5002
```

---

## Project Status

**Status:** ✅ Ready for Production Deployment

- ✅ Backend: Working
- ✅ Frontend: Working  
- ✅ Firebase: Configured
- ✅ Routing: Set up
- ⚠️ Credentials: Need your MongoDB URI

---

## Key Features

- 📦 Real-time package tracking
- 👥 User authentication & profiles
- 🗺️ Interactive maps
- 📊 Admin dashboard with analytics
- ✉️ Email notifications
- 🏷️ Print shipping labels
- 📞 Support & contact forms
- 🔐 Secure authentication

---

## What's Been Fixed

✅ Backend Server Ready
- MongoDB connection
- Health check endpoint
- Firebase Cloud Functions configured
- CORS properly set up
- Rate limiting active

✅ Frontend Ready
- Auto-detects API URL (local vs Firebase)
- Works with both environments
- No hardcoded URLs

✅ Configuration Ready
- firebase.json updated
- .firebaserc set up
- Environment variables configured

---

## Deployment

### Firebase (Recommended - Get Started Fast)

1. **[FIREBASE_QUICK_START.md](./FIREBASE_QUICK_START.md)** - Deploy in 10 min
2. **[FIREBASE_DEPLOYMENT.md](./FIREBASE_DEPLOYMENT.md)** - Full technical guide
3. **[FIREBASE_DEPLOYMENT_CHECKLIST.md](./FIREBASE_DEPLOYMENT_CHECKLIST.md)** - Checklist version

### Render (Alternative)

1. **[DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md)** - Complete Render guide
2. **[DEPLOYMENT_CHECKLIST.md](./DEPLOYMENT_CHECKLIST.md)** - Render checklist

---

## Documentation

| File | Purpose | Read Time |
|------|---------|-----------|
| **START_HERE.md** | Overview & next steps | 5 min |
| **FIREBASE_QUICK_START.md** | Deploy to Firebase fast | 10 min |
| **FIREBASE_DEPLOYMENT.md** | Firebase technical guide | 30 min |
| **FIREBASE_DEPLOYMENT_CHECKLIST.md** | Firebase checklist | 20 min |
| **QUICK_REFERENCE.md** | Commands & URLs | 5 min |
| **README_FULL.md** | Complete project info | 15 min |

---

## Quick Test

After starting the server:

```bash
# Health check
curl http://localhost:5002/health

# Track a shipment
curl http://localhost:5002/api/track/123456789012

# For Firebase (after deploy):
curl https://fedex-37e89.cloudfunctions.net/api/health
```

---

## Environment Variables

| Variable | Required | Value |
|----------|----------|-------|
| `MONGO_URI` | Yes | mongodb+srv://... |
| `EMAIL_USER` | Yes | your_email@gmail.com |
| `EMAIL_PASS` | Yes | app_specific_password |
| `BASE_URL` | Yes | https://fedex-37e89.web.app |
| `NODE_ENV` | No | production/development |

---

## Your URLs (After Firebase Deploy)

| Purpose | URL |
|---------|-----|
| **Website** | https://fedex-37e89.web.app |
| **API** | https://fedex-37e89.cloudfunctions.net |
| **Health** | https://fedex-37e89.cloudfunctions.net/api/health |
| **Console** | https://console.firebase.google.com/project/fedex-37e89 |

---

## Need Help?

1. Check **[START_HERE.md](./START_HERE.md)** for overview
2. Read **[FIREBASE_QUICK_START.md](./FIREBASE_QUICK_START.md)** to deploy fast
3. Use **[QUICK_REFERENCE.md](./QUICK_REFERENCE.md)** for commands
4. Check **[FIREBASE_DEPLOYMENT.md](./FIREBASE_DEPLOYMENT.md)** for details

---

## License

Educational Use Only

---

## 🚀 Ready to Deploy?

👉 **[Open FIREBASE_QUICK_START.md](./FIREBASE_QUICK_START.md)** to deploy in 10 minutes!

Or **[Open START_HERE.md](./START_HERE.md)** for an overview first.

Happy shipping! 📦✈️


