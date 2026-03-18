# 🚀 Firebase Deployment Guide - FedEx Clone

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Setup Firebase CLI](#setup-firebase-cli)
3. [Configure Firebase Project](#configure-firebase-project)
4. [Environment Setup](#environment-setup)
5. [Local Testing](#local-testing)
6. [Deploy to Firebase](#deploy-to-firebase)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites

You should have:
- ✅ Node.js 16+ installed
- ✅ Firebase project created (fedex-37e89)
- ✅ Firebase credentials/serviceAccountKey.json
- ✅ MongoDB connection string
- ✅ Gmail app-specific password
- ✅ Git and code pushed to GitHub (optional but recommended)

---

## Setup Firebase CLI

### 1. Install Firebase CLI

```bash
npm install -g firebase-tools
```

Verify installation:
```bash
firebase --version
```

### 2. Login to Firebase

```bash
firebase login
```

This will open a browser for authentication. Log in with your Google account that owns the Firebase project.

### 3. List Your Projects

```bash
firebase projects:list
```

You should see `fedex-37e89` in the list.

---

## Configure Firebase Project

### 1. Check Current Project Setup

```bash
firebase use
```

### 2. Set Active Project

```bash
firebase use fedex-37e89
```

### 3. Verify firebase.json Configuration

Your `firebase.json` should have:

```json
{
  "hosting": {
    "public": "frontend",
    "rewrites": [
      {
        "source": "/api/**",
        "function": "api"
      },
      {
        "source": "**",
        "destination": "/index.html"
      }
    ]
  },
  "functions": {
    "source": "backend",
    "runtime": "nodejs18",
    "timeoutSeconds": 60,
    "memory": "256MB"
  }
}
```

---

## Environment Setup

### 1. Configure Firebase Environment Variables

Set environment variables for Cloud Functions:

```bash
firebase functions:config:set mongo.uri="YOUR_MONGODB_URI" \
  email.user="your_email@gmail.com" \
  email.pass="your_app_password" \
  base.url="https://fedex-37e89.web.app" \
  cors.origins="https://fedex-37e89.web.app"
```

Or set them individually:

```bash
# MongoDB URI
firebase functions:config:set mongo.uri="mongodb+srv://greatugbome5_db_user:76TtO6KU4hIrf0lv@cluster0.yas9t3a.mongodb.net/fedex-clone"

# Email credentials
firebase functions:config:set email.user="your_email@gmail.com"
firebase functions:config:set email.pass="app_specific_password"

# Base URL
firebase functions:config:set base.url="https://fedex-37e89.web.app"

# CORS Origins
firebase functions:config:set cors.origins="https://fedex-37e89.web.app"
```

### 2. Verify Environment Variables

```bash
firebase functions:config:get
```

### 3. Store Local .env for Development

Create `backend/.env` with:

```env
MONGO_URI=mongodb+srv://greatugbome5_db_user:76TtO6KU4hIrf0lv@cluster0.yas9t3a.mongodb.net/fedex-clone
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password
BASE_URL=https://fedex-37e89.web.app
NODE_ENV=development
ALLOWED_ORIGINS=http://localhost:5002,http://localhost:3000,https://fedex-37e89.web.app
```

---

## Local Testing

### 1. Install Backend Dependencies

```bash
cd backend
npm install
cd ..
```

### 2. Start Firebase Emulator Suite (Optional)

```bash
firebase emulators:start
```

This will run Firebase locally for testing.

### 3. Test Backend Locally

```bash
cd backend
npm start
```

Should show: `Backend server running on http://localhost:5002`

### 4. Test Health Endpoint

```bash
curl http://localhost:5002/health
```

Expected response:
```json
{"status":"ok","database":"connected","timestamp":"..."}
```

### 5. Test Tracking API

```bash
curl http://localhost:5002/api/track/123456789012
```

---

## Deploy to Firebase

### 1. Build Backend

```bash
# Ensure dependencies are installed
cd backend
npm install
cd ..
```

### 2. Verify All Files

```bash
# Check backend
ls -la backend/

# Check frontend  
ls -la frontend/

# Check firebase.json
cat firebase.json
```

### 3. Deploy to Firebase

**Deploy Everything (Frontend + Backend):**
```bash
firebase deploy
```

**Deploy Only Frontend:**
```bash
firebase deploy --only hosting
```

**Deploy Only Backend (Cloud Functions):**
```bash
firebase deploy --only functions
```

---

## After Deployment

### 1. Get Your URLs

**Frontend URL:**
```
https://fedex-37e89.web.app
```

**API Base URL:**
```
https://fedex-37e89.cloudfunctions.net
```

**API Endpoints:**
```
https://fedex-37e89.cloudfunctions.net/api/track/:id
https://fedex-37e89.cloudfunctions.net/api/shipments
etc.
```

### 2. Test Live Application

```bash
# Test frontend
curl https://fedex-37e89.web.app

# Test health
curl https://fedex-37e89.cloudfunctions.net/api/health

# Test tracking
curl https://fedex-37e89.cloudfunctions.net/api/track/123456789012
```

### 3. View Logs

```bash
# View function logs
firebase functions:log

# Or in Firebase Console:
# Console > Cloud Functions > Select 'api' > Logs
```

---

## Environment Variables Reference

| Variable | Required | Example | Where Set |
|----------|----------|---------|-----------|
| `MONGO_URI` | Yes | mongodb+srv://user:pass@... | Firebase Config |
| `EMAIL_USER` | Yes | your@gmail.com | Firebase Config |
| `EMAIL_PASS` | Yes | xxxx xxxx xxxx xxxx | Firebase Config |
| `BASE_URL` | Yes | https://fedex-37e89.web.app | Firebase Config |
| `CORS_ORIGINS` | No | https://fedex-37e89.web.app | Firebase Config |
| `NODE_ENV` | No | production | Firebase Config |

### Set in Firebase:
```bash
firebase functions:config:set key.name="value"
```

### Retrieve:
```bash
firebase functions:config:get
```

---

## Important URLs

| Purpose | URL |
|---------|-----|
| Website | https://fedex-37e89.web.app |
| Tracking | https://fedex-37e89.web.app |
| API | https://fedex-37e89.cloudfunctions.net |
| Health Check | https://fedex-37e89.cloudfunctions.net/api/health |
| Admin | https://fedex-37e89.web.app/admin |
| Firebase Console | https://console.firebase.google.com/project/fedex-37e89 |

---

## Monitoring & Maintenance

### View Deployment Status

```bash
firebase deploy status
```

### View Function Logs

```bash
firebase functions:log --limit 50
```

### Update Deployment

Make changes and redeploy:

```bash
git add .
git commit -m "Update feature"
firebase deploy
```

### Update Only Functions

```bash
cd backend
npm install  # if dependencies changed
cd ..
firebase deploy --only functions
```

---

## Troubleshooting

### Issue: "Error: Could not authenticate with Firebase"

**Solution:**
```bash
firebase logout
firebase login
firebase use fedex-37e89
```

### Issue: "Cannot find module"

**Solution:**
```bash
cd backend
npm install
npm test  # verify
cd ..
firebase deploy --only functions
```

### Issue: MongoDB Connection Error

**Solution:**
1. Verify MONGO_URI is set correctly:
   ```bash
   firebase functions:config:get | grep mongo
   ```

2. Check MongoDB IP whitelist:
   - Go to MongoDB Atlas
   - Network Access
   - Add 0.0.0.0/0 (or specific Firebase IPs)

3. Verify credentials:
   ```bash
   firebase functions:config:set mongo.uri="new_uri"
   firebase deploy --only functions
   ```

### Issue: CORS Error

**Solution:**
1. Ensure ALLOWED_ORIGINS is set:
   ```bash
   firebase functions:config:set cors.origins="https://fedex-37e89.web.app"
   ```

2. Check server.js CORS configuration

3. Redeploy:
   ```bash
   firebase deploy --only functions
   ```

### Issue: Function Timeout

**Solution:**
1. Increase timeout in firebase.json:
   ```json
   "functions": {
     "timeoutSeconds": 120
   }
   ```

2. Redeploy:
   ```bash
   firebase deploy --only functions
   ```

### Issue: Frontend Shows 404 or "Cannot GET /"

**Solution:**
1. Verify firebase.json rewrites are correct
2. Redeploy hosting:
   ```bash
   firebase deploy --only hosting
   ```

### Issue: Email Not Sending

**Solution:**
1. Verify EMAIL_USER and EMAIL_PASS:
   ```bash
   firebase functions:config:get | grep email
   ```

2. Test Gmail app password at https://myaccount.google.com/apppasswords

3. Update if needed:
   ```bash
   firebase functions:config:set email.user="correct_email@gmail.com"
   firebase functions:config:set email.pass="correct_password"
   firebase deploy --only functions
   ```

---

## Firebase Console Navigation

Access your project:
```
https://console.firebase.google.com/project/fedex-37e89
```

### Key Sections:

1. **Build → Functions** - Manage Cloud Functions
   - View deployed functions
   - Check logs
   - Monitor performance

2. **Build → Hosting** - Manage Frontend
   - View deployment history
   - Preview releases
   - View domain info

3. **Build → Authentication** - User Management
   - Firebase Auth users
   - Sign-in methods
   - Custom claims

4. **Firestore Database** - View data (if using)

5. **Storage** - View/manage files

6. **Realtime Database** - View real-time data

---

## CI/CD with GitHub Actions

Optional: Automate deployment on GitHub push

Create `.github/workflows/firebase-deploy.yml`:

```yaml
name: Deploy to Firebase

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install Firebase CLI
        run: npm install -g firebase-tools
      
      - name: Deploy to Firebase
        run: firebase deploy --token ${{ secrets.FIREBASE_TOKEN }}
```

Then:
1. Generate token: `firebase login:ci`
2. Add to GitHub secrets as `FIREBASE_TOKEN`

---

## Success Checklist

- [ ] Firebase CLI installed and logged in
- [ ] Project set to `fedex-37e89`
- [ ] firebase.json configured correctly
- [ ] Environment variables set in Firebase
- [ ] Backend builds without errors
- [ ] Frontend builds successfully
- [ ] Local testing passes
- [ ] Deploy completes without errors
- [ ] Website loads at https://fedex-37e89.web.app
- [ ] API responds at https://fedex-37e89.cloudfunctions.net/api/health
- [ ] Tracking works
- [ ] Authentication works
- [ ] No errors in function logs

---

## Quick Command Reference

```bash
# Setup
firebase login
firebase use fedex-37e89

# Configuration
firebase functions:config:set mongo.uri="uri"
firebase functions:config:get

# Local Testing
firebase emulators:start
npm start (in backend)

# Deployment
firebase deploy              # Everything
firebase deploy --only hosting
firebase deploy --only functions

# Monitoring
firebase functions:log
firebase deploy status
firebase open console
```

---

## Need Help?

- **Firebase Docs:** https://firebase.google.com/docs
- **Cloud Functions:** https://firebase.google.com/docs/functions
- **Hosting:** https://firebase.google.com/docs/hosting
- **Firebase CLI:** https://firebase.google.com/docs/cli

---

## Next Steps

1. ✅ Set up Firebase CLI
2. ✅ Configure environment variables
3. ✅ Test locally
4. ✅ Deploy to Firebase
5. ✅ Test live application
6. ✅ Monitor with logs

**Your app is live at:** https://fedex-37e89.web.app 🎉
