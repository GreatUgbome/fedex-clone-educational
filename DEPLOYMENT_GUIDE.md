# 🚀 FedEx Clone - Complete Deployment Guide

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Local Development](#local-development)
3. [MongoDB Setup](#mongodb-setup)
4. [Render Deployment](#render-deployment)
5. [Environment Variables](#environment-variables)
6. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- Node.js 16+ installed
- MongoDB Atlas account (or local MongoDB)
- Render.com account (for hosting)
- Git installed

---

## Local Development

### 1. Install Backend Dependencies
```bash
cd backend
npm install
```

### 2. Configure Environment Variables
Create a `.env` file in the `backend` directory with the following:

```env
# MongoDB Connection
MONGO_URI=mongodb+srv://YOUR_USERNAME:YOUR_PASSWORD@YOUR_CLUSTER.mongodb.net/fedex-clone?retryWrites=true&w=majority

# Server Configuration
PORT=5002
BASE_URL=http://localhost:5002
NODE_ENV=development

# CORS Configuration
ALLOWED_ORIGINS=http://localhost:5002,http://localhost:3000

# Email Configuration (for password reset, verification)
EMAIL_USER=your-gmail@gmail.com
EMAIL_PASS=your-app-specific-password
```

### 3. Start the Backend Server
```bash
npm start
# or for development with auto-reload:
npm run dev
```

The server will start at `http://localhost:5002`

### 4. Test the Server
```bash
curl http://localhost:5002/health
# Expected response: {"status":"ok","database":"connected","timestamp":"..."}
```

---

## MongoDB Setup

### Option A: MongoDB Atlas (Cloud) - RECOMMENDED

1. **Create a free MongoDB Atlas cluster:**
   - Go to https://www.mongodb.com/cloud/atlas
   - Create a new cluster (free tier available)
   - Create a database user with a password

2. **Get your connection string:**
   - In MongoDB Atlas, click "Connect" → "Connect your application"
   - Copy the connection string
   - Replace `<password>` and `<username>` with your credentials

3. **Update your `.env` file:**
   ```env
   MONGO_URI=mongodb+srv://username:password@cluster0.xxxxx.mongodb.net/fedex-clone?retryWrites=true&w=majority
   ```

### Option B: Local MongoDB

1. **Install MongoDB Community:**
   - macOS: `brew install mongodb-community`
   - Windows: Download from https://www.mongodb.com/try/download/community
   - Linux: Follow MongoDB installation guide

2. **Start MongoDB:**
   ```bash
   brew services start mongodb-community
   ```

3. **Update `.env`:**
   ```env
   MONGO_URI=mongodb://localhost:27017/fedex-clone
   ```

---

## Render Deployment

### Step 1: Push Code to GitHub

```bash
git add .
git commit -m "Prepare for Render deployment"
git push origin main
```

### Step 2: Set Up Render Service

1. **Go to https://render.com** and log in
2. **Create a new Web Service:**
   - Click "New +" → "Web Service"
   - Connect your GitHub repository
   - Select the `fedex-clone-educational` repository

3. **Configure the service:**
   - **Name**: `fedex-clone-api`
   - **Environment**: Node
   - **Region**: Choose closest to you
   - **Branch**: `main`
   - **Build Command**: `cd backend && npm install`
   - **Start Command**: `cd backend && npm start`
   - **Plan**: Free tier (or Starter if you want persistence)

### Step 3: Add Environment Variables

In Render dashboard, go to your service and add the following Environment Variables:

```
MONGO_URI=mongodb+srv://YOUR_USERNAME:YOUR_PASSWORD@YOUR_CLUSTER.mongodb.net/fedex-clone?retryWrites=true&w=majority
PORT=5002
BASE_URL=https://YOUR_SERVICE_NAME.onrender.com
NODE_ENV=production
ALLOWED_ORIGINS=https://YOUR_SERVICE_NAME.onrender.com,https://YOUR_FRONTEND_URL.onrender.com
EMAIL_USER=your-gmail@gmail.com
EMAIL_PASS=your-app-specific-password
```

### Step 4: Deploy

Render will automatically deploy when you push changes to the main branch.

---

## Frontend Configuration

### Update the Frontend API URL

Edit `frontend/auth.js` and `frontend/script.js`:

Change:
```javascript
const API_BASE_URL = 'https://fedex-clone-educational.onrender.com';
```

To match your Render deployment URL (it will be shown in the Render dashboard).

---

## Environment Variables Reference

| Variable | Description | Example |
|----------|-------------|---------|
| `MONGO_URI` | MongoDB connection string | `mongodb+srv://user:pass@cluster.net/db` |
| `PORT` | Server port | `5002` |
| `BASE_URL` | Application base URL | `https://app.onrender.com` |
| `NODE_ENV` | Environment | `production` or `development` |
| `ALLOWED_ORIGINS` | CORS allowed origins (comma-separated) | `https://app.onrender.com` |
| `EMAIL_USER` | Gmail address for sending emails | `your@gmail.com` |
| `EMAIL_PASS` | Gmail app password | `xxxx xxxx xxxx xxxx` |

---

## Health Check

Test your deployment:
```bash
curl https://YOUR_SERVICE_NAME.onrender.com/health
```

Expected response:
```json
{
  "status": "ok",
  "database": "connected",
  "timestamp": "2026-03-17T21:30:00.000Z"
}
```

---

## Troubleshooting

### MongoDB Connection Error

**Error**: `MongoServerError: bad auth : authentication failed`

**Solutions**:
1. Verify MongoDB credentials are correct
2. Check IP whitelist in MongoDB Atlas (add 0.0.0.0/0 for all IPs)
3. Ensure password is properly URL-encoded if it contains special characters
4. Try creating a new MongoDB cluster

### Server Not Starting

**Error**: Port already in use

**Solution**: 
```bash
# Kill the process using port 5002
lsof -ti:5002 | xargs kill -9
```

### CORS Errors

**Error**: `Access to XMLHttpRequest blocked by CORS policy`

**Solution**: 
- Ensure `ALLOWED_ORIGINS` in `.env` includes your frontend URL
- Restart the server after updating `.env`

### Render Build Fails

1. Check the logs in Render dashboard
2. Ensure `cd backend &&` is included in build and start commands
3. Verify all dependencies are in `package.json`

---

## Testing API Endpoints

### Login/Signup (Local Auth)
```bash
# Signup
curl -X POST http://localhost:5002/api/signup \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"password123"}'

# Login
curl -X POST http://localhost:5002/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password123"}'
```

### Track Shipment
```bash
curl http://localhost:5002/api/track/123456789012
```

### Get Settings
```bash
curl http://localhost:5002/api/settings
```

---

## Common Issues & Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| `Cannot find module` | Dependencies not installed | Run `npm install` |
| `EADDRINUSE` | Port already in use | Kill the process or change PORT |
| `MongooseError: Cannot connect` | MongoDB not running | Start MongoDB or check URI |
| `CORS error` | Frontend URL not in ALLOWED_ORIGINS | Add to .env |
| `Firebase error` | Credentials invalid | Remove or update Firebase config |

---

## Next Steps

1. ✅ Test locally
2. ✅ Fix MongoDB credentials if needed
3. ✅ Deploy to Render
4. ✅ Update frontend API URLs
5. ✅ Test production deployment

---

## Support

For issues:
1. Check server logs: `http://localhost:5002/health`
2. Check Render logs in dashboard
3. Verify all environment variables are set
4. Ensure MongoDB is accessible

---

## Success Checklist

- [ ] Backend starts locally without errors
- [ ] Health endpoint returns `database: "connected"`
- [ ] MongoDB connection is successful
- [ ] Render service is provisioned
- [ ] Environment variables are set in Render
- [ ] Frontend can reach backend API
- [ ] Authentication works
- [ ] Can track shipments

Happy shipping! 📦
