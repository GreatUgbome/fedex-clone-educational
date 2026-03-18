# 🎯 FedEx Clone - Quick Reference Guide

## 📋 Files & Commands Reference

### Backend Setup
```bash
cd backend
npm install           # Install dependencies
npm start            # Start server (production)
npm run dev          # Start with auto-reload
npm test             # Run tests
```

### Key Files Modified
```
✅ backend/server.js         - Added MongoDB connection, health check
✅ frontend/script.js        - Fixed API URL detection
✅ frontend/auth.js          - Fixed Auth API URL detection
✅ backend/.env              - Added PORT, ALLOWED_ORIGINS
```

### New Documentation Files
```
📄 DEPLOYMENT_GUIDE.md         - Detailed deployment instructions
📄 DEPLOYMENT_CHECKLIST.md     - Step-by-step checklist
📄 README_FULL.md              - Complete project documentation
📄 setup.sh                    - Automated setup script
```

## 🔑 Essential Environment Variables

```env
# Required
MONGO_URI=mongodb+srv://username:password@cluster.net/db
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password
BASE_URL=https://your-app.onrender.com

# Optional
PORT=5002
NODE_ENV=production
ALLOWED_ORIGINS=https://app.onrender.com
```

## 🚀 One-Line Start Commands

```bash
# Local development
cd backend && npm install && npm start

# Test after starting
curl http://localhost:5002/health

# Test tracking API
curl http://localhost:5002/api/track/123456789012
```

## 📌 Important URLs

| Environment | URL |
|-------------|-----|
| Local | http://localhost:5002 |
| Local API | http://localhost:5002/api |
| Local Health | http://localhost:5002/health |
| Render API | https://fedex-clone-api.onrender.com |
| Render Health | https://fedex-clone-api.onrender.com/health |

## 🔍 Quick Diagnostics

```bash
# Check if server is running
curl http://localhost:5002/health

# Check logs on Render
# Dashboard → Your Service → Logs

# Check MongoDB connection
# Server response should show: "database": "connected"

# Test API endpoint
curl http://localhost:5002/api/track/123456789012

# Kill port 5002 if in use
lsof -ti:5002 | xargs kill -9
```

## 🛠️ Common Tasks

### Restart Backend
```bash
pkill -f "node server.js"
cd backend && npm start
```

### Update Dependencies
```bash
cd backend
npm install              # Install new packages
npm update              # Update existing
npm audit fix           # Fix vulnerabilities
```

### View Server Logs
```bash
# Local
npm start               # Logs display in terminal

# Render
# Go to: Dashboard → Your Service → Logs
```

### Add New Dependencies
```bash
cd backend
npm install package-name
git add package.json package-lock.json
git commit -m "Add package-name"
git push
```

## 📱 API Testing with curl

### Create Shipment (Admin Only)
```bash
curl -X POST http://localhost:5002/api/shipment \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "id":"123456789",
    "status":"In Transit",
    "service":"FedEx Ground",
    "destination":"New York, NY"
  }'
```

### Track Shipment (Public)
```bash
curl http://localhost:5002/api/track/123456789012
```

### Get Settings
```bash
curl http://localhost:5002/api/settings
```

### Health Check
```bash
curl http://localhost:5002/health
```

## 🐛 Troubleshooting Quick Fix

| Problem | Quick Fix |
|---------|-----------|
| MongoDB auth failed | Update MONGO_URI in .env |
| Port in use | `lsof -ti:5002 \| xargs kill -9` |
| CORS error | Add domain to ALLOWED_ORIGINS |
| Module not found | `rm -rf node_modules && npm install` |
| .env not loading | Restart server after updating .env |

## 📊 Project Stats

- **Backend:** Node.js + Express
- **Database:** MongoDB
- **Frontend:** Vanilla JavaScript + Tailwind CSS
- **Authentication:** Firebase + Local
- **Deployment:** Render.com
- **API Endpoints:** 20+
- **Database Collections:** 8

## 🎯 Deployment Flow

```
Code → GitHub → Render → Live at https://service.onrender.com
```

## 📚 Related Docs

- Read DEPLOYMENT_GUIDE.md for detailed steps
- Read DEPLOYMENT_CHECKLIST.md for step-by-step checklist
- Read README_FULL.md for complete project info

## ⚡ Performance Tips

1. Replace mock API calls with real endpoints
2. Add database indexes for frequently queries
3. Implement caching where possible
4. Use CDN for static assets
5. Monitor query performance in MongoDB

## 🔒 Security Checklist

- [ ] No credentials in GitHub
- [ ] .env file in .gitignore
- [ ] HTTPS enabled in production
- [ ] CORS properly configured
- [ ] Input validation on all endpoints
- [ ] Rate limiting active
- [ ] Strong passwords for MongoDB

## 📞 Support Resources

- **Render Docs:** https://docs.render.com
- **MongoDB Atlas:** https://docs.cloud.mongodb.com
- **Express.js:** https://expressjs.com/en/api.html
- **Firebase:** https://firebase.google.com/docs

---

**Keep this guide handy for quick reference!** 📌
