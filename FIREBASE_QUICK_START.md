# 🔥 Firebase Quick Start - FedEx Clone

Get your app deployed to Firebase in **10 minutes**!

## ⚡ 5-Step Quick Deploy

### Step 1: Install Firebase CLI (2 min)
```bash
npm install -g firebase-tools
firebase login
firebase use fedex-37e89
```

### Step 2: Set Environment Variables (2 min)
```bash
firebase functions:config:set \
  mongo.uri="mongodb+srv://greatugbome5_db_user:76TtO6KU4hIrf0lv@cluster0.yas9t3a.mongodb.net/fedex-clone" \
  email.user="your_email@gmail.com" \
  email.pass="your_app_password" \
  base.url="https://fedex-37e89.web.app" \
  cors.origins="https://fedex-37e89.web.app"
```

### Step 3: Test Locally (3 min)
```bash
cd backend
npm install
npm start
# In another terminal:
curl http://localhost:5002/health
# Should return: {"status":"ok","database":"connected"}
```

### Step 4: Deploy (2 min)
```bash
firebase deploy
```

Wait for completion... ✅

### Step 5: Test Live (1 min)
```bash
# Test health
curl https://fedex-37e89.cloudfunctions.net/api/health

# Open in browser
# https://fedex-37e89.web.app
```

**Done!** Your app is live! 🚀

---

## 🔑 What You Need

Before running the 5 steps above:

- [ ] Firebase CLI installed
- [ ] Logged in to Firebase
- [ ] MongoDB Atlas credentials
- [ ] Gmail app password (from https://myaccount.google.com/apppasswords)

---

## 📖 Full Documentation

For detailed information, see:
- **[FIREBASE_DEPLOYMENT.md](./FIREBASE_DEPLOYMENT.md)** - Complete technical guide
- **[FIREBASE_DEPLOYMENT_CHECKLIST.md](./FIREBASE_DEPLOYMENT_CHECKLIST.md)** - Step-by-step checklist

---

## ✅ Verification

After deployment, verify:

```bash
# 1. Check health
curl https://fedex-37e89.cloudfunctions.net/api/health
# Should return: {"status":"ok",...}

# 2. Check tracking
curl "https://fedex-37e89.cloudfunctions.net/api/track/123456789012"
# Should return shipment data

# 3. Check frontend loads
curl https://fedex-37e89.web.app | head -20
# Should return HTML

# 4. View logs
firebase functions:log --limit 10
# Should show successful requests
```

---

## 🆘 Troubleshooting

**Error: "Could not authenticate with Firebase"**
```bash
firebase logout
firebase login
```

**Error: "Cannot find module"**
```bash
cd backend && npm install && cd ..
firebase deploy --only functions
```

**Error: MongoDB auth failed**
- Verify MongoDB URI is correct
- Check IP whitelisting in MongoDB Atlas
- Update: `firebase functions:config:set mongo.uri="correct_uri"`

**Error: CORS error in browser**
- Update CORS: `firebase functions:config:set cors.origins="https://fedex-37e89.web.app"`
- Redeploy: `firebase deploy --only functions`

---

## 📊 Useful Commands

```bash
# Check status
firebase deploy status

# View logs
firebase functions:log

# Update just backend
firebase deploy --only functions

# Update just frontend
firebase deploy --only hosting

# See all configs
firebase functions:config:get
```

---

## 🌐 Your URLs

- **Website:** https://fedex-37e89.web.app
- **API:** https://fedex-37e89.cloudfunctions.net/api
- **Console:** https://console.firebase.google.com/project/fedex-37e89

---

## 🎉 Success!

Your FedEx Clone is now deployed on Firebase! 

Visit: **https://fedex-37e89.web.app**

---

For more help, read [FIREBASE_DEPLOYMENT.md](./FIREBASE_DEPLOYMENT.md)
