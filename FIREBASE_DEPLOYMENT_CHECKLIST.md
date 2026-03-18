# ✅ Firebase Deployment Checklist - FedEx Clone

Complete these steps in order to deploy to Firebase.

---

## 📋 Phase 1: Prerequisites Check

- [ ] Node.js 16+ installed (`node --version`)
- [ ] npm installed (`npm --version`)
- [ ] Git installed (`git --version`)
- [ ] Firebase project created (fedex-37e89)
- [ ] Google account with Firebase access
- [ ] MongoDB Atlas credentials ready
- [ ] Gmail app-specific password generated
- [ ] serviceAccountKey.json in backend/ directory
- [ ] .firebaserc file exists in project root

**How to check:**
```bash
node --version
npm --version
firebase --version  # Should show version if CLI installed
ls -la serviceAccountKey.json
ls -la .firebaserc
```

---

## 🔧 Phase 2: Install Firebase CLI

### Step 1: Install Firebase Tools
```bash
npm install -g firebase-tools
```

### Step 2: Verify Installation
```bash
firebase --version
```

Expected output: `version X.X.X` or similar

- [ ] Firebase CLI installed
- [ ] Version 12.0.0 or higher

**If stuck:** https://firebase.google.com/docs/cli

---

## 🔑 Phase 3: Authenticate with Firebase

### Step 1: Login to Firebase
```bash
firebase login
```

This will open your browser for Google authentication.

- [ ] Logged in successfully
- [ ] Saw the success message

### Step 2: List Your Firebase Projects
```bash
firebase projects:list
```

You should see `fedex-37e89` in the list.

- [ ] See fedex-37e89 in project list

### Step 3: Set Active Project
```bash
firebase use fedex-37e89
```

- [ ] Project set to fedex-37e89
- [ ] Confirmed with `firebase use`

---

## 🗂️ Phase 4: Configure Firebase Files

### Step 1: Verify firebase.json

```bash
cat firebase.json
```

Should contain:
- [ ] hosting section with "frontend" as public
- [ ] rewrites for /api/** to functions
- [ ] rewrites for ** to /index.html
- [ ] functions section with source: "backend"
- [ ] runtime: "nodejs18"

### Step 2: Verify .firebaserc

```bash
cat .firebaserc
```

Should show:
```json
{
  "projects": {
    "default": "fedex-37e89"
  }
}
```

- [ ] .firebaserc configured correctly
- [ ] Default project is fedex-37e89

---

## 🌐 Phase 5: Set Environment Variables

### Step 1: Set MongoDB URI
```bash
firebase functions:config:set mongo.uri="mongodb+srv://greatugbome5_db_user:76TtO6KU4hIrf0lv@cluster0.yas9t3a.mongodb.net/fedex-clone"
```

- [ ] MongoDB URI set

### Step 2: Set Email User
```bash
firebase functions:config:set email.user="your_email@gmail.com"
```

**Note:** Use the Gmail address you have an app password for

- [ ] Email user set

### Step 3: Set Email Password
```bash
firebase functions:config:set email.pass="your_app_password"
```

**Get app password from:** https://myaccount.google.com/apppasswords

- [ ] Email password set

### Step 4: Set Base URL
```bash
firebase functions:config:set base.url="https://fedex-37e89.web.app"
```

- [ ] Base URL set

### Step 5: Set CORS Origins
```bash
firebase functions:config:set cors.origins="https://fedex-37e89.web.app"
```

- [ ] CORS origins set

### Step 6: Verify All Settings
```bash
firebase functions:config:get
```

You should see all the values you just set:
- [ ] mongo.uri ✓
- [ ] email.user ✓
- [ ] email.pass ✓
- [ ] base.url ✓
- [ ] cors.origins ✓

---

## 🧪 Phase 6: Local Testing

### Step 1: Install Backend Dependencies
```bash
cd backend
npm install
cd ..
```

- [ ] Dependencies installed without errors

### Step 2: Test Backend Locally
```bash
cd backend
npm start
```

Expected output: `Backend server running on http://localhost:5002`

- [ ] Server starts without errors
- [ ] No MongoDB connection errors (or graceful fallback)

### Step 3: Test Health Endpoint (in another terminal)
```bash
curl http://localhost:5002/health
```

Expected response:
```json
{"status":"ok","database":"connected|disconnected","timestamp":"..."}
```

- [ ] Health endpoint responds
- [ ] Status is "ok"

### Step 4: Test API
```bash
curl http://localhost:5002/api/track/123456789012
```

- [ ] API endpoint responds
- [ ] Returns tracking data or 200 status

### Step 5: Stop Local Server
```bash
# In the terminal running the server, press Ctrl+C
```

- [ ] Server stopped cleanly

---

## 📦 Phase 7: Deploy to Firebase

### Step 1: Verify Project Structure
```bash
ls -la
```

Should show:
- [ ] backend/ directory
- [ ] frontend/ directory
- [ ] firebase.json
- [ ] .firebaserc

### Step 2: Install Backend Dependencies (Final Check)
```bash
cd backend
npm install
cd ..
```

- [ ] All dependencies installed

### Step 3: Build Backend
```bash
cd backend
npm run build  # if you have a build script
cd ..
```

- [ ] Build succeeds (or skip if no build script)

### Step 4: Deploy Everything
```bash
firebase deploy
```

This will deploy:
- Frontend (to Firebase Hosting)
- Backend (as Cloud Functions)

Wait for the deployment to complete. You should see:
```
✔ Deploy complete!

Project Console: https://console.firebase.google.com/project/fedex-37e89
Hosting URL: https://fedex-37e89.web.app
Function URL: https://fedex-37e89.cloudfunctions.net/api
```

- [ ] Deployment completes without errors
- [ ] See the success message
- [ ] Hosting URL provided
- [ ] Function URL provided

---

## ✅ Phase 8: Verify Live Deployment

### Step 1: Test Frontend
```bash
curl https://fedex-37e89.web.app
```

Should return HTML content.

- [ ] Frontend loads
- [ ] Gets HTML response

### Step 2: Test Health Endpoint
```bash
curl https://fedex-37e89.cloudfunctions.net/api/health
```

Expected:
```json
{"status":"ok","database":"connected","timestamp":"..."}
```

- [ ] Health check responds
- [ ] Database status shows

### Step 3: Test Tracking API
```bash
curl "https://fedex-37e89.cloudfunctions.net/api/track/123456789012"
```

Should return tracking data.

- [ ] Tracking endpoint works
- [ ] Returns shipment data

### Step 4: Open in Browser
Visit: https://fedex-37e89.web.app

- [ ] Website loads
- [ ] No console errors (F12 → Console)
- [ ] Can see the FedEx interface

### Step 5: Test Tracking in UI
1. Go to tracking section
2. Enter "123456789012"
3. Click Track

- [ ] Tracking works
- [ ] Shows shipment details
- [ ] Map loads

### Step 6: Test Authentication
1. Click "Sign Up"
2. Create a test account (or use existing)
3. Verify email (if required)

- [ ] Can create account
- [ ] Authentication works
- [ ] Can log in

### Step 7: Check Firebase Logs
```bash
firebase functions:log --limit 20
```

Look for:
- [ ] No error messages
- [ ] Successful function calls logged

---

## 📊 Phase 9: Monitoring

### View Deployment Status
```bash
firebase deploy status
```

- [ ] Shows recent deployment
- [ ] All services deployed

### View Function Logs
```bash
firebase functions:log
```

- [ ] Shows recent function activity
- [ ] Check for any errors

### View in Firebase Console
Go to: https://console.firebase.google.com/project/fedex-37e89

Check:
- [ ] Build → Hosting shows your site
- [ ] Build → Functions shows 'api' function
- [ ] Function shows recent invocations
- [ ] No error spikes

---

## 🐛 Phase 10: Troubleshooting (If Needed)

### If Deployment Failed:

**Check error message**
```bash
firebase deploy --debug
```

- [ ] Read error output
- [ ] Check MongoDB URI format
- [ ] Verify all environment variables set

**Redeploy Functions Only:**
```bash
firebase deploy --only functions
```

**Redeploy Hosting Only:**
```bash
firebase deploy --only hosting
```

### If Frontend Shows Errors:

1. Open https://fedex-37e89.web.app
2. Press F12 to open developer tools
3. Check Console tab for errors

If you see API errors:
- [ ] Check if API URL is correct
- [ ] Verify Functions are deployed
- [ ] Check Firebase logs

### If API Doesn't Work:

Test the endpoint directly:
```bash
curl -v https://fedex-37e89.cloudfunctions.net/api/health
```

- [ ] Returns 200 status
- [ ] Returns JSON response
- [ ] No CORS errors in console

---

## 🎉 Success Indicators

Your deployment is successful when:

- [ ] Website loads at https://fedex-37e89.web.app
- [ ] No browser console errors
- [ ] Tracking API works
- [ ] Can create account / login
- [ ] Firebase logs show successful requests
- [ ] Health check returns "ok"
- [ ] API responds from Cloud Functions
- [ ] No emails/auth errors in logs

---

## 📚 Quick Reference

| Task | Command |
|------|---------|
| Login | `firebase login` |
| Set Project | `firebase use fedex-37e89` |
| Set Env Vars | `firebase functions:config:set key.value="value"` |
| Deploy All | `firebase deploy` |
| Deploy Functions | `firebase deploy --only functions` |
| Deploy Hosting | `firebase deploy --only hosting` |
| View Logs | `firebase functions:log` |
| Check Status | `firebase deploy status` |
| Open Console | `firebase open console` |

---

## 🆘 Getting Help

**If you get stuck:**

1. Check **[FIREBASE_DEPLOYMENT.md](./FIREBASE_DEPLOYMENT.md)** for detailed explanations
2. Check function logs: `firebase functions:log`
3. Check Firebase Console: https://console.firebase.google.com/project/fedex-37e89
4. Visit Firebase Docs: https://firebase.google.com/docs

---

## 🏁 Done!

Once all phases are complete, your FedEx Clone is live on Firebase! 🎉

Visit: https://fedex-37e89.web.app

Admin: https://fedex-37e89.web.app (with admin account)

---

**Created:** March 2026
**Status:** ✅ Ready for Deployment
