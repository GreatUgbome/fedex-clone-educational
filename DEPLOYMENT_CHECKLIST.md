# 🚀 FedEx Clone - Deployment Checklist

Complete this checklist step-by-step to get your project deployed online.

## Phase 1: Local Setup & Testing

- [ ] **MongoDB Setup**
  - [ ] Create MongoDB Atlas account at https://www.mongodb.com/cloud/atlas
  - [ ] Create new cluster (free tier)
  - [ ] Create database user with password
  - [ ] Get connection string
  - [ ] Update `backend/.env` with `MONGO_URI`
  - [ ] Test connection locally

- [ ] **Email Configuration**
  - [ ] Enable 2-step verification on Google account
  - [ ] Go to https://myaccount.google.com/apppasswords
  - [ ] Generate app-specific password
  - [ ] Update `backend/.env` with:
    - `EMAIL_USER=your_email@gmail.com`
    - `EMAIL_PASS=the_16_char_password`

- [ ] **Backend Setup**
  ```bash
  cd backend
  npm install
  npm start
  ```
  - [ ] Server starts on http://localhost:5002
  - [ ] Health endpoint works: `curl http://localhost:5002/health`
  - [ ] Database connects: `"database": "connected"`

- [ ] **Frontend Testing**
  - [ ] Open http://localhost:5002 in browser
  - [ ] Can navigate pages
  - [ ] Can see tracking form
  - [ ] Can open login modal

## Phase 2: GitHub Setup

- [ ] **Push to GitHub**
  ```bash
  cd /path/to/fedex-clone-educational
  git add .
  git commit -m "Prepare for deployment"
  git push origin main
  ```
  - [ ] All changes pushed
  - [ ] No uncommitted files

- [ ] **Update in Git**
  - [ ] backend/.env added to .gitignore
  - [ ] node_modules in .gitignore (should be)
  - [ ] Verify no secrets in repo: `git log -p | grep -i password`

## Phase 3: Render Deployment

- [ ] **Create Render Account**
  - [ ] Sign up at https://render.com
  - [ ] Connect GitHub account
  - [ ] Authorize repository access

- [ ] **Create Backend Service**
  - [ ] Go to Dashboard → New Web Service
  - [ ] Connect GitHub repo (fedex-clone-educational)
  - [ ] Configure:
    - **Name:** `fedex-clone-api` (or your choice)
    - **Environment:** Node
    - **Region:** Choose nearest to you
    - **Branch:** main
    - **Build Command:** `cd backend && npm install`
    - **Start Command:** `cd backend && npm start`
    - **Plan:** Free tier recommended
  - [ ] Create Web Service

- [ ] **Set Environment Variables in Render**
  - Go to your service → Environment
  - [ ] Add `MONGO_URI`
  - [ ] Add `EMAIL_USER`
  - [ ] Add `EMAIL_PASS`
  - [ ] Add `BASE_URL=https://your-service-name.onrender.com`
  - [ ] Add `PORT=5002`
  - [ ] Add `NODE_ENV=production`
  - [ ] Add `ALLOWED_ORIGINS=https://your-service-name.onrender.com`
  - [ ] Save

- [ ] **First Deployment**
  - [ ] Go to Deployments tab
  - [ ] Click "Manual Deploy"
  - [ ] Wait for deployment to complete (5-10 minutes)
  - [ ] Check logs for errors

## Phase 4: Verify Deployment

- [ ] **Test Backend**
  - [ ] Visit `https://your-service-name.onrender.com/health`
  - [ ] Should see: `{"status":"ok","database":"connected"}`

- [ ] **Test API**
  - [ ] Try tracking endpoint:
    ```
    https://your-service-name.onrender.com/api/track/123456789012
    ```
  - [ ] Should return shipment data

- [ ] **Test Frontend**
  - [ ] Visit `https://your-service-name.onrender.com`
  - [ ] Can see full website
  - [ ] Tracking form works
  - [ ] Can open login modal

## Phase 5: Frontend Configuration

- [ ] **Update Frontend URLs (if needed)**
  - Edit `frontend/script.js`
  - Edit `frontend/auth.js`
  - Change API_BASE_URL to your Render service URL
  - Most URLs auto-detect now, but verify:
    ```bash
    curl https://your-service-name.onrender.com
    # Should load HTML
    ```

- [ ] **Test Full Features**
  - [ ] Login/Sign up works
  - [ ] Can view sample shipments
  - [ ] Tracking by ID works
  - [ ] Map displays
  - [ ] Email notifications work

## Phase 6: Final Verification

- [ ] **Health & Performance**
  - [ ] Response time < 2 seconds
  - [ ] No database errors in logs
  - [ ] CORS working (no browser errors)
  - [ ] All assets loading

- [ ] **Security Check**
  - [ ] No credentials visible in logs
  - [ ] HTTPS enforced
  - [ ] Rate limiting active
  - [ ] CORS properly configured

- [ ] **Functionality Check**
  - [ ] User can sign up
  - [ ] User can log in
  - [ ] User can verify email
  - [ ] User can reset password
  - [ ] User can track packages
  - [ ] Admin can access dashboard
  - [ ] Admin can manage shipments

## Phase 7: Optional Enhancements

- [ ] **Frontend Domain (Optional)**
  - If you want custom domain for frontend, use Render's custom domains feature
  - Add CNAME record from your domain registrar

- [ ] **Database Backups**
  - [ ] Enable MongoDB Atlas automatic backups
  - [ ] Test restore process

- [ ] **Monitoring (Optional)**
  - [ ] Set up error alerts in Render
  - [ ] Set up performance monitoring
  - [ ] Check logs regularly

- [ ] **SSL Certificate**
  - [ ] Verify HTTPS certificate is valid
  - [ ] Test in browser

## Phase 8: Maintenance

- [ ] **Scheduled Tasks**
  - [ ] Weekly: Check Render logs
  - [ ] Monthly: Review MongoDB usage
  - [ ] Monthly: Check for npm updates
  - [ ] Quarterly: Security audit

- [ ] **Update Dependencies (if needed)**
  ```bash
  cd backend
  npm update
  npm audit
  npm audit fix
  ```

- [ ] **Backup Important Data**
  - [ ] MongoDB data
  - [ ] Environment variables (save securely)
  - [ ] Source code (already in GitHub)

## Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| Database won't connect | Check MONGO_URI in Render environment |
| 502 Bad Gateway | Check server logs, restart service |
| Frontend not loading | Check ALLOWED_ORIGINS |
| CORS errors | Add frontend domain to ALLOWED_ORIGINS |
| Email not sending | Verify EMAIL_USER and EMAIL_PASS |
| Long deployment | May be first build, subsequent are faster |

## Success Indicators ✅

When you see these, you're done:

1. ✅ Render service is "Live" (green status)
2. ✅ Health endpoint returns success
3. ✅ Frontend loads in browser
4. ✅ Can click around without 404s
5. ✅ Database is connected
6. ✅ API endpoints respond correctly
7. ✅ No errors in Render logs
8. ✅ HTTPS working (padlock in browser)

## Your Deployed URLs

Once deployed, save these URLs:

- **Backend/Frontend:** https://your-service-name.onrender.com
- **Health Check:** https://your-service-name.onrender.com/health
- **API Base:** https://your-service-name.onrender.com/api

## Next Steps

1. **Share your app:** Send the URL to friends/colleagues
2. **Create admin account:** Sign up with admin@fedex.com email
3. **Add shipments:** Use admin dashboard
4. **Monitor performance:** Check Render logs weekly
5. **Plan improvements:** Add features, optimize, scale

## Documentation References

- [Full README](./README_FULL.md)
- [Deployment Guide](./DEPLOYMENT_GUIDE.md)
- [Render Docs](https://docs.render.com)
- [MongoDB Atlas Docs](https://docs.cloud.mongodb.com)

---

**You've got this! 🚀 Happy deploying!**

*Last updated: March 2026*
