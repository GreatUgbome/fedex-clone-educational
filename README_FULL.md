# FedEx Clone - Educational Project 📦

A full-stack shipment tracking and management application built with Express.js, MongoDB, Firebase, and Vanilla JavaScript.

## 🎯 Project Overview

This is an educational FedEx clone application that demonstrates:
- Real-time package tracking
- User authentication (Firebase + Email/Password)
- Admin dashboard
- Shipment management
- Geographic visualization with maps
- Email notifications
- Responsive design with Tailwind CSS

## 📁 Project Structure

```
fedex-clone-educational/
├── backend/                 # Node.js/Express API
│   ├── controllers/        # Business logic
│   ├── models/             # MongoDB schemas
│   ├── routes/             # API endpoints
│   ├── middleware/         # Auth & utilities
│   ├── utils/              # Helper functions
│   ├── .env                # Environment variables
│   └── server.js           # Main server file
├── frontend/               # Vanilla JS + HTML/CSS
│   ├── index.html          # Main page
│   ├── script.js           # Frontend logic
│   ├── auth.js             # Authentication
│   └── style.css           # Styling
└── DEPLOYMENT_GUIDE.md     # Detailed deployment instructions
```

## ⚡ Quick Start

### Local Development

1. **Install dependencies:**
   ```bash
   cd backend
   npm install
   ```

2. **Configure environment variables:**
   Create `.env` file in `backend/`:
   ```env
   MONGO_URI=your_mongodb_connection_string
   PORT=5002
   BASE_URL=http://localhost:5002
   EMAIL_USER=your_email@gmail.com
   EMAIL_PASS=your_app_password
   ```

3. **Start the server:**
   ```bash
   npm start
   # or for development:
   npm run dev
   ```

4. **Open in browser:**
   - Frontend: http://localhost:5002
   - Health check: http://localhost:5002/health

### Using Setup Script (macOS/Linux)

```bash
chmod +x setup.sh
./setup.sh
```

## 🔧 Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `MONGO_URI` | Yes | MongoDB connection string |
| `PORT` | No | Server port (default: 5002) |
| `BASE_URL` | Yes | Application URL |
| `EMAIL_USER` | Yes | Gmail address for emails |
| `EMAIL_PASS` | Yes | Gmail app-specific password |
| `NODE_ENV` | No | development/production |
| `ALLOWED_ORIGINS` | No | CORS allowed origins |

### Getting Email Credentials

1. **Enable 2-step verification** on your Google account
2. Go to **App Passwords**: https://myaccount.google.com/apppasswords
3. Generate a password for "Mail" and "macOS" (or your device)
4. Use this 16-character password as `EMAIL_PASS`

### MongoDB Setup

**Option 1: MongoDB Atlas (Recommended)**
- Create free account at https://cloud.mongodb.com
- Create cluster and user
- Get connection string from "Connect" button

**Option 2: Local MongoDB**
- Install: `brew install mongodb-community` (macOS)
- Start: `brew services start mongodb-community`
- URI: `mongodb://localhost:27017/fedex-clone`

## 📦 API Endpoints

### Authentication
- `POST /api/signup` - Register new user
- `POST /api/login` - User login
- `POST /api/verify-email` - Verify email
- `POST /api/forgot-password` - Forgot password
- `POST /api/reset-password` - Reset password

### Tracking
- `GET /api/track/:id` - Get shipment details
- `GET /api/shipments` - List all shipments (admin only)
- `POST /api/shipment` - Create shipment (admin only)
- `PUT /api/shipment/:id` - Update shipment (admin only)
- `DELETE /api/shipment/:id` - Delete shipment (admin only)

### Settings
- `GET /api/settings` - Get system settings
- `PUT /api/settings` - Update settings (admin only)

### Other
- `GET /health` - Health check
- `POST /api/feedback` - Submit feedback
- `POST /api/pickup` - Schedule pickup

## 🔐 Authentication

The application supports two authentication methods:

1. **Firebase Authentication** (primary)
   - Google Sign-in
   - Email/Password through Firebase

2. **Local Authentication** (backup)
   - Username/Password authentication
   - Email verification required
   - Password reset via email

## 🎨 Features

### For Users
- ✅ Package tracking by ID
- ✅ Real-time status updates
- ✅ Map visualization
- ✅ Email notifications
- ✅ Print shipping labels
- ✅ Schedule pickups
- ✅ Track by reference number

### For Admins
- ✅ Dashboard with analytics
- ✅ Create/Edit/Delete shipments
- ✅ Manage users
- ✅ View audit logs
- ✅ System settings
- ✅ Maintenance mode
- ✅ Export data

## 🚀 Deployment

### Deploy to Render

See [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md) for detailed instructions.

**Quick steps:**
1. Push code to GitHub
2. Connect GitHub to Render
3. Set environment variables
4. Deploy

**Your API URL:** `https://your-service-name.onrender.com`

### Deploy Frontend

The frontend is served by the backend. Just deploy the backend to Render.

## 🧪 Testing

### Test Health Endpoint
```bash
curl http://localhost:5002/health
```

### Test Tracking
```bash
curl http://localhost:5002/api/track/123456789012
```

### Test Local Authentication
```bash
curl -X POST http://localhost:5002/api/signup \
  -H "Content-Type: application/json" \
  -d '{
    "username":"testuser",
    "email":"test@example.com",
    "password":"password123"
  }'
```

## 📊 Technologies Used

### Backend
- **Runtime:** Node.js
- **Framework:** Express.js
- **Database:** MongoDB + Mongoose
- **Authentication:** Firebase Admin SDK
- **Email:** Nodemailer
- **Validation:** Express Validator
- **Security:** bcrypt, rate-limiting

### Frontend
- **Markup:** HTML5
- **Styling:** Tailwind CSS
- **JavaScript:** Vanilla ES6+
- **Auth:** Firebase SDK
- **Maps:** Leaflet.js
- **Charts:** Chart.js
- **PDF Export:** html2pdf.js

## 🐛 Troubleshooting

### MongoDB Connection Failed
```
Error: MongoServerError: bad auth : authentication failed
```
**Solution:** Check MONGO_URI and credentials in .env

### Port Already in Use
```bash
# Kill process using port 5002
lsof -ti:5002 | xargs kill -9
```

### CORS Errors
```
Access to XMLHttpRequest blocked by CORS policy
```
**Solution:** Update ALLOWED_ORIGINS in .env to include your frontend URL

### Email Not Sending
- Verify EMAIL_USER and EMAIL_PASS are correct
- Check Gmail app-specific password setup
- Ensure less secure apps are not a factor (use app password)

## 📝 Important Notes

1. **Development Mode:**
   - Seeding includes sample shipments
   - Rate limiting is reduced
   - CORS allows localhost

2. **Production Mode:**
   - Update ALLOWED_ORIGINS
   - Use strong DATABASE passwords
   - Enable EMAIL authentication properly
   - Update BASE_URL to production URL
   - Consider using secure environment variable manager

3. **Security Considerations:**
   - Never commit .env file
   - Use environment variables for secrets
   - Implement HTTPS in production
   - Regularly update dependencies

## 🤝 Contributing

This is an educational project. Feel free to:
- Fork and modify
- Add new features
- Improve UI/UX
- Optimize backend

## 📚 Learning Resources

- MongoDB: https://docs.mongodb.com
- Express: https://expressjs.com
- Firebase: https://firebase.google.com/docs
- Tailwind CSS: https://tailwindcss.com/docs
- Leaflet Maps: https://leafletjs.com

## 📄 License

Educational Use Only

## 🆘 Support

For issues:
1. Check DEPLOYMENT_GUIDE.md
2. Review error logs
3. Verify .env configuration
4. Test endpoints with curl
5. Check Render logs if deployed

---

**Happy shipping!** 📦✈️
