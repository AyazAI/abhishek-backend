# VaultPass Authentication API

A comprehensive, production-ready authentication API built with Node.js, Express, TypeScript, and MongoDB. Features advanced security measures, two-factor authentication, device management, and real-time security monitoring.

## 🚀 Features

### Core Authentication

- ✅ **User Registration** - Email/username based signup with password validation
- ✅ **Secure Login** - JWT-based authentication with refresh tokens
- ✅ **Email Verification** - Complete email verification flow with resend capability
- ✅ **Password Management** - Forgot password, reset password, and change password flows
- ✅ **Token Refresh** - Automatic token refresh system for extended sessions

### Advanced Security Features

- 🔐 **Two-Factor Authentication (2FA)** - TOTP-based 2FA with QR code generation
- 🔑 **Backup Codes** - One-time backup codes for 2FA recovery
- 📱 **Device Management** - Track and manage logged-in devices
- 🔄 **Session Management** - View and revoke active sessions
- 🛡️ **Brute Force Protection** - Account lockout after failed login attempts
- 📊 **Security Activity Logs** - Comprehensive activity tracking and monitoring
- 🚨 **Suspicious Activity Detection** - AI-powered detection of unusual login patterns
- 📍 **IP Geolocation** - Track login locations (optional integration)
- 🔒 **Password Strength Meter** - Real-time password strength validation
- ⚡ **Rate Limiting** - Protection against DDoS and brute force attacks
- 🛡️ **Security Headers** - Helmet.js for enhanced security
- 🧹 **Input Sanitization** - Protection against NoSQL injection attacks

### Unique Features

- 🎯 **Smart Security Alerts** - Email notifications for suspicious activities
- 📈 **Security Dashboard** - Activity summaries and statistics
- 🌍 **Location Tracking** - Optional IP geolocation for login tracking
- 🔍 **Device Fingerprinting** - Automatic device identification and tracking
- ⏰ **Activity History** - Complete audit trail of all security events
- 🔐 **Role-Based Access Control (RBAC)** - Admin, moderator, and user roles

## 📋 Prerequisites

- Node.js (v18 or higher)
- MongoDB (v5 or higher)
- npm or yarn

## 🛠️ Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd VaultPass
   ```

2. **Install dependencies**

   ```bash
   npm install
   ```

3. **Set up environment variables**
   Create a `.env` file in the root directory:

   ```env
   NODE_ENV=development
   PORT=5000
   FRONTEND_URL=http://localhost:3000

   #Add MONGODB URI HERE!
   # https://www.mongodb.com/
   MONGODB_URI=mongodb://localhost:27017/vaultpass

   JWT_SECRET=your-super-secret-jwt-access-token-key
   JWT_REFRESH_SECRET=your-super-secret-jwt-refresh-token-key
   JWT_ACCESS_EXPIRY=15m
   JWT_REFRESH_EXPIRY=7d

   BCRYPT_ROUNDS=12
   MAX_LOGIN_ATTEMPTS=5
   LOCKOUT_TIME=30

   #ADD EMAIL CREDENTIALS HERE

    #You can get email password
    #Go to https://myaccount.google.com/
    #Sign in → Security
    #Turn on 2-Step Verification
    #After it's enabled → Go to App passwords
    #Select “Mail” → “Other” (or any) → Generate
    #Copy the 16-character password → this is your EMAIL_PASS

   EMAIL_HOST=smtp.gmail.com
   EMAIL_PORT=587
   EMAIL_USER=your-email@gmail.com
   EMAIL_PASS=your-app-specific-password
   EMAIL_FROM=VaultPass <noreply@vaultpass.com>

   RATE_LIMIT_WINDOW_MS=900000
   RATE_LIMIT_MAX_REQUESTS=100
   ```

4. **Build the project**

   ```bash
   npm run build
   ```

5. **Start the server**

   ```bash
   # Development mode
   npm run dev

   # Production mode
   npm start
   ```

## 📚 API Documentation

### Authentication Endpoints

#### Register User

```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "username": "johndoe", // optional
  "firstName": "John", // optional
  "lastName": "Doe" // optional
}
```

#### Login

```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "twoFactorToken": "123456" // required if 2FA is enabled
}
```

#### Refresh Token

```http
POST /api/auth/refresh-token
Content-Type: application/json

{
  "refreshToken": "your-refresh-token"
}
```

#### Logout

```http
POST /api/auth/logout
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "refreshToken": "your-refresh-token" // optional, logs out specific session
}
```

### Email Verification

#### Verify Email

```http
GET /api/auth/verify-email?token=<verification-token>
```

#### Resend Verification Email

```http
POST /api/auth/resend-verification
Content-Type: application/json

{
  "email": "user@example.com"
}
```

#### Check Verification Status

```http
GET /api/auth/verification-status
Authorization: Bearer <access-token>
```

### Password Management

#### Forgot Password

```http
POST /api/auth/forgot-password
Content-Type: application/json

{
  "email": "user@example.com"
}
```

#### Reset Password

```http
POST /api/auth/reset-password
Content-Type: application/json

{
  "token": "<reset-token>",
  "password": "NewSecurePass123!"
}
```

#### Change Password

```http
POST /api/auth/change-password
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "currentPassword": "OldPass123!",
  "newPassword": "NewSecurePass123!"
}
```

#### Check Password Strength

```http
POST /api/auth/check-password
Content-Type: application/json

{
  "password": "MyPassword123!"
}
```

### User Profile

#### Get Profile

```http
GET /api/auth/profile
Authorization: Bearer <access-token>
```

#### Update Profile

```http
PUT /api/auth/profile
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "firstName": "John",
  "lastName": "Doe",
  "username": "johndoe"
}
```

### Two-Factor Authentication

#### Setup 2FA

```http
POST /api/auth/2fa/setup
Authorization: Bearer <access-token>
```

#### Verify and Enable 2FA

```http
POST /api/auth/2fa/verify
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "token": "123456"
}
```

#### Disable 2FA

```http
POST /api/auth/2fa/disable
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "password": "YourPassword123!",
  "token": "123456"
}
```

#### Get 2FA Status

```http
GET /api/auth/2fa/status
Authorization: Bearer <access-token>
```

#### Regenerate Backup Codes

```http
POST /api/auth/2fa/regenerate-backup-codes
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "password": "YourPassword123!"
}
```

### Device Management

#### Get All Devices

```http
GET /api/auth/devices
Authorization: Bearer <access-token>
```

#### Trust Device

```http
POST /api/auth/devices/:deviceId/trust
Authorization: Bearer <access-token>
```

#### Revoke Device

```http
DELETE /api/auth/devices/:deviceId
Authorization: Bearer <access-token>
```

#### Revoke All Devices

```http
DELETE /api/auth/devices
Authorization: Bearer <access-token>
```

### Session Management

#### Get All Sessions

```http
GET /api/auth/sessions
Authorization: Bearer <access-token>
```

#### Revoke Session

```http
DELETE /api/auth/sessions/:sessionId
Authorization: Bearer <access-token>
```

#### Revoke All Sessions

```http
DELETE /api/auth/sessions
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "currentRefreshToken": "your-current-refresh-token"
}
```

### Security & Activity

#### Get Activity Logs

```http
GET /api/auth/security/activity?page=1&limit=20
Authorization: Bearer <access-token>
```

#### Get Security Summary

```http
GET /api/auth/security/summary
Authorization: Bearer <access-token>
```

## 🔒 Security Features

### Password Requirements

- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- Optional: Special characters for stronger passwords

### Rate Limiting

- **General API**: 100 requests per 15 minutes
- **Authentication**: 5 attempts per 15 minutes
- **Password Reset**: 3 attempts per hour
- **Email Verification**: 5 attempts per hour

### Account Lockout

- Account locked after 5 failed login attempts
- Lockout duration: 30 minutes (configurable)
- Automatic unlock after lockout period

### Security Logging

All security events are logged including:

- Login attempts (success/failure)
- Password changes
- Email verifications
- 2FA enable/disable
- Session creation/revocation
- Suspicious activity detection

## 🧪 Testing

```bash
npm test
```

## 📦 Project Structure

```
src/
├── config/          # Database configuration
├── controllers/     # Route controllers
├── middleware/      # Express middleware
├── models/          # Mongoose models
├── routes/          # API routes
├── utils/           # Utility functions
└── server.ts        # Express app entry point
```

## 🚀 Deployment

1. Set `NODE_ENV=production` in your environment variables
2. Use a production MongoDB instance (MongoDB Atlas recommended)
3. Configure proper CORS origins
4. Use strong JWT secrets
5. Set up proper email service (SendGrid, AWS SES, etc.)
6. Enable HTTPS
7. Set up monitoring and logging

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

ISC

## 🙏 Acknowledgments

- Express.js
- MongoDB & Mongoose
- JWT (jsonwebtoken)
- Speakeasy (2FA)
- Nodemailer

---
