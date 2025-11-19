import express from "express";
import {
  login,
  logout,
  refreshToken,
  register,
} from "../controllers/authController";
import {
  getDevices,
  revokeAllDevices,
  revokeDevice,
  trustDevice,
} from "../controllers/deviceController";
import {
  changePassword,
  checkPassword,
  forgotPassword,
  resetPassword,
} from "../controllers/passwordController";
import { getProfile, updateProfile } from "../controllers/profileController";
import {
  getActivityLogs,
  getSecuritySummary,
} from "../controllers/securityController";
import {
  getSessions,
  revokeAllSessions,
  revokeSession,
} from "../controllers/sessionController";
import {
  disable2FA,
  get2FAStatus,
  regenerateBackupCodes,
  setup2FA,
  verify2FA,
} from "../controllers/twoFactorController";
import {
  checkVerificationStatus,
  resendVerificationEmail,
  verifyEmail,
} from "../controllers/verificationController";
import { authenticate, authorize } from "../middleware/auth";
import {
  apiLimiter,
  authLimiter,
  emailVerificationLimiter,
  passwordResetLimiter,
} from "../middleware/rateLimiter";
import {
  changePasswordValidation,
  forgotPasswordValidation,
  loginValidation,
  registerValidation,
  resetPasswordValidation,
  updateProfileValidation,
  validate,
  verify2FAValidation,
} from "../middleware/validation";

const router = express.Router();

// Public routes
// Authentication
router.post("/register", apiLimiter, registerValidation, validate, register);
router.post("/login", authLimiter, loginValidation, validate, login);
router.post("/refresh-token", apiLimiter, refreshToken);
router.post("/logout", apiLimiter, logout);

// Email verification
router.get("/verify-email", emailVerificationLimiter, verifyEmail);
router.post(
  "/resend-verification",
  emailVerificationLimiter,
  resendVerificationEmail
);

// Password management
router.post(
  "/forgot-password",
  passwordResetLimiter,
  forgotPasswordValidation,
  validate,
  forgotPassword
);
router.post(
  "/reset-password",
  passwordResetLimiter,
  resetPasswordValidation,
  validate,
  resetPassword
);
router.post("/check-password", apiLimiter, checkPassword);

// Protected routes (require authentication)
router.use(authenticate);

// User profile
router.get("/profile", getProfile);
router.put("/profile", updateProfileValidation, validate, updateProfile);

// Email verification status
router.get("/verification-status", checkVerificationStatus);

// Password management
router.post(
  "/change-password",
  changePasswordValidation,
  validate,
  changePassword
);

// Two-factor authentication
router.get("/2fa/status", get2FAStatus);
router.post("/2fa/setup", setup2FA);
router.post("/2fa/verify", verify2FAValidation, validate, verify2FA);
router.post("/2fa/disable", verify2FAValidation, validate, disable2FA);
router.post("/2fa/regenerate-backup-codes", regenerateBackupCodes);

// Device management
router.get("/devices", getDevices);
router.post("/devices/:deviceId/trust", trustDevice);
router.delete("/devices/:deviceId", revokeDevice);
router.delete("/devices", revokeAllDevices);

// Session management
router.get("/sessions", getSessions);
router.delete("/sessions/:sessionId", revokeSession);
router.delete("/sessions", revokeAllSessions);

// Security & Activity
router.get("/security/activity", getActivityLogs);
router.get("/security/summary", getSecuritySummary);

// Admin routes (require admin role)
router.get("/admin/users", authorize("admin", "moderator"), (req, res) => {
  res.status(200).json({
    success: true,
    message: "Admin endpoint - implement user management here",
  });
});

export default router;
