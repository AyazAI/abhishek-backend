import { Request, Response } from 'express';
import crypto from 'crypto';
import mongoose from 'mongoose';
import User from '../models/User';
import Session from '../models/Session';
import Device from '../models/Device';
import { generateTokenPair, verifyRefreshToken } from '../utils/jwt';
import { sendVerificationEmail, sendSecurityAlertEmail } from '../utils/email';
import { parseDeviceInfo, generateDeviceId } from '../utils/deviceParser';
import { logSecurityEvent } from '../middleware/auth';
import { checkPasswordStrength } from '../utils/passwordStrength';
import { checkSuspiciousLogin } from '../utils/suspiciousActivity';
import { getLocationFromRequest } from '../utils/geolocation';

// Register new user
export const register = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password, username, firstName, lastName } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email: email.toLowerCase() }, ...(username ? [{ username }] : [])],
    });

    if (existingUser) {
      res.status(400).json({
        success: false,
        message: existingUser.email === email.toLowerCase() 
          ? 'Email already registered' 
          : 'Username already taken',
      });
      return;
    }

    // Check password strength
    const passwordStrength = checkPasswordStrength(password);
    if (passwordStrength.strength === 'weak') {
      res.status(400).json({
        success: false,
        message: 'Password is too weak',
        passwordStrength,
      });
      return;
    }

    // Generate email verification token
    const emailVerificationToken = crypto.randomBytes(32).toString('hex');
    const emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Create user
    const user = await User.create({
      email: email.toLowerCase(),
      password,
      username,
      firstName,
      lastName,
      emailVerificationToken,
      emailVerificationExpires,
    });

    // Send verification email
    try {
      await sendVerificationEmail(user.email, emailVerificationToken, user.firstName);
    } catch (emailError) {
      console.error('Error sending verification email:', emailError);
      // Don't fail registration if email fails
    }

    // Log security event
    await logSecurityEvent(
      String(user._id),
      user.email,
      'register',
      req,
      'success',
      'User registered successfully'
    );

    res.status(201).json({
      success: true,
      message: 'Registration successful. Please check your email to verify your account.',
      data: {
        userId: user._id,
        email: user.email,
        username: user.username,
        isEmailVerified: user.isEmailVerified,
      },
    });
  } catch (error: any) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Registration failed. Please try again.',
    });
  }
};

// Login user
export const login = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password, twoFactorToken } = req.body;
    const deviceInfo = parseDeviceInfo(req);

    // Find user with password field
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');

    if (!user) {
      await logSecurityEvent(
        undefined,
        email,
        'login',
        req,
        'failure',
        'User not found'
      );
      res.status(401).json({
        success: false,
        message: 'Invalid email or password',
      });
      return;
    }

    // Check if account is locked
    if (user.isAccountLocked()) {
      await logSecurityEvent(
        String(user._id),
        user.email,
        'login',
        req,
        'failure',
        'Account locked due to too many failed attempts'
      );
      res.status(403).json({
        success: false,
        message: 'Account is locked. Please try again later or reset your password.',
      });
      return;
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      await user.incrementLoginAttempts();
      await logSecurityEvent(
        String(user._id),
        user.email,
        'login',
        req,
        'failure',
        'Invalid password'
      );
      res.status(401).json({
        success: false,
        message: 'Invalid email or password',
      });
      return;
    }

    // Check 2FA if enabled
    if (user.twoFactorEnabled) {
      if (!twoFactorToken) {
        res.status(200).json({
          success: false,
          requires2FA: true,
          message: 'Two-factor authentication required',
        });
        return;
      }

      const speakeasy = require('speakeasy');
      const isValidToken = speakeasy.totp.verify({
        secret: user.twoFactorSecret!,
        encoding: 'base32',
        token: twoFactorToken,
        window: 2, // Allow 2 time steps (60 seconds) of tolerance
      });

      // Check backup codes if TOTP fails
      let backupCodeUsed = false;
      if (!isValidToken && user.backupCodes) {
        const codeIndex = user.backupCodes.findIndex(
          (code) => code === twoFactorToken
        );
        if (codeIndex !== -1) {
          backupCodeUsed = true;
          user.backupCodes.splice(codeIndex, 1);
          await user.save();
        }
      }

      if (!isValidToken && !backupCodeUsed) {
        await logSecurityEvent(
          String(user._id),
          user.email,
          'login',
          req,
          'failure',
          'Invalid 2FA token'
        );
        res.status(401).json({
          success: false,
          message: 'Invalid two-factor authentication code',
        });
        return;
      }
    }

    // Reset login attempts on successful login
    await user.resetLoginAttempts();

    // Update last login info
    user.lastLogin = new Date();
    user.lastLoginIP = deviceInfo.ipAddress;
    await user.save();

    // Check for suspicious activity
    const suspiciousCheck = await checkSuspiciousLogin(String(user._id), req);
    
    // Generate tokens
    const tokens = generateTokenPair(user);

    // Create or update device
    const deviceId = generateDeviceId(deviceInfo);
    await Device.findOneAndUpdate(
      { userId: user._id, deviceId },
      {
        userId: user._id,
        deviceId,
        deviceName: `${deviceInfo.browser} on ${deviceInfo.os}`,
        deviceType: deviceInfo.deviceType,
        browser: deviceInfo.browser,
        os: deviceInfo.os,
        ipAddress: deviceInfo.ipAddress,
        lastUsed: new Date(),
      },
      { upsert: true, new: true }
    );

    // Create session
    const sessionExpiry = new Date();
    sessionExpiry.setDate(sessionExpiry.getDate() + 7); // 7 days

    await Session.create({
      userId: user._id,
      refreshToken: tokens.refreshToken,
      deviceInfo,
      expiresAt: sessionExpiry,
    });

    // Log successful login
    await logSecurityEvent(
      String(user._id),
      user.email,
      'login',
      req,
      'success',
      'User logged in successfully'
    );

    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user._id,
          email: user.email,
          username: user.username,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          isEmailVerified: user.isEmailVerified,
          twoFactorEnabled: user.twoFactorEnabled,
          profilePicture: user.profilePicture,
        },
        tokens: {
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
        },
      },
    });
  } catch (error: any) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed. Please try again.',
    });
  }
};

// Refresh access token
export const refreshToken = async (req: Request, res: Response): Promise<void> => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      res.status(400).json({
        success: false,
        message: 'Refresh token is required',
      });
      return;
    }

    // Verify refresh token
    let decoded;
    try {
      decoded = verifyRefreshToken(refreshToken);
    } catch (error: any) {
      res.status(401).json({
        success: false,
        message: 'Invalid or expired refresh token',
      });
      return;
    }

    // Check if session exists and is active
    const session = await Session.findOne({
      refreshToken,
      isActive: true,
      expiresAt: { $gt: new Date() },
    });

    if (!session) {
      res.status(401).json({
        success: false,
        message: 'Session expired or invalid',
      });
      return;
    }

    // Get user
    const user = await User.findById(decoded.userId);
    if (!user) {
      res.status(401).json({
        success: false,
        message: 'User not found',
      });
      return;
    }

    // Check if account is locked
    if (user.isAccountLocked()) {
      res.status(403).json({
        success: false,
        message: 'Account is locked',
      });
      return;
    }

    // Generate new token pair
    const tokens = generateTokenPair(user);

    // Update session with new refresh token
    session.refreshToken = tokens.refreshToken;
    session.lastActivity = new Date();
    await session.save();

    res.status(200).json({
      success: true,
      data: {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      },
    });
  } catch (error: any) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      success: false,
      message: 'Token refresh failed',
    });
  }
};

// Logout user
export const logout = async (req: Request, res: Response): Promise<void> => {
  try {
    const { refreshToken } = req.body;
    const userId = req.user?._id;

    if (refreshToken) {
      // Deactivate specific session
      await Session.findOneAndUpdate(
        { refreshToken, userId },
        { isActive: false }
      );
    } else if (userId) {
      // Deactivate all sessions for user
      await Session.updateMany(
        { userId, isActive: true },
        { isActive: false }
      );
    }

    await logSecurityEvent(
      userId,
      req.user?.email,
      'logout',
      req,
      'success',
      'User logged out'
    );

    res.status(200).json({
      success: true,
      message: 'Logged out successfully',
    });
  } catch (error: any) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Logout failed',
    });
  }
};

