import { Request, Response } from 'express';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import User from '../models/User';
import { logSecurityEvent } from '../middleware/auth';
import { sendSecurityAlertEmail } from '../utils/email';
import { parseDeviceInfo } from '../utils/deviceParser';
import crypto from 'crypto';

// Generate 2FA secret and QR code
export const setup2FA = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?._id;

    if (!userId) {
      res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
      return;
    }

    const user = await User.findById(userId).select('+twoFactorSecret');
    if (!user) {
      res.status(404).json({
        success: false,
        message: 'User not found',
      });
      return;
    }

    if (user.twoFactorEnabled) {
      res.status(400).json({
        success: false,
        message: 'Two-factor authentication is already enabled',
      });
      return;
    }

    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `VaultPass (${user.email})`,
      issuer: 'VaultPass',
      length: 32,
    });

    // Generate backup codes
    const backupCodes = Array.from({ length: 10 }, () =>
      crypto.randomBytes(4).toString('hex').toUpperCase()
    );

    // Store secret and backup codes temporarily (not enabled yet)
    user.twoFactorSecret = secret.base32;
    user.backupCodes = backupCodes;
    await user.save();

    // Generate QR code
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url!);

    res.status(200).json({
      success: true,
      message: '2FA setup initiated. Scan QR code and verify with a code.',
      data: {
        secret: secret.base32,
        qrCode: qrCodeUrl,
        backupCodes, // Show only once during setup
        manualEntryKey: secret.base32,
      },
    });
  } catch (error: any) {
    console.error('Setup 2FA error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to setup two-factor authentication',
    });
  }
};

// Verify and enable 2FA
export const verify2FA = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?._id;
    const { token } = req.body;

    if (!userId) {
      res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
      return;
    }

    const user = await User.findById(userId).select('+twoFactorSecret +backupCodes');
    if (!user) {
      res.status(404).json({
        success: false,
        message: 'User not found',
      });
      return;
    }

    if (!user.twoFactorSecret) {
      res.status(400).json({
        success: false,
        message: '2FA setup not initiated. Please setup 2FA first.',
      });
      return;
    }

    if (user.twoFactorEnabled) {
      res.status(400).json({
        success: false,
        message: 'Two-factor authentication is already enabled',
      });
      return;
    }

    // Verify token
    const isValidToken = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token,
      window: 2,
    });

    if (!isValidToken) {
      res.status(400).json({
        success: false,
        message: 'Invalid verification code',
      });
      return;
    }

    // Enable 2FA
    user.twoFactorEnabled = true;
    await user.save();

    // Send security alert
    const deviceInfo = parseDeviceInfo(req);
    try {
      await sendSecurityAlertEmail(
        user.email,
        '2FA Enabled',
        'Two-factor authentication has been enabled on your account.',
        deviceInfo.ipAddress,
        user.firstName
      );
    } catch (emailError) {
      console.error('Error sending security alert:', emailError);
    }

    await logSecurityEvent(
      userId,
      user.email,
      '2fa_enabled',
      req,
      'success',
      'Two-factor authentication enabled'
    );

    res.status(200).json({
      success: true,
      message: 'Two-factor authentication enabled successfully',
      data: {
        backupCodes: user.backupCodes, // Return backup codes one more time
      },
    });
  } catch (error: any) {
    console.error('Verify 2FA error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to verify two-factor authentication',
    });
  }
};

// Disable 2FA
export const disable2FA = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?._id;
    const { password, token } = req.body;

    if (!userId) {
      res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
      return;
    }

    const user = await User.findById(userId).select('+password +twoFactorSecret');
    if (!user) {
      res.status(404).json({
        success: false,
        message: 'User not found',
      });
      return;
    }

    if (!user.twoFactorEnabled) {
      res.status(400).json({
        success: false,
        message: 'Two-factor authentication is not enabled',
      });
      return;
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      res.status(401).json({
        success: false,
        message: 'Invalid password',
      });
      return;
    }

    // Verify 2FA token
    const isValidToken = speakeasy.totp.verify({
      secret: user.twoFactorSecret!,
      encoding: 'base32',
      token,
      window: 2,
    });

    if (!isValidToken) {
      res.status(401).json({
        success: false,
        message: 'Invalid 2FA code',
      });
      return;
    }

    // Disable 2FA
    user.twoFactorEnabled = false;
    user.twoFactorSecret = undefined;
    user.backupCodes = undefined;
    await user.save();

    // Send security alert
    const deviceInfo = parseDeviceInfo(req);
    try {
      await sendSecurityAlertEmail(
        user.email,
        '2FA Disabled',
        'Two-factor authentication has been disabled on your account. If you did not make this change, please contact support immediately.',
        deviceInfo.ipAddress,
        user.firstName
      );
    } catch (emailError) {
      console.error('Error sending security alert:', emailError);
    }

    await logSecurityEvent(
      userId,
      user.email,
      '2fa_disabled',
      req,
      'success',
      'Two-factor authentication disabled'
    );

    res.status(200).json({
      success: true,
      message: 'Two-factor authentication disabled successfully',
    });
  } catch (error: any) {
    console.error('Disable 2FA error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to disable two-factor authentication',
    });
  }
};

// Get 2FA status
export const get2FAStatus = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?._id;

    if (!userId) {
      res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
      return;
    }

    const user = await User.findById(userId);
    if (!user) {
      res.status(404).json({
        success: false,
        message: 'User not found',
      });
      return;
    }

    res.status(200).json({
      success: true,
      data: {
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error: any) {
    console.error('Get 2FA status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get 2FA status',
    });
  }
};

// Regenerate backup codes
export const regenerateBackupCodes = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const userId = req.user?._id;
    const { password } = req.body;

    if (!userId) {
      res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
      return;
    }

    const user = await User.findById(userId).select('+password +backupCodes');
    if (!user) {
      res.status(404).json({
        success: false,
        message: 'User not found',
      });
      return;
    }

    if (!user.twoFactorEnabled) {
      res.status(400).json({
        success: false,
        message: 'Two-factor authentication is not enabled',
      });
      return;
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      res.status(401).json({
        success: false,
        message: 'Invalid password',
      });
      return;
    }

    // Generate new backup codes
    const backupCodes = Array.from({ length: 10 }, () =>
      crypto.randomBytes(4).toString('hex').toUpperCase()
    );

    user.backupCodes = backupCodes;
    await user.save();

    await logSecurityEvent(
      userId,
      user.email,
      '2fa_backup_codes_regenerated',
      req,
      'success',
      'Backup codes regenerated'
    );

    res.status(200).json({
      success: true,
      message: 'Backup codes regenerated successfully',
      data: {
        backupCodes,
      },
    });
  } catch (error: any) {
    console.error('Regenerate backup codes error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to regenerate backup codes',
    });
  }
};

