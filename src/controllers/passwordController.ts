import { Request, Response } from 'express';
import crypto from 'crypto';
import User from '../models/User';
import {
  sendPasswordResetEmail,
  sendPasswordChangedEmail,
  sendSecurityAlertEmail,
} from '../utils/email';
import { logSecurityEvent } from '../middleware/auth';
import { checkPasswordStrength } from '../utils/passwordStrength';
import { parseDeviceInfo } from '../utils/deviceParser';
import { checkSuspiciousPasswordChange } from '../utils/suspiciousActivity';

// Forgot password - send reset email
export const forgotPassword = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() });

    // Always return success to prevent email enumeration
    if (!user) {
      res.status(200).json({
        success: true,
        message: 'If the email exists, a password reset link has been sent.',
      });
      return;
    }

    // Generate reset token
    const passwordResetToken = crypto.randomBytes(32).toString('hex');
    const passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    user.passwordResetToken = passwordResetToken;
    user.passwordResetExpires = passwordResetExpires;
    await user.save();

    // Send reset email
    try {
      await sendPasswordResetEmail(user.email, passwordResetToken, user.firstName);
    } catch (emailError) {
      console.error('Error sending password reset email:', emailError);
      res.status(500).json({
        success: false,
        message: 'Failed to send password reset email',
      });
      return;
    }

    await logSecurityEvent(
      String(user._id),
      user.email,
      'password_reset',
      req,
      'success',
      'Password reset email sent'
    );

    res.status(200).json({
      success: true,
      message: 'If the email exists, a password reset link has been sent.',
    });
  } catch (error: any) {
    console.error('Forgot password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process password reset request',
    });
  }
};

// Reset password with token
export const resetPassword = async (req: Request, res: Response): Promise<void> => {
  try {
    const { token, password } = req.body;

    const user = await User.findOne({
      passwordResetToken: token,
      passwordResetExpires: { $gt: new Date() },
    }).select('+password');

    if (!user) {
      res.status(400).json({
        success: false,
        message: 'Invalid or expired reset token',
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

    // Check if new password is same as old
    const isSamePassword = await user.comparePassword(password);
    if (isSamePassword) {
      res.status(400).json({
        success: false,
        message: 'New password must be different from the current password',
      });
      return;
    }

    // Update password
    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.resetLoginAttempts(); // Reset lockout on password reset
    await user.save();

    // Send confirmation email
    try {
      await sendPasswordChangedEmail(user.email, user.firstName);
    } catch (emailError) {
      console.error('Error sending password changed email:', emailError);
    }

    // Send security alert
    const deviceInfo = parseDeviceInfo(req);
    try {
      await sendSecurityAlertEmail(
        user.email,
        'Password Reset',
        'Your password was successfully reset. If you did not make this change, please contact support immediately.',
        deviceInfo.ipAddress,
        user.firstName
      );
    } catch (emailError) {
      console.error('Error sending security alert:', emailError);
    }

    await logSecurityEvent(
      String(user._id),
      user.email,
      'password_reset',
      req,
      'success',
      'Password reset successfully'
    );

    res.status(200).json({
      success: true,
      message: 'Password reset successfully',
    });
  } catch (error: any) {
    console.error('Reset password error:', error);
    res.status(500).json({
      success: false,
      message: 'Password reset failed',
    });
  }
};

// Change password (requires authentication)
export const changePassword = async (req: Request, res: Response): Promise<void> => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user?._id;

    if (!userId) {
      res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
      return;
    }

    const user = await User.findById(userId).select('+password');
    if (!user) {
      res.status(404).json({
        success: false,
        message: 'User not found',
      });
      return;
    }

    // Verify current password
    const isPasswordValid = await user.comparePassword(currentPassword);
    if (!isPasswordValid) {
      await logSecurityEvent(
        userId,
        user.email,
        'password_change',
        req,
        'failure',
        'Invalid current password'
      );
      res.status(401).json({
        success: false,
        message: 'Current password is incorrect',
      });
      return;
    }

    // Check password strength
    const passwordStrength = checkPasswordStrength(newPassword);
    if (passwordStrength.strength === 'weak') {
      res.status(400).json({
        success: false,
        message: 'New password is too weak',
        passwordStrength,
      });
      return;
    }

    // Check if new password is same as old
    const isSamePassword = await user.comparePassword(newPassword);
    if (isSamePassword) {
      res.status(400).json({
        success: false,
        message: 'New password must be different from the current password',
      });
      return;
    }

    // Check for suspicious activity
    const suspiciousCheck = await checkSuspiciousPasswordChange(userId, req);

    // Update password
    user.password = newPassword;
    await user.save();

    // Send confirmation email
    try {
      await sendPasswordChangedEmail(user.email, user.firstName);
    } catch (emailError) {
      console.error('Error sending password changed email:', emailError);
    }

    // Send security alert
    const deviceInfo = parseDeviceInfo(req);
    try {
      await sendSecurityAlertEmail(
        user.email,
        'Password Changed',
        'Your password was successfully changed. If you did not make this change, please contact support immediately.',
        deviceInfo.ipAddress,
        user.firstName
      );
    } catch (emailError) {
      console.error('Error sending security alert:', emailError);
    }

    await logSecurityEvent(
      userId,
      user.email,
      'password_change',
      req,
      'success',
      'Password changed successfully'
    );

    res.status(200).json({
      success: true,
      message: 'Password changed successfully',
    });
  } catch (error: any) {
    console.error('Change password error:', error);
    res.status(500).json({
      success: false,
      message: 'Password change failed',
    });
  }
};

// Check password strength
export const checkPassword = async (req: Request, res: Response): Promise<void> => {
  try {
    const { password } = req.body;

    if (!password) {
      res.status(400).json({
        success: false,
        message: 'Password is required',
      });
      return;
    }

    const passwordStrength = checkPasswordStrength(password);

    res.status(200).json({
      success: true,
      data: passwordStrength,
    });
  } catch (error: any) {
    console.error('Check password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to check password strength',
    });
  }
};

