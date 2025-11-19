import { Request } from 'express';
import SecurityLog from '../models/SecurityLog';
import User from '../models/User';
import { parseDeviceInfo } from './deviceParser';
import { getLocationFromRequest } from './geolocation';
import { sendSecurityAlertEmail } from './email';

export interface SuspiciousActivityCheck {
  isSuspicious: boolean;
  reasons: string[];
  riskScore: number; // 0-100
}

// Check for suspicious login activity
export const checkSuspiciousLogin = async (
  userId: string,
  req: Request
): Promise<SuspiciousActivityCheck> => {
  const reasons: string[] = [];
  let riskScore = 0;

  try {
    const deviceInfo = parseDeviceInfo(req);
    const user = await User.findById(userId);

    if (!user) {
      return { isSuspicious: false, reasons: [], riskScore: 0 };
    }

    // Check recent failed login attempts
    const recentFailures = await SecurityLog.countDocuments({
      userId,
      action: 'login',
      status: 'failure',
      createdAt: { $gte: new Date(Date.now() - 15 * 60 * 1000) }, // Last 15 minutes
    });

    if (recentFailures >= 3) {
      reasons.push('Multiple failed login attempts in short time');
      riskScore += 30;
    }

    // Check for new IP address
    const recentSuccessfulLogins = await SecurityLog.find({
      userId,
      action: 'login',
      status: 'success',
      createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }, // Last 30 days
    }).sort({ createdAt: -1 }).limit(10);

    const knownIPs = new Set(
      recentSuccessfulLogins.map((log) => log.ipAddress)
    );

    if (!knownIPs.has(deviceInfo.ipAddress) && recentSuccessfulLogins.length > 0) {
      reasons.push('Login from new IP address');
      riskScore += 25;
    }

    // Check for new device/browser
    const knownUserAgents = new Set(
      recentSuccessfulLogins.map((log) => log.userAgent)
    );

    if (!knownUserAgents.has(deviceInfo.userAgent) && recentSuccessfulLogins.length > 0) {
      reasons.push('Login from new device or browser');
      riskScore += 20;
    }

    // Check for login from different country (if location data available)
    const location = await getLocationFromRequest(req);
    if (location?.country) {
      const recentCountries = new Set(
        recentSuccessfulLogins
          .filter((log) => log.location?.country)
          .map((log) => log.location!.country)
      );

      if (!recentCountries.has(location.country) && recentCountries.size > 0) {
        reasons.push(`Login from new country: ${location.country}`);
        riskScore += 30;
      }
    }

    // Check for login outside normal hours (if user has login history)
    if (recentSuccessfulLogins.length > 5) {
      const currentHour = new Date().getHours();
      const loginHours = recentSuccessfulLogins.map((log) => {
        const logDate = new Date(log.createdAt);
        return logDate.getHours();
      });

      const averageHour =
        loginHours.reduce((a, b) => a + b, 0) / loginHours.length;
      const hourDifference = Math.abs(currentHour - averageHour);

      if (hourDifference > 6) {
        reasons.push('Login outside normal hours');
        riskScore += 15;
      }
    }

    // Check if account was recently locked
    if (user.isLocked || user.lockUntil) {
      reasons.push('Account was recently locked');
      riskScore += 20;
    }

    const isSuspicious = riskScore >= 50;

    // Log suspicious activity
    if (isSuspicious) {
      await SecurityLog.create({
        userId,
        email: user.email,
        action: 'suspicious_activity',
        ipAddress: deviceInfo.ipAddress,
        userAgent: deviceInfo.userAgent,
        status: 'warning',
        details: `Suspicious login detected: ${reasons.join(', ')}`,
        location: location || undefined,
      });

      // Send security alert email
      try {
        await sendSecurityAlertEmail(
          user.email,
          'Suspicious Login Detected',
          `We detected a login attempt with the following suspicious characteristics: ${reasons.join(', ')}. If this was you, you can ignore this message. If not, please secure your account immediately.`,
          deviceInfo.ipAddress,
          user.firstName
        );
      } catch (emailError) {
        console.error('Error sending security alert:', emailError);
      }
    }

    return { isSuspicious, reasons, riskScore };
  } catch (error) {
    console.error('Error checking suspicious activity:', error);
    return { isSuspicious: false, reasons: [], riskScore: 0 };
  }
};

// Check for suspicious password change activity
export const checkSuspiciousPasswordChange = async (
  userId: string,
  req: Request
): Promise<SuspiciousActivityCheck> => {
  const reasons: string[] = [];
  let riskScore = 0;

  try {
    const deviceInfo = parseDeviceInfo(req);

    // Check if password change is from new IP
    const recentActivity = await SecurityLog.find({
      userId,
      action: { $in: ['login', 'password_change'] },
      status: 'success',
      createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }, // Last 7 days
    }).sort({ createdAt: -1 }).limit(5);

    const knownIPs = new Set(recentActivity.map((log) => log.ipAddress));

    if (!knownIPs.has(deviceInfo.ipAddress) && recentActivity.length > 0) {
      reasons.push('Password change from new IP address');
      riskScore += 40;
    }

    // Check if password was changed recently
    const recentPasswordChanges = await SecurityLog.countDocuments({
      userId,
      action: 'password_change',
      createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }, // Last 24 hours
    });

    if (recentPasswordChanges > 0) {
      reasons.push('Password changed multiple times recently');
      riskScore += 30;
    }

    const isSuspicious = riskScore >= 40;

    if (isSuspicious) {
      const user = await User.findById(userId);
      if (user) {
        await SecurityLog.create({
          userId,
          email: user.email,
          action: 'suspicious_activity',
          ipAddress: deviceInfo.ipAddress,
          userAgent: deviceInfo.userAgent,
          status: 'warning',
          details: `Suspicious password change: ${reasons.join(', ')}`,
        });
      }
    }

    return { isSuspicious, reasons, riskScore };
  } catch (error) {
    console.error('Error checking suspicious password change:', error);
    return { isSuspicious: false, reasons: [], riskScore: 0 };
  }
};

