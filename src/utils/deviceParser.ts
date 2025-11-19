import { Request } from 'express';

export interface DeviceInfo {
  userAgent: string;
  ipAddress: string;
  deviceType?: string;
  browser?: string;
  os?: string;
}

export const parseDeviceInfo = (req: Request): DeviceInfo => {
  const userAgent = req.get('user-agent') || 'Unknown';
  const ipAddress = 
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    (req.headers['x-real-ip'] as string) ||
    req.socket.remoteAddress ||
    'Unknown';

  // Parse browser
  let browser = 'Unknown';
  if (userAgent.includes('Chrome') && !userAgent.includes('Edg')) browser = 'Chrome';
  else if (userAgent.includes('Firefox')) browser = 'Firefox';
  else if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) browser = 'Safari';
  else if (userAgent.includes('Edg')) browser = 'Edge';
  else if (userAgent.includes('Opera')) browser = 'Opera';

  // Parse OS
  let os = 'Unknown';
  if (userAgent.includes('Windows')) os = 'Windows';
  else if (userAgent.includes('Mac OS')) os = 'macOS';
  else if (userAgent.includes('Linux')) os = 'Linux';
  else if (userAgent.includes('Android')) os = 'Android';
  else if (userAgent.includes('iOS')) os = 'iOS';

  // Parse device type
  let deviceType: 'mobile' | 'tablet' | 'desktop' | 'unknown' = 'unknown';
  if (/Mobile|Android|iPhone|iPad/.test(userAgent)) {
    if (/iPad|Tablet/.test(userAgent)) {
      deviceType = 'tablet';
    } else {
      deviceType = 'mobile';
    }
  } else {
    deviceType = 'desktop';
  }

  return {
    userAgent,
    ipAddress,
    deviceType,
    browser,
    os,
  };
};

export const generateDeviceId = (deviceInfo: DeviceInfo): string => {
  // Generate a unique device ID based on user agent and IP
  const crypto = require('crypto');
  const deviceString = `${deviceInfo.userAgent}-${deviceInfo.ipAddress}`;
  return crypto.createHash('sha256').update(deviceString).digest('hex').substring(0, 32);
};

