import { Request } from 'express';
import { parseDeviceInfo } from './deviceParser';

export interface LocationInfo {
  country?: string;
  city?: string;
  coordinates?: {
    lat: number;
    lng: number;
  };
  isp?: string;
  timezone?: string;
}

// Simple IP geolocation (can be enhanced with external API like ipapi.co, ip-api.com, etc.)
export const getLocationFromIP = async (ipAddress: string): Promise<LocationInfo | null> => {
  try {
    // Skip localhost and private IPs
    if (
      ipAddress === '127.0.0.1' ||
      ipAddress === '::1' ||
      ipAddress.startsWith('192.168.') ||
      ipAddress.startsWith('10.') ||
      ipAddress.startsWith('172.16.')
    ) {
      return {
        country: 'Local',
        city: 'Local Network',
      };
    }

    // In production, you would use a service like:
    // - ipapi.co (free tier available)
    // - ip-api.com (free tier available)
    // - maxmind GeoIP2
    // For now, return null to indicate location not available
    // You can integrate with an external API here

    // Example integration (uncomment and configure):
    /*
    const response = await fetch(`https://ipapi.co/${ipAddress}/json/`);
    const data = await response.json();
    return {
      country: data.country_name,
      city: data.city,
      coordinates: {
        lat: data.latitude,
        lng: data.longitude,
      },
      isp: data.org,
      timezone: data.timezone,
    };
    */

    return null;
  } catch (error) {
    console.error('Error getting location from IP:', error);
    return null;
  }
};

export const getLocationFromRequest = async (req: Request): Promise<LocationInfo | null> => {
  const deviceInfo = parseDeviceInfo(req);
  return getLocationFromIP(deviceInfo.ipAddress);
};

