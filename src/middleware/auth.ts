import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken, TokenPayload } from '../utils/jwt';
import User from '../models/User';
import { ISecurityLog } from '../models/SecurityLog';
import SecurityLog from '../models/SecurityLog';
import { parseDeviceInfo } from '../utils/deviceParser';
import { getLocationFromRequest } from '../utils/geolocation';

// Extend Express Request to include user
declare global {
  namespace Express {
    interface Request {
      user?: TokenPayload & { _id: string };
    }
  }
}

export const authenticate = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ 
        success: false, 
        message: 'No token provided. Please authenticate.' 
      });
      return;
    }

    const token = authHeader.substring(7);
    
    try {
      const decoded = verifyAccessToken(token);
      
      // Verify user still exists
      const user = await User.findById(decoded.userId);
      if (!user) {
        res.status(401).json({ 
          success: false, 
          message: 'User not found. Token invalid.' 
        });
        return;
      }

      // Check if account is locked
      if (user.isAccountLocked()) {
        res.status(403).json({ 
          success: false, 
          message: 'Account is locked. Please contact support.' 
        });
        return;
      }

      req.user = {
        ...decoded,
        _id: decoded.userId,
      };
      
      next();
    } catch (error: any) {
      if (error.name === 'TokenExpiredError') {
        res.status(401).json({ 
          success: false, 
          message: 'Token expired. Please refresh your token.' 
        });
        return;
      }
      
      res.status(401).json({ 
        success: false, 
        message: 'Invalid token. Please authenticate.' 
      });
    }
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Authentication error' 
    });
  }
};

export const authorize = (...roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ 
        success: false, 
        message: 'Authentication required' 
      });
      return;
    }

    if (!roles.includes(req.user.role)) {
      res.status(403).json({ 
        success: false, 
        message: 'Insufficient permissions. Access denied.' 
      });
      return;
    }

    next();
  };
};

export const logSecurityEvent = async (
  userId: string | undefined,
  email: string | undefined,
  action: string,
  req: Request,
  status: 'success' | 'failure' | 'warning',
  details?: string
): Promise<void> => {
  try {
    const deviceInfo = parseDeviceInfo(req);
    
    // Get location info (async, but we don't wait for it to complete)
    getLocationFromRequest(req).then((location: any) => {
      // Update log with location if available
      if (location) {
        SecurityLog.findOneAndUpdate(
          { userId, action, ipAddress: deviceInfo.ipAddress, createdAt: { $gte: new Date(Date.now() - 1000) } },
          { location },
          { sort: { createdAt: -1 } }
        ).catch(() => {});
      }
    }).catch(() => {});
    
    const logEntry: Partial<ISecurityLog> = {
      userId: userId ? require('mongoose').Types.ObjectId.createFromHexString(userId) : undefined,
      email,
      action,
      ipAddress: deviceInfo.ipAddress,
      userAgent: deviceInfo.userAgent,
      status,
      details,
    };

    await SecurityLog.create(logEntry);
  } catch (error) {
    console.error('Error logging security event:', error);
  }
};

