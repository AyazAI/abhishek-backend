import { Request, Response } from 'express';
import SecurityLog from '../models/SecurityLog';

// Get security activity logs
export const getActivityLogs = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?._id;
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 20;
    const skip = (page - 1) * limit;

    if (!userId) {
      res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
      return;
    }

    const logs = await SecurityLog.find({ userId })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await SecurityLog.countDocuments({ userId });

    res.status(200).json({
      success: true,
      data: {
        logs: logs.map((log) => ({
          id: log._id,
          action: log.action,
          status: log.status,
          ipAddress: log.ipAddress,
          userAgent: log.userAgent,
          location: log.location,
          details: log.details,
          createdAt: log.createdAt,
        })),
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit),
        },
      },
    });
  } catch (error: any) {
    console.error('Get activity logs error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch activity logs',
    });
  }
};

// Get security summary/statistics
export const getSecuritySummary = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?._id;

    if (!userId) {
      res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
      return;
    }

    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const [
      totalLogs,
      successfulLogins,
      failedLogins,
      recentActivity,
      suspiciousActivity,
    ] = await Promise.all([
      SecurityLog.countDocuments({ userId }),
      SecurityLog.countDocuments({
        userId,
        action: 'login',
        status: 'success',
      }),
      SecurityLog.countDocuments({
        userId,
        action: 'login',
        status: 'failure',
      }),
      SecurityLog.find({ userId })
        .sort({ createdAt: -1 })
        .limit(10),
      SecurityLog.countDocuments({
        userId,
        action: 'suspicious_activity',
        createdAt: { $gte: thirtyDaysAgo },
      }),
    ]);

    res.status(200).json({
      success: true,
      data: {
        summary: {
          totalLogs,
          successfulLogins,
          failedLogins,
          suspiciousActivityCount: suspiciousActivity,
        },
        recentActivity: recentActivity.map((log) => ({
          action: log.action,
          status: log.status,
          ipAddress: log.ipAddress,
          createdAt: log.createdAt,
        })),
      },
    });
  } catch (error: any) {
    console.error('Get security summary error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch security summary',
    });
  }
};

