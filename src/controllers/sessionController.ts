import { Request, Response } from 'express';
import Session from '../models/Session';
import { logSecurityEvent } from '../middleware/auth';

// Get all active sessions
export const getSessions = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?._id;

    if (!userId) {
      res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
      return;
    }

    const sessions = await Session.find({ userId, isActive: true }).sort({
      lastActivity: -1,
    });

    res.status(200).json({
      success: true,
      data: sessions.map((session) => ({
        id: session._id,
        deviceInfo: session.deviceInfo,
        lastActivity: session.lastActivity,
        createdAt: session.createdAt,
        expiresAt: session.expiresAt,
      })),
    });
  } catch (error: any) {
    console.error('Get sessions error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch sessions',
    });
  }
};

// Revoke a specific session
export const revokeSession = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?._id;
    const { sessionId } = req.params;

    if (!userId) {
      res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
      return;
    }

    const session = await Session.findOne({ _id: sessionId, userId });
    if (!session) {
      res.status(404).json({
        success: false,
        message: 'Session not found',
      });
      return;
    }

    session.isActive = false;
    await session.save();

    await logSecurityEvent(
      userId,
      req.user?.email,
      'session_revoked',
      req,
      'success',
      'Session revoked'
    );

    res.status(200).json({
      success: true,
      message: 'Session revoked successfully',
    });
  } catch (error: any) {
    console.error('Revoke session error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to revoke session',
    });
  }
};

// Revoke all sessions except current
export const revokeAllSessions = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?._id;
    const { currentRefreshToken } = req.body;

    if (!userId) {
      res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
      return;
    }

    await Session.updateMany(
      {
        userId,
        refreshToken: { $ne: currentRefreshToken },
        isActive: true,
      },
      { isActive: false }
    );

    await logSecurityEvent(
      userId,
      req.user?.email,
      'all_sessions_revoked',
      req,
      'success',
      'All sessions revoked except current'
    );

    res.status(200).json({
      success: true,
      message: 'All sessions revoked successfully',
    });
  } catch (error: any) {
    console.error('Revoke all sessions error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to revoke sessions',
    });
  }
};

