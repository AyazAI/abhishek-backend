import { Request, Response } from 'express';
import Device from '../models/Device';
import Session from '../models/Session';
import { logSecurityEvent } from '../middleware/auth';
import { parseDeviceInfo, generateDeviceId } from '../utils/deviceParser';

// Get all devices for user
export const getDevices = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?._id;

    if (!userId) {
      res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
      return;
    }

    const devices = await Device.find({ userId }).sort({ lastUsed: -1 });

    res.status(200).json({
      success: true,
      data: devices.map((device) => ({
        id: device._id,
        deviceId: device.deviceId,
        deviceName: device.deviceName,
        deviceType: device.deviceType,
        browser: device.browser,
        os: device.os,
        ipAddress: device.ipAddress,
        isTrusted: device.isTrusted,
        lastUsed: device.lastUsed,
        createdAt: device.createdAt,
      })),
    });
  } catch (error: any) {
    console.error('Get devices error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch devices',
    });
  }
};

// Trust a device
export const trustDevice = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?._id;
    const { deviceId } = req.params;

    if (!userId) {
      res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
      return;
    }

    const device = await Device.findOne({ userId, deviceId });
    if (!device) {
      res.status(404).json({
        success: false,
        message: 'Device not found',
      });
      return;
    }

    device.isTrusted = true;
    await device.save();

    await logSecurityEvent(
      userId,
      req.user?.email,
      'device_trusted',
      req,
      'success',
      `Device ${device.deviceName} marked as trusted`
    );

    res.status(200).json({
      success: true,
      message: 'Device trusted successfully',
    });
  } catch (error: any) {
    console.error('Trust device error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to trust device',
    });
  }
};

// Revoke/remove a device
export const revokeDevice = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?._id;
    const { deviceId } = req.params;

    if (!userId) {
      res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
      return;
    }

    const device = await Device.findOne({ userId, deviceId });
    if (!device) {
      res.status(404).json({
        success: false,
        message: 'Device not found',
      });
      return;
    }

    // Also revoke all sessions for this device
    await Session.updateMany(
      {
        userId,
        'deviceInfo.deviceType': device.deviceType,
        'deviceInfo.ipAddress': device.ipAddress,
      },
      { isActive: false }
    );

    await device.deleteOne();

    await logSecurityEvent(
      userId,
      req.user?.email,
      'device_revoked',
      req,
      'success',
      `Device ${device.deviceName} revoked`
    );

    res.status(200).json({
      success: true,
      message: 'Device revoked successfully',
    });
  } catch (error: any) {
    console.error('Revoke device error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to revoke device',
    });
  }
};

// Revoke all devices except current
export const revokeAllDevices = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?._id;
    const deviceInfo = parseDeviceInfo(req);
    const currentDeviceId = generateDeviceId(deviceInfo);

    if (!userId) {
      res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
      return;
    }

    // Delete all devices except current
    await Device.deleteMany({
      userId,
      deviceId: { $ne: currentDeviceId },
    });

    // Revoke all sessions except current
    await Session.updateMany(
      {
        userId,
        refreshToken: { $ne: req.body.currentRefreshToken },
      },
      { isActive: false }
    );

    await logSecurityEvent(
      userId,
      req.user?.email,
      'all_devices_revoked',
      req,
      'success',
      'All devices revoked except current'
    );

    res.status(200).json({
      success: true,
      message: 'All devices revoked successfully',
    });
  } catch (error: any) {
    console.error('Revoke all devices error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to revoke devices',
    });
  }
};

