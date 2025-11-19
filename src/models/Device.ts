import mongoose, { Document, Schema } from 'mongoose';

export interface IDevice extends Document {
  userId: mongoose.Types.ObjectId;
  deviceId: string;
  deviceName: string;
  deviceType: 'mobile' | 'tablet' | 'desktop' | 'unknown';
  browser: string;
  os: string;
  ipAddress: string;
  lastUsed: Date;
  isTrusted: boolean;
  createdAt: Date;
}

const DeviceSchema = new Schema<IDevice>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    deviceId: {
      type: String,
      required: true,
    },
    deviceName: {
      type: String,
      required: true,
    },
    deviceType: {
      type: String,
      enum: ['mobile', 'tablet', 'desktop', 'unknown'],
      default: 'unknown',
    },
    browser: String,
    os: String,
    ipAddress: {
      type: String,
      required: true,
    },
    lastUsed: {
      type: Date,
      default: Date.now,
    },
    isTrusted: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

// Compound index to ensure unique device per user
DeviceSchema.index({ userId: 1, deviceId: 1 }, { unique: true });

export default mongoose.model<IDevice>('Device', DeviceSchema);

