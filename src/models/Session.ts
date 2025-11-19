import mongoose, { Document, Schema } from 'mongoose';

export interface ISession extends Document {
  userId: mongoose.Types.ObjectId;
  refreshToken: string;
  deviceInfo: {
    userAgent: string;
    ipAddress: string;
    deviceType?: string;
    browser?: string;
    os?: string;
  };
  isActive: boolean;
  lastActivity: Date;
  expiresAt: Date;
  createdAt: Date;
}

const SessionSchema = new Schema<ISession>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    refreshToken: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    deviceInfo: {
      userAgent: {
        type: String,
        required: true,
      },
      ipAddress: {
        type: String,
        required: true,
      },
      deviceType: String,
      browser: String,
      os: String,
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    lastActivity: {
      type: Date,
      default: Date.now,
    },
    expiresAt: {
      type: Date,
      required: true,
      index: { expireAfterSeconds: 0 },
    },
  },
  {
    timestamps: true,
  }
);

// Indexes
SessionSchema.index({ userId: 1, isActive: 1 });
SessionSchema.index({ refreshToken: 1 });

export default mongoose.model<ISession>('Session', SessionSchema);

