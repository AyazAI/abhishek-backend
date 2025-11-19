import mongoose, { Document, Schema } from 'mongoose';

export interface ISecurityLog extends Document {
  userId?: mongoose.Types.ObjectId;
  email?: string;
  action: string;
  ipAddress: string;
  userAgent: string;
  status: 'success' | 'failure' | 'warning';
  details?: string;
  location?: {
    country?: string;
    city?: string;
    coordinates?: {
      lat: number;
      lng: number;
    };
  };
  createdAt: Date;
}

const SecurityLogSchema = new Schema<ISecurityLog>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      index: true,
    },
    email: {
      type: String,
      index: true,
    },
    action: {
      type: String,
      required: true,
      enum: [
        'login',
        'logout',
        'register',
        'password_change',
        'password_reset',
        'email_verification',
        '2fa_enabled',
        '2fa_disabled',
        '2fa_verified',
        'session_created',
        'session_revoked',
        'suspicious_activity',
        'account_locked',
        'profile_update',
      ],
    },
    ipAddress: {
      type: String,
      required: true,
    },
    userAgent: {
      type: String,
      required: true,
    },
    status: {
      type: String,
      enum: ['success', 'failure', 'warning'],
      required: true,
    },
    details: String,
    location: {
      country: String,
      city: String,
      coordinates: {
        lat: Number,
        lng: Number,
      },
    },
  },
  {
    timestamps: true,
  }
);

// Indexes for efficient querying
SecurityLogSchema.index({ userId: 1, createdAt: -1 });
SecurityLogSchema.index({ email: 1, createdAt: -1 });
SecurityLogSchema.index({ action: 1, createdAt: -1 });
SecurityLogSchema.index({ status: 1, createdAt: -1 });
SecurityLogSchema.index({ createdAt: -1 });

export default mongoose.model<ISecurityLog>('SecurityLog', SecurityLogSchema);

