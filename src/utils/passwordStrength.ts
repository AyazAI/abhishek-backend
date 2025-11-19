export interface PasswordStrength {
  score: number; // 0-100
  strength: 'weak' | 'fair' | 'good' | 'strong' | 'very-strong';
  feedback: string[];
  requirements: {
    length: boolean;
    uppercase: boolean;
    lowercase: boolean;
    number: boolean;
    special: boolean;
    common: boolean;
  };
}

export const checkPasswordStrength = (password: string): PasswordStrength => {
  const feedback: string[] = [];
  const requirements = {
    length: password.length >= 8,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    number: /\d/.test(password),
    special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
    common: !isCommonPassword(password),
  };

  let score = 0;

  // Length scoring
  if (password.length >= 8) score += 20;
  if (password.length >= 12) score += 10;
  if (password.length >= 16) score += 10;

  // Character variety scoring
  if (requirements.uppercase) score += 15;
  if (requirements.lowercase) score += 15;
  if (requirements.number) score += 15;
  if (requirements.special) score += 15;

  // Bonus for uncommon passwords
  if (requirements.common) score += 10;

  // Penalties
  if (password.length < 8) {
    feedback.push('Password should be at least 8 characters long');
  }
  if (!requirements.uppercase) {
    feedback.push('Add uppercase letters');
  }
  if (!requirements.lowercase) {
    feedback.push('Add lowercase letters');
  }
  if (!requirements.number) {
    feedback.push('Add numbers');
  }
  if (!requirements.special) {
    feedback.push('Add special characters');
  }
  if (!requirements.common) {
    feedback.push('Avoid common passwords');
  }

  // Determine strength
  let strength: 'weak' | 'fair' | 'good' | 'strong' | 'very-strong';
  if (score < 40) strength = 'weak';
  else if (score < 60) strength = 'fair';
  else if (score < 80) strength = 'good';
  else if (score < 90) strength = 'strong';
  else strength = 'very-strong';

  return {
    score,
    strength,
    feedback,
    requirements,
  };
};

const isCommonPassword = (password: string): boolean => {
  const commonPasswords = [
    'password',
    '12345678',
    '123456789',
    '1234567890',
    'qwerty',
    'abc123',
    'password123',
    'admin',
    'letmein',
    'welcome',
    'monkey',
    '1234567',
    'sunshine',
    'princess',
    'football',
    'iloveyou',
  ];
  return commonPasswords.includes(password.toLowerCase());
};

