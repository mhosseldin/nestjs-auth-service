import { createHash, randomBytes } from 'crypto';

export function generateRawToken(byteLength = 32) {
  return randomBytes(byteLength).toString('base64url');
}

export function hashToken(raw: string) {
  return createHash('sha256').update(raw).digest('hex');
}

export function newSid(length = 16): string {
  return randomBytes(length).toString('hex');
}
