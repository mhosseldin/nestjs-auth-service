import { Injectable } from '@nestjs/common';
import { JwtService, JwtSignOptions, JwtVerifyOptions } from '@nestjs/jwt';
import { Role } from '@prisma/client';
import { createHash } from 'crypto';

type AccessClaims = { sub: string; role: Role };
type RefreshClaims = { sub: string; sid: string };

const ACCESS_SECRET = process.env.ACCESS_TOKEN_SECRET!;
const ACCESS_TTL = process.env.ACCESS_TOKEN_TTL || '15m';
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET!;
const REFRESH_TTL = process.env.REFRESH_TOKEN_TTL || '14d';
const ISS = process.env.JWT_ISSUER || 'auth-service';
const AUD = process.env.JWT_AUDIENCE || 'your-app';

@Injectable()
export class TokensService {
  constructor(private readonly jwt: JwtService) {}

  signAccess(payload: AccessClaims): string {
    if (!ACCESS_SECRET) throw new Error('ACCESS_TOKEN_SECRET is not set');
    const options: JwtSignOptions = {
      algorithm: 'HS256',
      secret: ACCESS_SECRET,
      expiresIn: ACCESS_TTL,
      issuer: ISS,
      audience: AUD,
    };
    return this.jwt.sign(payload, options);
  }

  verifyAccess(token: string): AccessClaims {
    if (!ACCESS_SECRET) throw new Error('ACCESS_TOKEN_SECRET is not set');
    const options: JwtVerifyOptions = {
      algorithms: ['HS256'],
      secret: ACCESS_SECRET,
      issuer: ISS,
      audience: AUD,
      clockTolerance: 5,
    };
    return this.jwt.verify(token, options) as AccessClaims;
  }

  signRefresh(payload: RefreshClaims): string {
    if (!REFRESH_SECRET) throw new Error('REFRESH_TOKEN_SECRET is not set');
    const options: JwtSignOptions = {
      algorithm: 'HS256',
      secret: REFRESH_SECRET,
      expiresIn: REFRESH_TTL,
      issuer: ISS,
      audience: AUD,
    };
    return this.jwt.sign(payload, options);
  }

  verifyRefresh(token: string): RefreshClaims {
    if (!REFRESH_SECRET) throw new Error('REFRESH_TOKEN_SECRET is not set');
    const options: JwtVerifyOptions = {
      algorithms: ['HS256'],
      secret: REFRESH_SECRET,
      issuer: ISS,
      audience: AUD,
      clockTolerance: 5,
    };
    return this.jwt.verify(token, options) as RefreshClaims;
  }

  hashRefreshToken(raw: string) {
    return createHash('sha256').update(raw).digest('hex');
  }

  decode<T = any>(token: string): T | null {
    return this.jwt.decode(token) as T | null;
  }
}
