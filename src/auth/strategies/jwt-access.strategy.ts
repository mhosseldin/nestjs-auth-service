import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Role } from '@prisma/client';

type AccessClaims = { sub: string; role: Role };
const ACCESS_SECRET = process.env.ACCESS_TOKEN_SECRET!;
const ISS = process.env.JWT_ISSUER || 'auth-service';
const AUD = process.env.JWT_AUDIENCE || 'your-app';

@Injectable()
export class JwtAccessStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: ACCESS_SECRET,
      issuer: ISS,
      audience: AUD,
      ignoreExpiration: false,
    });
  }

  validate(payload: AccessClaims) {
    return { userId: payload.sub, role: payload.role };
  }
}
