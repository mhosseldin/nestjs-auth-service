import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { RegisterDto } from './dtos/register.dto';
import * as bcrypt from 'bcrypt';
import { Prisma, Role } from '@prisma/client';
import { generateRawToken, hashToken, newSid } from './utils/token.util';
import { TokensService } from 'src/tokens/tokens.service';
import { LoginDto } from './dtos/login.dto';
import { LogoutDto } from './dtos/logout.dto';

type ReqCtx = { ip?: string; userAgent?: string };

@Injectable()
export class AuthService {
  private readonly bcryptCost = 12;
  private readonly verifyTtlMinutes = 15;
  private readonly resendCooldownMs = 2 * 60 * 1000;
  constructor(
    private readonly prisma: PrismaService,
    private readonly tokens: TokensService,
  ) {}

  async register(userDto: RegisterDto, ctx?: ReqCtx) {
    const email = userDto.email.trim().toLowerCase();
    const emailExist = await this.prisma.user.findUnique({
      where: { email },
      select: { id: true },
    });
    if (emailExist) {
      await this.prisma.auditLog.create({
        data: {
          actorId: null,
          action: 'register',
          entity: `email:${email}`,
          ip: ctx?.ip,
          userAgent: ctx?.userAgent,
          result: 'FAILURE',
          metadata: { reason: 'email already in use.' },
        },
      });
      throw new ConflictException('Email is already in use.');
    }

    const passwordHash = await bcrypt.hash(userDto.password, this.bcryptCost);

    try {
      // User Creation
      const user = this.prisma.user.create({
        data: { email, passwordHash },
      });

      // Email Verification Ticket Creation
      const rawToken = generateRawToken(32);
      const tokenHash = hashToken(rawToken);
      const expiresAt = new Date(
        Date.now() + this.verifyTtlMinutes * 60 * 1000,
      );

      await this.prisma.emailTicket.create({
        data: {
          userId: (await user).id,
          tokenHash,
          type: 'VERIFY',
          expiresAt,
        },
      });

      const appUrl = process.env.APP_URL ?? 'http://localhost:3000';
      const verifyUrl = `${appUrl}/verify-email?token=${encodeURIComponent(rawToken)}`;
      console.log(
        '🔐 Verify email link:',
        verifyUrl,
        '(expires',
        this.verifyTtlMinutes,
        'min)',
      );

      // Audit Success
      await this.prisma.auditLog.create({
        data: {
          actorId: null,
          action: 'register',
          entity: `user:${user}`,
          ip: ctx?.ip,
          userAgent: ctx?.userAgent,
          result: 'SUCCESS',
          metadata: { email },
        },
      });

      return user;
    } catch (err) {
      if (
        err instanceof Prisma.PrismaClientKnownRequestError &&
        err.code === 'P2002'
      ) {
        await this.prisma.auditLog.create({
          data: {
            actorId: null,
            action: 'register',
            entity: `email:${email}`,
            ip: ctx?.ip,
            userAgent: ctx?.userAgent,
            result: 'FAILURE',
            metadata: { reason: 'unique_violation' },
          },
        });
        throw new ConflictException('Email already in use.');
      }
      // Unexpected failure
      await this.prisma.auditLog.create({
        data: {
          actorId: null,
          action: 'register',
          entity: `email:${email}`,
          ip: ctx?.ip,
          userAgent: ctx?.userAgent,
          result: 'FAILURE',
          metadata: { reason: 'unexpected', code: (err as any)?.code },
        },
      });
      throw err;
    }
  }

  async verifyEmail(rawToken: string, ctx?: ReqCtx) {
    const tokenHash = hashToken(rawToken);
    const ticket = await this.prisma.emailTicket.findUnique({
      where: { tokenHash },
      select: {
        id: true,
        userId: true,
        type: true,
        expiresAt: true,
        usedAt: true,
      },
    });

    const baseAudit = {
      actorId: ticket?.userId ?? null,
      action: 'verify_email',
      entity: ticket ? `user:${ticket.userId}` : undefined,
      ip: ctx?.ip,
      userAgent: ctx?.userAgent,
    } as const;

    const now = new Date();
    if (
      !ticket ||
      ticket.usedAt ||
      ticket.type !== 'VERIFY' ||
      ticket.expiresAt <= now
    ) {
      await this.prisma.auditLog.create({
        data: {
          ...baseAudit,
          result: 'FAILURE',
          metadata: { reason: 'invalid_or_expired' },
        },
      });
      throw new BadRequestException('Invalid or expired token.');
    }

    await this.prisma.$transaction([
      this.prisma.emailTicket.update({
        where: { tokenHash },
        data: { usedAt: now },
      }),
      this.prisma.user.update({
        where: { id: ticket.userId },
        data: { emailVerifiedAt: now },
      }),
      this.prisma.emailTicket.deleteMany({
        where: { userId: ticket.userId, type: 'VERIFY', usedAt: null },
      }),
    ]);

    await this.prisma.auditLog.create({
      data: { ...baseAudit, result: 'SUCCESS' },
    });
  }

  async resendVerifyEmail(rawEmail: string, ctx?: ReqCtx) {
    const email = rawEmail.trim().toLowerCase();

    const user = await this.prisma.user.findUnique({
      where: { email },
      select: { id: true, emailVerifiedAt: true },
    });

    const baseAudit = {
      actorId: user?.id ?? null,
      action: 'resend_verify_email',
      entity: user ? `user:${user.id}` : `email:${email}`,
      ip: ctx?.ip,
      userAgent: ctx?.userAgent,
    } as const;

    if (!user || user.emailVerifiedAt) {
      await this.prisma.auditLog.create({
        data: { ...baseAudit, result: 'SUCCESS', metadata: { reason: 'noop' } },
      });
      return;
    }

    await this.prisma.emailTicket.deleteMany({
      where: { userId: user.id, type: 'VERIFY', usedAt: null },
    });

    const rawToken = generateRawToken(32);
    const tokenHashed = hashToken(rawToken);
    const expiresAt = new Date(Date.now() + this.verifyTtlMinutes * 60 * 1000);

    await this.prisma.emailTicket.create({
      data: {
        userId: user.id,
        tokenHash: tokenHashed,
        type: 'VERIFY',
        expiresAt,
      },
    });

    const appUrl = process.env.APP_URL ?? 'http://localhost:3000';
    const verifyUrl = `${appUrl}/verify-email?token=${encodeURIComponent(rawToken)}`;
    console.log(
      '🔐 (Resent) Verify email link:',
      verifyUrl,
      `(expires ${this.verifyTtlMinutes} min)`,
    );

    // Audit Success
    await this.prisma.auditLog.create({
      data: { ...baseAudit, result: 'SUCCESS', metadata: { resent: true } },
    });
  }

  async login(loginDto: LoginDto, ctx?: ReqCtx) {
    const email = loginDto.email.trim().toLowerCase();
    const user = await this.prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        emailVerifiedAt: true,
        passwordHash: true,
        role: true,
      },
    });

    const baseAudit = {
      actorId: user?.id ?? null,
      action: 'login',
      entity: user ? `user:${user.id}` : `email:${email}`,
      ip: ctx?.ip,
      userAgent: ctx?.userAgent,
    } as const;

    if (!user) {
      await this.prisma.auditLog.create({
        data: {
          ...baseAudit,
          result: 'FAILURE',
          metadata: { reason: 'user_not_found' },
        },
      });
      throw new UnauthorizedException('Invalid credentials.');
    }

    if (!user.emailVerifiedAt) {
      await this.prisma.auditLog.create({
        data: {
          ...baseAudit,
          result: 'FAILURE',
          metadata: { reason: 'unverified_account' },
        },
      });
      throw new ForbiddenException('Please verify your email first.');
    }

    const validPass = await bcrypt.compare(
      loginDto.password,
      user.passwordHash,
    );
    if (!validPass) {
      await this.prisma.auditLog.create({
        data: {
          ...baseAudit,
          result: 'FAILURE',
          metadata: { reason: 'invalid_credentials' },
        },
      });
      throw new UnauthorizedException('Invalid credentials.');
    }

    const accessToken = this.tokens.signAccess({
      sub: user.id,
      role: user.role as Role,
    });

    const sid = newSid();
    const refreshToken = this.tokens.signRefresh({ sub: user.id, sid });

    const decoded: any = this.tokens.decode(refreshToken);
    const expSec = decoded?.exp as number | undefined;
    const expiresAt = expSec
      ? new Date(expSec * 1000)
      : new Date(Date.now() + 14 * 24 * 3600 * 1000);

    await this.prisma.refreshToken.create({
      data: {
        userId: user.id,
        tokenHash: this.tokens.hashRefreshToken(refreshToken),
        createdAt: new Date(),
        expiresAt,
        ip: ctx?.ip,
        userAgent: ctx?.userAgent,
      },
    });

    await this.prisma.auditLog.create({
      data: { ...baseAudit, result: 'SUCCESS' },
    });

    return { accessToken, refreshToken };
  }

  async refresh(rawRefreshToken: string, ctx?: ReqCtx) {
    const baseAudit = {
      actorId: null,
      action: 'refresh',
      entity: undefined,
      ip: ctx?.ip,
      userAgent: ctx?.userAgent,
    } as const;

    let payload: { sub: string; sid: string };
    try {
      payload = this.tokens.verifyRefresh(rawRefreshToken);
    } catch {
      await this.prisma.auditLog.create({
        data: {
          ...baseAudit,
          result: 'FAILURE',
          metadata: { reason: 'invalid_refresh_jwt' },
        },
      });
      throw new UnauthorizedException('Invalid refresh token.');
    }

    const tokenHash = this.tokens.hashRefreshToken(rawRefreshToken);
    const record = await this.prisma.refreshToken.findUnique({
      where: { tokenHash },
      select: {
        id: true,
        userId: true,
        expiresAt: true,
        revokedAt: true,
      },
    });

    const now = new Date();
    if (!record || record.revokedAt || record.expiresAt <= now) {
      await this.prisma.auditLog.create({
        data: {
          ...baseAudit,
          actorId: record?.userId ?? null,
          entity: record ? `user:${record.userId}` : undefined,
          result: 'FAILURE',
          metadata: {
            reason: !record
              ? 'not_found'
              : record.revokedAt
                ? 'revoked'
                : 'expired',
          },
        },
      });
      throw new UnauthorizedException('Invalid refresh token.');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: record?.userId },
      select: { id: true, role: true },
    });
    if (!user) {
      await this.prisma.auditLog.create({
        data: {
          ...baseAudit,
          result: 'FAILURE',
          metadata: { reason: 'user_not_found' },
        },
      });
      throw new UnauthorizedException('Invalid refresh token.');
    }

    const newAccess = this.tokens.signAccess({
      sub: user.id,
      role: user.role as Role,
    });
    const sid = newSid();
    const newRefresh = this.tokens.signRefresh({ sub: user.id, sid });

    const decoded: any = this.tokens.decode(newRefresh);
    const expSec = decoded?.exp as number | undefined;
    const newExpiresAt = expSec
      ? new Date(expSec * 1000)
      : new Date(now.getTime() + 14 * 24 * 3600 * 1000);

    const newHash = this.tokens.hashRefreshToken(newRefresh);

    await this.prisma.$transaction([
      this.prisma.refreshToken.update({
        where: { tokenHash },
        data: { revokedAt: now, replacedBy: newHash },
      }),
      this.prisma.refreshToken.create({
        data: {
          userId: user.id,
          tokenHash: newHash,
          createdAt: now,
          expiresAt: newExpiresAt,
          ip: ctx?.ip,
          userAgent: ctx?.userAgent,
        },
      }),
      this.prisma.auditLog.create({
        data: {
          ...baseAudit,
          actorId: user.id,
          entity: `user:${user.id}`,
          result: 'SUCCESS',
          metadata: { rotated: true },
        },
      }),
    ]);

    return { accessToken: newAccess, refreshToken: newRefresh };
  }

  async me(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        role: true,
        emailVerifiedAt: true,
        createdAt: true,
      },
    });
    return user;
  }

  async logout(logoutDto: LogoutDto, ctx?: ReqCtx) {
    const baseAudit = {
      action: 'logout',
      actorId: null,
      entity: undefined,
      ip: ctx?.ip,
      userAgent: ctx?.userAgent,
    } as const;

    let payload: { sub: string; sid: string } | null = null;
    try {
      payload = this.tokens.verifyRefresh(logoutDto.refreshToken);
    } catch {
      await this.prisma.auditLog.create({
        data: {
          ...baseAudit,
          result: 'FAILURE',
          metadata: { reason: 'invalid_refresh_jwt' },
        },
      });
      return;
    }

    const tokenHash = this.tokens.hashRefreshToken(logoutDto.refreshToken);
    const record = await this.prisma.refreshToken.findUnique({
      where: { tokenHash },
      select: { id: true, userId: true, revokedAt: true, expiresAt: true },
    });

    const now = new Date();
    if (!record || record.revokedAt || record.expiresAt <= now) {
      await this.prisma.auditLog.create({
        data: {
          ...baseAudit,
          actorId: record?.userId ?? null,
          entity: record ? `user:${record.userId}` : undefined,
          result: 'FAILURE',
          metadata: {
            reason: !record
              ? 'not_found'
              : record.revokedAt
                ? 'revoked'
                : 'expired',
          },
        },
      });
      return;
    }

    await this.prisma.refreshToken.update({
      where: { tokenHash },
      data: { revokedAt: now },
    });

    await this.prisma.auditLog.create({
      data: {
        ...baseAudit,
        actorId: record.userId,
        entity: `user:${record.userId}`,
        result: 'SUCCESS',
      },
    });
  }
}
