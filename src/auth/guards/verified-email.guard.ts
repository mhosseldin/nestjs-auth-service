import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PrismaService } from 'prisma/prisma.service';
import { Observable } from 'rxjs';
import { ALLOW_UNVERIFIED_KEY } from '../decorators/allow-unverified.decorator';

@Injectable()
export class VerifiedEmailGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly prisma: PrismaService,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const allowVerified = this.reflector.getAllAndOverride<boolean>(
      ALLOW_UNVERIFIED_KEY,
      [ctx.getHandler(), ctx.getClass()],
    );
    if (allowVerified) return true;

    const req = ctx.switchToHttp().getRequest();
    const user = (req.user as { userId: string }) || undefined;

    if (!user?.userId) {
      throw new ForbiddenException('Missing our context.');
    }

    const found = await this.prisma.user.findUnique({
      where: { id: user.userId },
      select: { emailVerifiedAt: true },
    });

    if (!found?.emailVerifiedAt) {
      throw new ForbiddenException('Email is not verified.');
    }

    return true;
  }
}
