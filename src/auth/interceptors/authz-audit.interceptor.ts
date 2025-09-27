import {
  CallHandler,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  NestInterceptor,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { catchError, Observable, throwError } from 'rxjs';

@Injectable()
export class AuthzAuditInterceptor implements NestInterceptor {
  constructor(private readonly prisma: PrismaService) {}

  intercept(ctx: ExecutionContext, next: CallHandler<any>): Observable<any> {
    const req = ctx.switchToHttp().getRequest();
    const actor = (req.user as { userId?: string } | undefined)?.userId ?? null;
    const ip =
      (req.headers['x-forwarded-for'] as string) || req.ip || undefined;
    const userAgent = (req.headers['user-agent'] as string) || undefined;
    const entity = `${req.method} ${req.originalUrl || req.url}`;

    return next.handle().pipe(
      catchError((err) => {
        if (
          err instanceof ForbiddenException ||
          err instanceof UnauthorizedException
        ) {
          this.prisma.auditLog
            .create({
              data: {
                actorId: actor,
                action: 'authorize',
                entity,
                ip,
                userAgent,
                result: 'FAILURE',
                metadata: {
                  reason:
                    err instanceof ForbiddenException
                      ? 'forbidden'
                      : 'unauthorized',
                },
              },
            })
            .catch(() => void 0);
        }
        return throwError(() => err);
      }),
    );
  }
}
