import type { Role } from '@prisma/client';
import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export type RequestUser = {
  userId: string;
  role: Role;
};

export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): RequestUser => {
    const req = ctx.switchToHttp().getRequest();
    return req.user as RequestUser;
  },
);
