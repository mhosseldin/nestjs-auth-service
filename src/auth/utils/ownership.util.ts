import { ForbiddenException } from '@nestjs/common';
import { Role } from '@prisma/client';

export function AssertOwnerOrAdmin(params: {
  actorId: string;
  actorRole: Role;
  ownerId: string;
  message?: string;
}) {
  const { actorId, actorRole, ownerId, message } = params;

  if (actorId === ownerId) return;
  if (actorRole === 'ADMIN') return;

  throw new ForbiddenException(
    message ?? 'Not allowed to access this resource.',
  );
}
