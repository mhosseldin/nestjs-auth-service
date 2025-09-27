import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TokensModule } from 'src/tokens/tokens.module';
import { JwtAccessStrategy } from './strategies/jwt-access.strategy';
import { PassportModule } from '@nestjs/passport';
import { RolesGuard } from './guards/roles.guard';
import { VerifiedEmailGuard } from './guards/verified-email.guard';
import { AuthzAuditInterceptor } from './interceptors/authz-audit.interceptor';

@Module({
  imports: [PassportModule, TokensModule],
  controllers: [AuthController],
  providers: [
    AuthService,
    JwtAccessStrategy,
    RolesGuard,
    VerifiedEmailGuard,
    AuthzAuditInterceptor,
  ],
  exports: [RolesGuard, VerifiedEmailGuard, AuthzAuditInterceptor],
})
export class AuthModule {}
