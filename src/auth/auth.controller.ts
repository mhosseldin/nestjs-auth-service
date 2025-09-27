import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dtos/register.dto';
import { VerifyEmailDto } from './dtos/verify-email.dto';
import { Throttle } from '@nestjs/throttler';
import { Request } from 'express';
import { ResendVerifyEmailDto } from './dtos/resend-verify-email.dto';
import { LoginDto } from './dtos/login.dto';
import { TokensDto } from './dtos/tokens.dto';
import { RefreshDto } from './dtos/refresh.dto';
import { CurrentUser, RequestUser } from './decorators/current-user';
import { JwtAccessGuard } from './guards/jwt-access.guard';
import { LogoutDto } from './dtos/logout.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @Throttle({ default: { ttl: 60, limit: 5 } })
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() dto: RegisterDto, @Req() req: Request) {
    const ip = (req.headers['x-forwarded-for'] as string) || req.ip || '';
    const userAgent = req.headers['user-agent'] || '';

    await this.authService.register(dto, { ip, userAgent } as const);
    return {
      message:
        'Registration successful. Please check your email to verify your account.',
    };
  }

  @Post('verify-email')
  @Throttle({ default: { limit: 30, ttl: 60 } })
  @HttpCode(HttpStatus.OK)
  async verifyEmail(@Body() dto: VerifyEmailDto, @Req() req: Request) {
    const ip = (req.headers['x-forwarded-for'] as string) || req.ip || '';
    const userAgent = req.headers['user-agent'] || '';
    await this.authService.verifyEmail(dto.token, { ip, userAgent });
    return { message: 'Email verified successfully.' };
  }

  @Post('verify-email/resend')
  @Throttle({ default: { limit: 3, ttl: 600 } })
  @HttpCode(HttpStatus.OK)
  async resendVerifyEmail(
    @Body() resendDto: ResendVerifyEmailDto,
    @Req() req: Request,
  ) {
    const ip = (req.headers['x-forwarded-for'] as string) || req.ip || '';
    const userAgent = req.headers['user-agent'] || '';
    await this.authService.resendVerifyEmail(resendDto.email, {
      ip,
      userAgent,
    });
    return { message: 'a new verification email has been sent.' };
  }

  @Post('login')
  @Throttle({ default: { limit: 5, ttl: 60 } })
  @HttpCode(HttpStatus.OK)
  async login(@Body() dto: LoginDto, @Req() req: Request): Promise<TokensDto> {
    const ip = (req.headers['x-forwarded-for'] as string) || req.ip || '';
    const userAgent = req.headers['user-agent'] || '';
    return await this.authService.login(dto, {
      ip,
      userAgent,
    });
  }

  @Post('refresh')
  @Throttle({ default: { limit: 20, ttl: 60 } }) // softer than login
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Body() dto: RefreshDto,
    @Req() req: Request,
  ): Promise<TokensDto> {
    const ip = (req.headers['x-forwarded-for'] as string) || req.ip || '';
    const userAgent = req.headers['user-agent'] || '';
    return await this.authService.refresh(dto.refreshToken, { ip, userAgent });
  }

  @Get('me')
  @UseGuards(JwtAccessGuard)
  async me(@CurrentUser() user: RequestUser) {
    return this.authService.me(user.userId);
  }

  @Post('logout')
  @Throttle({ default: { limit: 20, ttl: 60 } }) // gentle; prevents abuse
  @HttpCode(HttpStatus.OK)
  async logout(@Body() dto: LogoutDto, @Req() req: Request) {
    const ip = (req.headers['x-forwarded-for'] as string) || req.ip || '';
    const userAgent = req.headers['user-agent'] || '';
    await this.authService.logout(dto, { ip, userAgent });
    return { message: 'Logged out.' };
  }
}
