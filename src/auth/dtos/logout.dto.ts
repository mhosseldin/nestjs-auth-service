import { IsString, MinLength, IsOptional } from 'class-validator';

export class LogoutDto {
  @IsString()
  @MinLength(20)
  refreshToken!: string;
}
