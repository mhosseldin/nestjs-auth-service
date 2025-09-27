import { IsString, MinLength } from 'class-validator';

export class RefreshDto {
  @IsString()
  @MinLength(20) // JWTs are long; this blocks obvious junk
  refreshToken!: string;
}
