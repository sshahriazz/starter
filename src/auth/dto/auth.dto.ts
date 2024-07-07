import { UserDto } from '@/user/dto/user.dto';
import {
  IsEmail,
  IsJWT,
  IsPhoneNumber,
  IsString,
  IsStrongPassword,
} from 'class-validator';

export class LoginDto {
  @IsEmail()
  email: string;
  @IsStrongPassword()
  password: string;
}
export class RegisterDto extends LoginDto {
  @IsString()
  firstName: string;
  @IsString()
  lastName: string;
}

export class ChangePasswordDto {
  @IsEmail()
  email: string;
  @IsString()
  otp: string;
  @IsStrongPassword()
  newPassword: string;
}

export class TokensDto {
  @IsJWT()
  accessToken: string;
  @IsJWT()
  refreshToken: string;
}

export class LoginResponseDto {
  user: UserDto;
  tokens: TokensDto;
}
export class RegisterResponseDto {
  user: UserDto;
  tokens: TokensDto;
}
