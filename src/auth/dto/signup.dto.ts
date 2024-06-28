import { IsEmail, IsStrongPassword } from 'class-validator';

export class SignUpDto {
  firstname?: string;
  lastname?: string;
  @IsEmail()
  email: string;
  @IsStrongPassword()
  password: string;
}
