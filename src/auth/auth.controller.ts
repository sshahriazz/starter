import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SigninDto } from './dto/signin.dto';
import { SignUpDto } from './dto/signup.dto';
import { ApiTags } from '@nestjs/swagger';

@Controller('auth')
@ApiTags('Auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('/signin')
  signIn(
    @Body() authCredentialsDto: SigninDto,
  ): Promise<{ accessToken: string }> {
    return this.authService.signIn(authCredentialsDto);
  }
  @Post('/signup')
  signUp(
    @Body() authCredentialsDto: SignUpDto,
  ): Promise<{ accessToken: string }> {
    console.log(authCredentialsDto);

    return this.authService.signup(authCredentialsDto);
  }
}
