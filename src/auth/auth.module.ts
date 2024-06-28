import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({
      secret: 'topSecret92', // SECRET KEY - TEXT OR FILE
      signOptions: {
        expiresIn: 3600, // TOKEN EXPIRY TIME
      },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService],
  exports: [PassportModule],
})
export class AuthModule {}
