import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'nestjs-prisma';
import { JwtPayload } from './interface/jwt-payload.interface';
import { User } from '@prisma/client';

export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly prismaService: PrismaService) {
    super({
      secretOrKey: 'topSecret92',
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    });
  }

  async validate(payload: JwtPayload): Promise<Omit<User, 'password'>> {
    const { email } = payload;
    const user = await this.prismaService.user.findUnique({
      select: {
        email: true,
        email_verified: true,
        id: true,
      },
      where: { email },
    });

    if (!user) {
      throw new UnauthorizedException();
    }

    return user;
  }
}
