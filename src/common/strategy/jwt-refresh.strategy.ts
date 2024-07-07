import { Strategy, ExtractJwt } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtDto } from '../types/jwt';
import { UserDto } from '@/user/dto/user.dto';
import { SecurityConfig } from '../configs/config.interface';
import { PrismaService } from 'nestjs-prisma';

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(
    private readonly prismaService: PrismaService,
    readonly configService: ConfigService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<SecurityConfig>('security')?.refreshSecret,
    });
  }

  async validate(payload: JwtDto): Promise<UserDto> {
    const user = await this.prismaService.user.findUnique({
      where: {
        id: payload.user_id,
      },
    });
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
