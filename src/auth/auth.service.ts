import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt'; // JWT
import { PrismaService } from 'nestjs-prisma';
import { SigninDto } from './dto/signin.dto';
import { JwtPayload } from './interface/jwt-payload.interface';
import { SignUpDto } from './dto/signup.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private jwtService: JwtService,
  ) {}

  async signIn(signInDto: SigninDto): Promise<{ accessToken: string }> {
    const { email, password } = signInDto;
    const user = await this.prismaService.user.findUnique({
      where: { email },
    });

    if (user && (await bcrypt.compare(password, user.password))) {
      const payload: JwtPayload = { email: user.email, sub: user.id };
      const accessToken = this.jwtService.sign(payload);
      return { accessToken };
    } else {
      throw new UnauthorizedException('Please check your login credentials.');
    }
  }
  async signup(signUpDto: SignUpDto) {
    const { email, password } = signUpDto;
    const user = await this.prismaService.user.findUnique({
      where: {
        email,
      },
    });
    if (user?.id) {
      throw new ConflictException('User already exist');
    }
    const salt = bcrypt.genSaltSync(10);
    const newUser = await this.prismaService.user.create({
      data: {
        email: email,
        password: bcrypt.hashSync(password, salt),
      },
    });
    const payload: JwtPayload = { email: newUser.email, sub: newUser.id };
    const accessToken = await this.jwtService.signAsync(payload);
    return { accessToken };
  }
}
