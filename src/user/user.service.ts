import {
  HttpException,
  HttpStatus,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'nestjs-prisma';
import { UserResponseDto } from './dto/user-response.dto';

import { ConfigService } from '@nestjs/config';
import { UserListDto } from './dto/user.dto';
import { NestConfig, SecurityConfig } from '@/common/configs/config.interface';

import { UpdateUserDto } from './dto/update-user.dto';
import { hash } from 'bcrypt';

@Injectable()
export class UserService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly configService: ConfigService,
  ) {}

  private async hashPassword(password: string): Promise<string> {
    const securityConfig = this.configService.get<SecurityConfig>('security')!;
    const salt = securityConfig.bcryptSaltOrRound;
    const hashedPassword = await hash(password, salt);
    if (!hashedPassword) {
      throw new HttpException('Password not hashed', HttpStatus.BAD_REQUEST);
    }
    return hashedPassword;
  }

  async updateUser(user: UpdateUserDto): Promise<UserResponseDto> {
    const { id, password, ...rest } = user;
    return await this.prismaService.user.update({
      where: { id },
      data: password
        ? { ...rest, password: await this.hashPassword(password) }
        : rest,
    });
  }
  async deleteUser(id: string) {
    const user = await this.prismaService.user.findUnique({
      where: { id: id },
    });
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return await this.prismaService.user.delete({ where: { id: id } });
  }

  async findUser(id: string): Promise<UserResponseDto> {
    const user = await this.prismaService.user.findUnique({
      where: { id: id },
    });
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }
  async findUserByEmail(email: string): Promise<UserResponseDto> {
    const user = await this.prismaService.user.findUnique({
      where: { email: email },
    });
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  async listUsers(
    take: number,
    cursor: string | null,
    sortColumn: 'created_at' | 'first_name' | 'last_name' | 'email',
    sortOrder: 'asc' | 'desc',
  ): Promise<UserListDto> {
    const pageSize =
      this.configService.get<NestConfig>('nest')?.defaultPageSize;

    const users = await this.prismaService.user.findMany({
      take: Number.isNaN(take) ? pageSize! : take,
      cursor: cursor ? { id: cursor } : undefined,
      orderBy: { [sortColumn]: sortOrder },
    });

    const nextCursor =
      users.length < (!Number.isNaN(take) ? take : pageSize!)
        ? null
        : users[users.length - 1]?.id ?? null;

    return { data: users, nextCursor };
  }
}
