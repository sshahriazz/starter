import {
  ConflictException,
  HttpException,
  HttpStatus,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';

import { SecurityConfig } from '@/common/configs/config.interface';

import { hash, compare } from 'bcrypt';
import { JWTPayload } from '@/common/types/api';

import { PrismaService } from 'nestjs-prisma';
import { RoleCreateDto } from './dto/role-create.dto';
import { PermissionsDto } from './dto/permissions.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly prismaService: PrismaService,
  ) {}

  async login(email: string, password: string) {
    const existingUser = await this.validateUser(email);

    if (!existingUser) {
      throw new NotFoundException('User not found');
    }

    const { password: pass } = existingUser;
    const isPasswordMatching = await compare(password, pass);

    if (!isPasswordMatching) {
      throw new HttpException('Invalid credentials', HttpStatus.BAD_REQUEST);
    }

    const payload: JWTPayload = {
      user_id: existingUser.id,
      avatar: existingUser.avatar,
      email: existingUser.email,
      firstname: existingUser.first_name!,
      lastname: existingUser.last_name!,
    };

    const accessToken = await this.generateAccessToken(payload);
    const refreshToken = await this.generateRefreshToken(payload);

    return { accessToken, refreshToken };
  }

  async register(
    email: string,
    firstName: string,
    lastName: string,

    password: string,
  ) {
    const existingUser = await this.validateUser(email);

    if (existingUser) {
      throw new ConflictException('User already exists');
    }

    const hashedPassword = await this.hashPassword(password);

    try {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password, ...user } = await this.prismaService.user.create({
        data: {
          email,
          password: hashedPassword,
          first_name: firstName,
          last_name: lastName,
        },
      });

      const payload: JWTPayload = {
        user_id: user.id,
        email: user.email,
        avatar: user.avatar,
        firstname: user.first_name!,
        lastname: user.last_name!,
      };

      const accessToken = await this.generateAccessToken(payload);
      const refreshToken = await this.generateRefreshToken(payload);

      return { accessToken, refreshToken };
    } catch (error) {
      throw new HttpException('User Creation Failed', HttpStatus.BAD_REQUEST);
    }
  }

  async refreshTokens(refreshToken: string) {
    const securityConfig = this.configService.get<SecurityConfig>('security')!;
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: securityConfig.refreshSecret,
      });

      const user = await this.prismaService.user.findUnique({
        where: { id: payload.user_id },
        // include: { role: { include: { permissions: true } } },
      });

      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      const jwtPayload: JWTPayload = {
        user_id: user.id,
        avatar: user.avatar,
        email: user.email,
        firstname: user.first_name!,
        lastname: user.last_name!,
      };

      const accessToken = await this.generateAccessToken(jwtPayload);
      const newRefreshToken = await this.generateRefreshToken(jwtPayload);

      return { accessToken, newRefreshToken };
    } catch (error) {
      throw new HttpException('Invalid refresh token', HttpStatus.UNAUTHORIZED);
    }
  }

  async changePassword(email: string, otp: string, newPassword: string) {
    const user = await this.validateUser(email);
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    const hashedOTP = await compare(otp, 'otp');
    if (!hashedOTP) {
      throw new HttpException('Invalid OTP', HttpStatus.BAD_REQUEST);
    }

    await this.prismaService.user.update({
      where: {
        email,
      },
      data: {
        password: await this.hashPassword(newPassword),
      },
    });
    //TODO: Send an event to notify the user that the password has been changed via email
    return { message: 'Password changed successfully' };
  }

  async forgotPasswordRequest(email: string) {
    const user = await this.validateUser(email);
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }
    // const otp = await this.generateOTP();
    // const hashedOTP = await this.hashOTP(otp);
    await this.prismaService.user.update({
      where: {
        email,
      },
      data: {
        // otp_secret: hashedOTP,
      },
    });
    //TODO: Now emit the event to send the OTP to the user
    return { message: 'OTP sent to your email' };
  }

  async validateUser(email: string) {
    const user = await this.prismaService.user.findUnique({
      where: { email },
    });
    if (user) {
      return user;
    }
    return null;
  }

  private async generateAccessToken(payload: JWTPayload): Promise<string> {
    const securityConfig = this.configService.get<SecurityConfig>('security')!;

    return this.jwtService.sign(payload, {
      secret: securityConfig.accessSecret,
      expiresIn: securityConfig.expiresIn,
    });
  }

  private async generateRefreshToken(payload: {
    user_id: string;
  }): Promise<string> {
    const securityConfig = this.configService.get<SecurityConfig>('security')!;
    return this.jwtService.sign(payload, {
      secret: securityConfig.refreshSecret,
      expiresIn: securityConfig.refreshIn,
    });
  }
  private async hashPassword(password: string): Promise<string> {
    const securityConfig = this.configService.get<SecurityConfig>('security')!;
    const salt = securityConfig.bcryptSaltOrRound;
    const hashedPassword = await hash(password, salt);
    if (!hashedPassword) {
      throw new HttpException('Password not hashed', HttpStatus.BAD_REQUEST);
    }
    return hashedPassword;
  }

  async attachRoleToUser(userId: string, roleId: string, assignedBy: string) {
    try {
      await this.prismaService.user_Role.create({
        data: {
          role_id: roleId,
          user_id: userId,
          assignedBy: assignedBy,
          assignedAt: new Date(),
        },
      });
      return {
        statusCode: 201,
        message: 'Role attached to user successfully',
      };
    } catch (error) {
      throw new HttpException(
        'Failed to attach role to user',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  // Role Permission based authentication
  async createRole(data: RoleCreateDto) {
    // Create a new role
    await this.prismaService.role.create({
      data: {
        ...data,
        permissions: {
          create: [],
        },
      },
    });
  }

  async addPermissionsToRole(roleId: string, permissions: PermissionsDto[]) {
    try {
      permissions.forEach(async (permission) => {
        await this.prismaService.permission.create({
          data: {
            resource: permission.resource,
            actions: permission.actions,
            role: {
              connect: { id: roleId },
            },
          },
        });
      });
      return {
        statusCode: 201,
        message: 'Permissions created for role successfully',
      };
    } catch (error) {
      console.log(error);

      throw new HttpException(
        'Failed to add permissions',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  async attachPermissionToRole(role_id: string, permission_id: string) {
    try {
      await this.prismaService.role.update({
        where: {
          id: role_id,
        },
        data: {
          permissions: {
            connect: {
              id: permission_id,
            },
          },
        },
      });

      return {
        statusCode: 200,
        message: 'Permissions added to role successfully',
      };
    } catch (error) {
      console.log(error);

      throw new HttpException(
        'Failed to add permissions',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  async deleteRole(roleId: string) {
    try {
      await this.prismaService.role.delete({
        where: {
          id: roleId,
        },
      });
      return {
        statusCode: HttpStatus.CREATED,
        message: 'Role deleted successfully',
      };
    } catch (error) {
      throw new HttpException('Failed to delete role', HttpStatus.BAD_REQUEST);
    }
  }

  async deletePermission(permissionId: string) {
    try {
      await this.prismaService.permission.delete({
        where: {
          id: permissionId,
        },
      });
      return {
        statusCode: HttpStatus.OK,
        message: 'Permission deleted successfully',
      };
    } catch (error) {
      throw new HttpException(
        'Failed to delete permission',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  async removePermissionsFromRole(roleId: string, permissionId: string) {
    // try {
    await this.prismaService.role.update({
      where: {
        id: roleId,
      },
      data: {
        permissions: {
          delete: {
            id: permissionId,
          },
        },
      },
    });
    return {
      statusCode: HttpStatus.CREATED,
      message: 'Permissions removed from role successfully',
    };
    // } catch (error) {
    //   throw new HttpException(
    //     'Failed to remove permissions from role',
    //     HttpStatus.BAD_REQUEST,
    //   );
    // }
  }

  async removeRoleFromUser(userId: string, roleId: string) {
    try {
      await this.prismaService.user.update({
        where: {
          id: userId,
        },
        data: {
          user_role: {
            disconnect: {
              role_id_user_id: {
                role_id: roleId,
                user_id: userId,
              },
            },
          },
        },
      });
      return {
        statusCode: HttpStatus.CREATED,
        message: 'Role removed from user successfully',
      };
    } catch (error) {
      throw new HttpException(
        'Failed to remove role from user',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  async listUserRoles(user_id: string) {
    return await this.prismaService.user_Role.findMany({
      where: {
        user_id,
      },
    });
  }
  async listPermissions() {
    return await this.prismaService.permission.findMany();
  }
  async listRoles() {
    return await this.prismaService.role.findMany({
      include: {
        permissions: true,
      },
    });
  }
}
