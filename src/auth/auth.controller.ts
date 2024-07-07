import {
  Body,
  Controller,
  Get,
  HttpException,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto } from './dto/auth.dto';
import { ApiBearerAuth, ApiBody, ApiTags } from '@nestjs/swagger';
import { Response, Request } from 'express';
import { IsPublic } from '@/common/metadata/public.decorator';
// import { JwtAuthGuard } from '@/common/decorators/jwt.guard';
import { JwtRefreshGuard } from '@/common/decorators/jwt-refresh.guard';
import { RoleCreateDto } from './dto/role-create.dto';
import { PermissionsDto } from './dto/permissions.dto';

@ApiTags('Authentication')
@ApiBearerAuth()
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @IsPublic()
  async register(@Body() registerDto: RegisterDto) {
    const authState = await this.authService.register(
      registerDto.email.toLowerCase(),
      registerDto.firstName,
      registerDto.lastName,

      registerDto.password,
    );

    return authState;
  }

  @Post('login')
  @IsPublic()
  async login(
    @Body() loginDto: LoginDto,
    @Query('isCookie') isCookie: boolean = false,
    @Res({ passthrough: true }) res: Response,
  ) {
    const authState = await this.authService.login(
      loginDto.email.toLowerCase(),
      loginDto.password,
    );

    if (!(authState instanceof HttpException)) {
      if (isCookie) {
        res.cookie('accessToken', authState.accessToken, {
          httpOnly: true,
          secure: true,
          // domain: '.absolutegm.com',
          sameSite: 'none',
        });
        res.cookie('refreshToken', authState.refreshToken, {
          httpOnly: true,
          secure: true,
          // domain: '.absolutegm.com',
          sameSite: 'none',
        });
      }
    }
    return authState;
  }

  @Get('refresh-token')
  @UseGuards(JwtRefreshGuard)
  async refreshToken(@Req() req: Request, @Query('rt') rt?: string) {
    return await this.authService.refreshTokens(rt);
  }

  @Post('add-role')
  // @UseGuards(JwtAuthGuard)
  async createUserRole(@Body() roleDto: RoleCreateDto) {
    return await this.authService.createRole(roleDto);
  }

  @Post('attach-role-to-user')
  // @UseGuards(JwtAuthGuard)
  async attachRoleToUser(
    @Query('user_id') user_id: string,
    @Query('role_id') role_id: string,
    @Query('assigned_by') assigned_by: string,
  ) {
    return await this.authService.attachRoleToUser(
      user_id,
      role_id,
      assigned_by,
    );
  }

  @Post('add-permissions-to-role')
  @ApiBody({ type: PermissionsDto, isArray: true })
  // @UseGuards(JwtAuthGuard)
  async addPermissionsToRole(
    @Query('role_id') role_id: string,
    @Body() permission: PermissionsDto[],
  ) {
    return await this.authService.addPermissionsToRole(role_id, permission);
  }

  @Post('attach-permissions-to-role')
  // @UseGuards(JwtAuthGuard)
  async attachPermissionToRole(
    @Query('role_id') role_id: string,
    @Query('permission_id') permission_id: string,
  ) {
    return await this.authService.attachPermissionToRole(
      role_id,
      permission_id,
    );
  }

  @Post('delete-role')
  // @UseGuards(JwtAuthGuard)
  async deleteRole(@Query('role_id') role_id: string) {
    return await this.authService.deleteRole(role_id);
  }

  @Post('delete-permissions')
  // @UseGuards(JwtAuthGuard)
  async deletePermission(@Query('permission_id') permission_id: string) {
    return await this.authService.deletePermission(permission_id);
  }

  @Post('remove-permission-from-role')
  // @UseGuards(JwtAuthGuard)
  async deleteRolePermission(
    @Query('role_id') role_id: string,
    @Query('permission_id') permission_id: string,
  ) {
    return await this.authService.removePermissionsFromRole(
      role_id,
      permission_id,
    );
  }

  @Post('remove-user-role')
  // @UseGuards(JwtAuthGuard)
  async removeUserRole(
    @Query('user_id') user_id: string,
    @Query('role_id') role_id: string,
  ) {
    return await this.authService.removeRoleFromUser(user_id, role_id);
  }

  @Get('list-user-role')
  // @UseGuards(JwtAuthGuard)
  async listUserRole(@Query('user_id') user_id: string) {
    return await this.authService.listUserRoles(user_id);
  }

  @Get('list-permissions')
  // @UseGuards(JwtAuthGuard)
  async listRolePermissions() {
    return await this.authService.listPermissions();
  }

  @Get('list-roles')
  // @UseGuards(JwtAuthGuard)
  async listRoles() {
    return await this.authService.listRoles();
  }
}
