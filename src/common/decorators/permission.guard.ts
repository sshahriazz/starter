import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PrismaService } from 'nestjs-prisma';

@Injectable()
export class PermissionGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly prismaService: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext) {
    const permission = this.reflector.get<string>(
      'permission',
      context.getHandler(),
    );
    // const resource = this.reflector.get<string>('resource', context.getClass());

    const isPublic = this.reflector.get<boolean>(
      'isPublic',
      context.getHandler(),
    );

    if (isPublic) {
      return true;
    }

    // const request = context.switchToHttp().getRequest();
    // const user = request.user;

    // const dbUser = await this.prismaService.user.findUnique({
    //   where: { id: user.id },
    //   include: {
    //     role: {
    //       include: { permissions: true },
    //     },
    //   },
    // });
    // if (!dbUser) {
    //   throw new ForbiddenException(
    //     "You don't have permission to access this resource",
    //   );
    // }
    // console.log(dbUser);

    // const permissions = dbUser.role.map((role) => role.permissions).flat();

    // const isPresent = permissions.map((res) =>
    //   res.resource === resource ? res : null,
    // );
    const isPresent = [];
    console.log(isPresent, 'isPresent');

    if (isPresent.length <= 0) {
      throw new ForbiddenException(
        "You don't have permission to access this resource",
      );
    }
    const action = isPresent.map((res) =>
      res?.actions.includes(permission) ? true : false,
    );
    if (!action) {
      throw new ForbiddenException(
        "You don't have permission to access this resource",
      );
    } else {
      return true;
    }
  }
}
