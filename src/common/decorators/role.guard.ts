import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';

@Injectable()
export class RoleGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  matchesRoles(roles: string[], userRole: string[]): boolean {
    return userRole.every((role) => roles.includes(role));
  }
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const roles = this.reflector.get<string[]>('roles', context.getHandler());
    const isPublic = this.reflector.get<boolean>(
      'isPublic',
      context.getHandler(),
    );

    if (isPublic) {
      return true;
    }

    if (!roles) {
      return true;
    }
    const request = context.switchToHttp().getRequest();
    const user = request.user;
    const isPresent = this.matchesRoles(roles, user.role);
    console.log(user.role, roles);

    if (isPresent) {
      return true;
    } else {
      throw new ForbiddenException(
        "You don't have permission to access this resource",
      );
    }
  }
}
