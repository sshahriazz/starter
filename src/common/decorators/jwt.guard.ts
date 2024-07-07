import {
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard, IAuthModuleOptions } from '@nestjs/passport';
import { type Observable } from 'rxjs';

/**
 * JwtAuthGuard
 *
 */
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt-access') {
  constructor(private reflector: Reflector) {
    super();
  }
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    // Add your custom authentication logic here
    // for example, call super.logIn(request) to establish a session.
    // check form matching role

    const isPublic = this.reflector.get<boolean>(
      'isPublic',
      context.getHandler(),
    );

    if (isPublic) {
      return true;
    }

    return super.canActivate(context);
  }

  handleRequest(err: any, user: any, info: any, context: any, status: any) {
    console.log(info, context, status);

    if (err || !user || info) {
      throw err || new UnauthorizedException();
    }

    return user;
  }
}
