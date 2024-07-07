import {
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { TokenExpiredError } from '@nestjs/jwt';
import { AuthGuard } from '@nestjs/passport';
import { type Observable } from 'rxjs';

/**
 * JwtAuthGuard
 *
 */
@Injectable()
export class JwtRefreshGuard extends AuthGuard('jwt-refresh') {
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

  handleRequest(err: any, user: any, info: Error) {
    console.log(info);
    if (err || !user || info) {
      if (info instanceof TokenExpiredError) {
        throw new UnauthorizedException('Token expired');
      }
      throw err || new UnauthorizedException();
    }

    return user;
  }
}
