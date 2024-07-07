import { HttpStatus, Logger, Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_FILTER, APP_GUARD, HttpAdapterHost } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import {
  PrismaClientExceptionFilter,
  PrismaModule,
  QueryInfo,
  loggingMiddleware,
} from 'nestjs-prisma';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import config from './common/configs/config';

@Module({
  imports: [
    ThrottlerModule.forRoot([
      {
        ttl: 6000,
        limit: 10,
      },
    ]),
    ConfigModule.forRoot({
      isGlobal: true,
      load: [config],
      envFilePath: ['.env.local', '.env'],
    }),
    PrismaModule.forRoot({
      isGlobal: true,
      prismaServiceOptions: {
        middlewares: [
          loggingMiddleware({
            logger: new Logger('PrismaMiddleware'),
            logLevel: 'log', // default is `debug`
            logMessage: (query: QueryInfo) =>
              `[DB_Q:] ${query.model}:${query.action} - ${query.executionTime}ms`,
          }),
        ],
      },
    }),
    UserModule,
    AuthModule,
  ],
  controllers: [],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    {
      provide: APP_FILTER,
      useFactory: ({ httpAdapter }: HttpAdapterHost) => {
        return new PrismaClientExceptionFilter(httpAdapter, {
          P2000: HttpStatus.BAD_REQUEST,
          P2002: HttpStatus.CONFLICT,
          P2025: HttpStatus.NOT_FOUND,
        });
      },
      inject: [HttpAdapterHost],
    },
  ],
})
export class AppModule {}
