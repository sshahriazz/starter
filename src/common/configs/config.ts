import type { Config } from './config.interface';

const config: Config = {
  nest: {
    port: parseInt(process.env.NEST_PORT) || 4000,
    url: process.env.NEST_URL || 'http://localhost:4000',
    defaultPageSize: parseInt(process.env.PAGE_SIZE) || 60,
  },
  s3: {
    region: process.env.S3_REGION || 'us-east-2',
    accessKeyId: process.env.S3_ACCESS_KEY_ID,
    bucketName: process.env.S3_BUCKET_NAME || 'counter-top-storage',
    secretAccessKey: process.env.S3_SECRET_ACCESS_KEY,
    bucketUrl:
      process.env.S3_BUCKET_URL ||
      'https://counter-top-storage.s3.us-east-2.amazonaws.com/',
  },
  cors: {
    enabled: true,
    origins: [
      'http://localhost:3000',
      'http://localhost:4000',
      'https://absolutegm.com',
      'https://shop.absolutegm.com',
      'https://api.absolutegm.com',
      'https://counter-top-web.vercel.app/',
      'https://4z332rgjibttqqgvblv4i6nuiy.srv.us/',
    ],
  },
  mail: {
    clientId:
      '979855681822-ogjn6q5cupbcbu3m3hblvctcl4produs.apps.googleusercontent.com',
    clientSecret: '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',
    email: 'shahriazkobir@gmail.com',
    refreshToken:
      '1//04MhPF4AK9zjyCgYIARAAGAQSNwF-L9Ir4e0hPgPnBTr1dE6wENGvOMPdMXu1bJcW6tSkhUb-aw_xfHUj_uT5xHpHI8hS9AT1zFg',
  },
  db: {
    database: 'counter-top-dev',
    host: 'localhost',
    password: '',
    port: 3306,
    type: 'mysql',
    username: 'root',
  },
  swagger: {
    enabled: process.env.NODE_ENV === 'production' ? false : true,
    title: 'Counter Top Platform API',
    description:
      'The Counter Top Platform API For managing the products and orders',
    version: '0.5-dev',
    path: 'api',
  },
  session: {
    resave: false,
    saveUninitialized: false,
    secret: 'my-secret',
  },
  security: {
    expiresIn: '30m',
    refreshIn: '7d',
    bcryptSaltOrRound: 10,
    refreshSecret: 'my-refresh-secret',
    accessSecret: 'my-access-secret',
    jwtSecret: 'my-jwt-secret',
  },
};

export default (): Config => config;
