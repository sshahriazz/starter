import { SetMetadata } from '@nestjs/common';

export const Resource = (args: string) => SetMetadata('resource', args);
