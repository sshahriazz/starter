import { User } from '@prisma/client';

export class UserResponseDto implements User {
  id: string;
  email: string;

  first_name: string;
  last_name: string;
  password: string;
  email_verified: boolean;
  disable_access: boolean;
  avatar: string;
  created_at: Date;
  updated_at: Date;
}
