import { IsArray, IsNotEmpty, IsString } from 'class-validator';

export class PermissionsDto {
  @IsString()
  @IsNotEmpty()
  resource: string;

  @IsArray()
  @IsString({ each: true })
  @IsNotEmpty({ each: true })
  actions: string[];
}
