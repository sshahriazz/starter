import { Body, Controller, Get, Put, Query } from '@nestjs/common';
import { UserService } from './user.service';

import { ApiBearerAuth, ApiQuery, ApiResponse, ApiTags } from '@nestjs/swagger';
import { UserResponseDto } from './dto/user-response.dto';
import { UserListDto } from './dto/user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
// import { JwtAuthGuard } from '@/common/decorators/jwt.guard';

@Controller('user')
@ApiTags('user')
@ApiBearerAuth()
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Put('update')
  async updateUser(
    @Body() userUpdateDto: UpdateUserDto,
  ): Promise<UserResponseDto> {
    return await this.userService.updateUser(userUpdateDto);
  }

  @Get('find')
  @ApiResponse({ type: UserResponseDto })
  async findUser(@Query('id') id: string): Promise<UserResponseDto> {
    return await this.userService.findUser(id);
  }

  @Get('find-by-email')
  async findUserByEmail(
    @Query('email') email: string,
  ): Promise<UserResponseDto> {
    return await this.userService.findUserByEmail(email);
  }

  @Get('list')
  @ApiQuery({
    name: 'take',
    required: false,
    type: Number,
    description: 'Number of users to take',
  })
  @ApiQuery({
    name: 'cursor',
    required: false,
    type: String,
    description: 'Cursor for pagination',
  })
  @ApiQuery({
    name: 'sortColumn',
    required: false,
    type: String,
    description: 'Column to sort by',
  })
  @ApiQuery({
    name: 'sortOrder',
    required: false,
    type: String,
    description: 'Sort order',
  })
  // @UseGuards(JwtAuthGuard)
  async listUsers(
    @Query('take') take: number,
    @Query('cursor') cursor: string,
    @Query('sortColumn')
    sortColumn: 'created_at' | 'first_name' | 'last_name' | 'email',
    @Query('sortOrder') sortOrder: 'asc' | 'desc',
  ): Promise<UserListDto> {
    return await this.userService.listUsers(
      take,
      cursor,
      sortColumn,
      sortOrder,
    );
  }
}
