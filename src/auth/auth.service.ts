import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { RegisterUserDto } from './dto';
import * as bcrypt from 'bcrypt';
@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  onModuleInit() {
    this.$connect();
    this.logger.log('MongoDB Connected');
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { email, name, password } = registerUserDto;
    try {
      const user = await this.user.findUnique({ where: { email } });

      if (user) {
        throw new RpcException({ status: 400, message: 'User already exist' });
      }

      const createdUser = await this.user.create({
        data: {
          email,
          name,
          password: bcrypt.hashSync(password, 10),
        },
      });

      const { password: _, ...rest } = createdUser;

      return { user: rest };
    } catch (error) {
      console.log('error.message :', error.message);
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }
}
