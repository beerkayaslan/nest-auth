import { HttpException, Injectable } from '@nestjs/common';
import { LoginDto } from './dto/login.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';
import { RegisterDto } from './dto/register.dto';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
    constructor(
        @InjectModel(User.name) private UserModel: Model<User>,
        private jwtService: JwtService
    ) { }

    async validateUser(LoginDto: LoginDto): Promise<string> {
        const { email, password } = LoginDto;

        const user = await this.UserModel.findOne({ email, password });

        if (!user) {
            throw new HttpException('Invalid credentials', 401);
        }

        const payload = { email: user.email };

        return await this.jwtService.signAsync(payload);
    }

    async registerUser(RegisterDto: RegisterDto) {
        const { email, password } = RegisterDto;

        const user = await this.UserModel.findOne({ email });

        if (user) {
            throw new HttpException('User already exists', 409);
        }

        const newUser = new this.UserModel({ email, password });

        return await newUser.save();

    }
}
