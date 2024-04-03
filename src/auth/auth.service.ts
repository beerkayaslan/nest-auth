import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { LoginDto } from './dto/login.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';
import { RegisterDto } from './dto/register.dto';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import config from '../config';

@Injectable()
export class AuthService {
    constructor(
        @InjectModel(User.name) private UserModel: Model<User>,
        private jwtService: JwtService
    ) { }

    async loginUser(LoginDto: LoginDto) {
        try {
            const { email, password } = LoginDto;
            const user = await this.UserModel.findOne({ email });

            if (!user) {
                throw new BadRequestException('Invalid credentials');
            }

            const isMatchPassword = await bcrypt.compare(password, user.password);

            if (!isMatchPassword) {
                throw new BadRequestException('Invalid credentials');
            }

            const { access_token, refresh_token } = await this.createToken(user.email);

            const hashedRefreshToken = await bcrypt.hash(refresh_token, 10);

            await this.UserModel.findOneAndUpdate({ email: user.email }, { refresh_token: hashedRefreshToken }, { new: true });

            return {
                user: {
                    email: user.email,
                },
                access_token,
                refresh_token
            }
        } catch {
            throw new BadRequestException('Invalid credentials');
        }
    }

    async registerUser(RegisterDto: RegisterDto) {
        try {
            const { email, password } = RegisterDto;

            const user = await this.UserModel.findOne({ email });

            if (user) {
                throw new BadRequestException('User already exists');
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            const newUser = new this.UserModel({ email, password: hashedPassword });

            await newUser.save();

            return { email };
        }
        catch {
            throw new BadRequestException('Invalid credentials');
        }
    }

    async refreshToken(refreshToken: string) {
        try {

            const payload = await this.jwtService.verifyAsync(refreshToken, {
                secret: config().REFRESH_TOKEN_SECRET,
            });

            if (!payload) {
                throw new BadRequestException('Invalid token');
            }

            const user = await this.UserModel.findOne({ email: payload.email });

            if (!user) {
                throw new BadRequestException('Invalid token');
            }

            const isMatch = await bcrypt.compare(refreshToken, user.refresh_token);

            if (!isMatch) {
                throw new BadRequestException('Invalid token');
            }

            const { access_token, refresh_token } = await this.createToken(payload.email);

            const hashedRefreshToken = await bcrypt.hash(refresh_token, 10);

            await this.UserModel.findOneAndUpdate({ email: user.email }, { refresh_token: hashedRefreshToken }, { new: true });

            return {
                user: {
                    email: payload.email,
                },
                access_token,
                refresh_token
            }
        } catch {
            throw new UnauthorizedException();
        }
    }

    async me(accesToken: string) {
        try {
            const payload = await this.jwtService.verifyAsync(accesToken, {
                secret: config().ACCESS_TOKEN_SECRET,
            });

            return payload;
        } catch {
            throw new UnauthorizedException();
        }
    }

    async createToken(email: string) {
        try {
            const access_token = await this.jwtService.signAsync({
                email
            }, {
                secret: config().ACCESS_TOKEN_SECRET,
                expiresIn: "1h",
            });

            const refresh_token = await this.jwtService.signAsync({
                email
            }, {
                secret: config().REFRESH_TOKEN_SECRET,
                expiresIn: "7d",
            });

            return { access_token, refresh_token };
        } catch {
            throw new Error('Error creating token');
        }
    }
}