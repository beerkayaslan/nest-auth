import { HttpException, Injectable, UnauthorizedException } from '@nestjs/common';
import { LoginDto } from './dto/login.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';
import { RegisterDto } from './dto/register.dto';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class AuthService {
    constructor(
        @InjectModel(User.name) private UserModel: Model<User>,
        private jwtService: JwtService
    ) { }

    async loginUser(LoginDto: LoginDto) {
        const { email, password } = LoginDto;


        const user = await this.UserModel.findOne({ email });

        if (!user) {
            throw new HttpException('Invalid credentials', 401);
        }

        const isMatchPassword = await bcrypt.compare(password, user.password);

        if (!isMatchPassword) {
            throw new HttpException('Invalid credentials', 401);
        }

        const acces_token = await this.jwtService.signAsync({
            email: user.email,
            sub: user._id,
        }, {
            secret: "acces_token_secret_key",
            expiresIn: "10s",
        });

        const refresh_token = await this.jwtService.signAsync({
            email: user.email,
            sub: user._id,
        }, {
            secret: "refresh_token_secret_key",
            expiresIn: "15s",
        });

        const response = {
            user: {
                email: user.email,
            },
            acces_token,
            refresh_token
        }

        return response;
    }

    async registerUser(RegisterDto: RegisterDto) {
        const { email, password } = RegisterDto;

        const user = await this.UserModel.findOne({ email });

        if (user) {
            throw new HttpException('User already exists', 409);
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new this.UserModel({ email, password: hashedPassword });

        await newUser.save();

        // const token = this.jwtService.sign({ email });

        return await { email };

    }

    async refreshToken(refreshToken: string) {

        try {
            const payload = await this.jwtService.verifyAsync(refreshToken, {
                secret: "refresh_token_secret_key",
            });


            if (!payload) {
                throw new HttpException('Invalid token', 401);
            }

            const acces_token = await this.jwtService.signAsync({
                email: payload.email,

            }, {
                secret: "acces_token_secret_key",
                expiresIn: "10s",
            });

            const refresh_token = await this.jwtService.signAsync({
                email: payload.email,
            }, {
                secret: "refresh_token_secret_key",
                expiresIn: "15s",
            });

            const response = {
                user: {
                    email: payload.email,
                },
                acces_token,
                refresh_token
            }

            return response;


        } catch {
            throw new UnauthorizedException();
        }

    }
}
