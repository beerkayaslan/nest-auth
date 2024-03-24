import { Controller, Get, UseGuards, Request, Post, Body } from '@nestjs/common';
import { LoginDto } from './dto/login.dto';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { AuthGuard } from './auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    return this.authService.loginUser(loginDto);
  }

  @Post('register')
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.registerUser(registerDto);
  }

  @Post('refresh')
  async refresh(@Body() refreshToken: { refresh_token: string }) {
    return this.authService.refreshToken(refreshToken.refresh_token);
  }

  @Get('profile')
  @UseGuards(AuthGuard)
  async profile(@Request() req) {
    return req.user;
  }
}
