import { Controller, Get, UseGuards, Post, Body, Headers } from '@nestjs/common';
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
  async refresh(@Body() refreshToken: { token: string }) {
    return this.authService.refreshToken(refreshToken.token);
  }

  @Get('me')
  @UseGuards(AuthGuard)
  async me(@Headers('Authorization') authorizationHeader: string){
    const accessToken = authorizationHeader.split(' ')[1];
    return this.authService.me(accessToken);
  }

}