import { Body, Controller, HttpCode, HttpStatus, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dtos/auth.dto';
import { Tokens } from './types';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';

@Controller('auth')
export class AuthController {

    constructor(private readonly authService: AuthService) {}

    @Post('/signup')
    signup(@Body() dto: AuthDto): Promise<Tokens> {
        return this.authService.signup(dto);
    }

    @Post('/signin')
    signin(@Body() dto: AuthDto): Promise<Tokens> {
        return this.authService.signin(dto);
    }

    @UseGuards(AuthGuard('jwt')) // has to be the same as the one in the access token strategy
    @Post('/signout')
    @HttpCode(HttpStatus.OK)
    signout(@Req() request: Request): Promise<void> {
        const user = request.user;
        return this.authService.signout(user['sub']);
    }

    @UseGuards(AuthGuard('jwt-refresh-token')) // has to be the same as the one in the refresh token strategy
    @Post('/refreshtoken')
    refreshtoken() {
        return this.authService.refreshtoken();
    }
}
