import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dtos/auth.dto';
import { Tokens } from './types';

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

    @Post('/signout')
    signout() {
        return this.authService.signout();
    }

    @Post('/refreshtoken')
    refreshtoken() {
        return this.authService.refreshtoken();
    }
}
