import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { DatabaseService } from 'src/database/database.service';
import { AuthDto } from './dtos/auth.dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {

    constructor(private readonly databaseservice: DatabaseService,
        private readonly jwtService: JwtService
    ) {}

    hashData(data: string): Promise<string> {
        return bcrypt.hash(data, 10);
    }

    async generateTokens(userId: string, email: string): Promise<Tokens> {
        const [at, rt] = await Promise.all([this.jwtService.signAsync({ sub:userId, email },
            {
                secret: 'secret',
                expiresIn: '1h'
            }
        ), this.jwtService.signAsync({ sub:userId, email },
            {
                secret: 'secret',
                expiresIn: '7d'
            }
        )]);

        return { accessToken: at, refreshToken: rt };
    }

    async updateRThash(userId: string, refreshToken: string): Promise<void> {
        const hashedRefreshToken = await this.hashData(refreshToken);
        await this.databaseservice.user.update({
            where: {
                id: userId
            },
            data: {
                hashedRT: hashedRefreshToken
            }
        });
    }

    async signup(user: AuthDto): Promise<Tokens> {

        const userExists = await this.databaseservice.user.findUnique({
            where: {
                email: user.email
            }
        });

        if (userExists) {
            throw new HttpException('User already exists', HttpStatus.BAD_REQUEST);
        }

        const hashedPassword = await this.hashData(user.password);

        const newUser = this.databaseservice.user.create({
            data: {
                email: user.email,
                hashedPassword: hashedPassword
            }
        }); 

        const tokens = await this.generateTokens((await newUser).id, (await newUser).email);

        await this.updateRThash((await newUser).id, tokens.refreshToken);

        return tokens;
    }

    async signin() {
        return 'signin';
    }

    async signout() {
        return 'signout';
    }

    async refreshtoken() {
        return 'refreshtoken';
    }
}
