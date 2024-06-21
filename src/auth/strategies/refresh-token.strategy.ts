import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { Request } from "express";
import { Injectable } from "@nestjs/common";

@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, 'jwt-refresh-token') {
    constructor() {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: 'secret', // or from an environment variable
            passReqToCallback: true // to access the request object in the validate method to hash the refresh token
        });
    }
    validate(request: Request, payload: any) {
        const refreshToken = request.headers.authorization.split(' ')[1];
        return {...payload, refreshToken};
    }
}