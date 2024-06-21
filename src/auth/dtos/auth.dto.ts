import { IsEmail, IsNotEmpty, MaxLength, MinLength } from 'class-validator';

export class AuthDto {
    @IsEmail({}, { message: 'Invalid email' })
    @IsNotEmpty({ message: 'Invalid email' })
    email: string;

    @IsNotEmpty({ message: 'Password is required'})
    @MaxLength(20, {message: 'Password cannot be more than 20 characters'})
    @MinLength(8, {message: 'Password cannot be less than 8 characters'})
    password: string;
}