import { Body, Controller, Get, Param, ParseEnumPipe, Post, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { GenerateProductKeyDto, SigninDto, SignupDto } from '../dto/auth.dto';
import * as argon2 from "argon2";
import { UserType } from '@prisma/client';



@Controller('auth')
export class AuthController {
    constructor(private readonly authService:AuthService){}
  
    @Post('/signup/:userType')
    async signup(
      @Body() body: SignupDto,
      @Param('userType', new ParseEnumPipe(UserType)) userType: UserType,
    ) {
      if (userType !== UserType.BUYER ){
        if (!body.productKey) {
          throw new UnauthorizedException();
        }
  
        const validProductKey = `${body.email}-${userType}-${process.env.PRODUCT_KEY_SECRET}`;
       
  
        const isValidProductKey = await argon2.verify(
          body.productKey,
          validProductKey
          
        );
  
        if (!isValidProductKey) {
          throw new UnauthorizedException();
        }
      }
  
      return this.authService.signup(body, userType);
    }


    @Post('/signin')
    signin(@Body() body:SigninDto){
        return this.authService.signin(body);
    }

    @Post("/key") 
    generateProductKey(@Body() {email, userType}:GenerateProductKeyDto){
        return this.authService.generateProductKey(email, userType )
    }
}
