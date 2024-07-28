import { ConflictException, Injectable , HttpException} from '@nestjs/common';
import * as argon2 from "argon2";
import * as jwt from "jsonwebtoken";
import { PrismaService } from 'src/prisma/prisma.service';
import { UserType } from '@prisma/client';

interface SignupParams {
    email: string;
    password:string;
    name: string;
    phone: string
}
interface SignInParams {
    email: string;
    password:string
  
}
@Injectable()
export class AuthService {
    constructor (private readonly prismaService:PrismaService) {}

 async signup( 
    { email, password, name, phone }: SignupParams, userType: UserType)
    {
    const userExists = await this.prismaService.user.findUnique({
        where:{
            email
        },
    });
        if (userExists) {
            throw new ConflictException()
        }
        const hashedPassword = await argon2.hash(password)
        const  user =  await this.prismaService.user.create({
            data: {
                email,
                name,
                phone,
                password: hashedPassword,
                user_type: userType

            },
        });
        return this.generateJWT(name, user.id)
        
    }


    async signin({email, password}:SignInParams){
        const user = await this.prismaService.user.findUnique({
            where:{
                email,
            },
        });
        if (!user) {
            throw new HttpException('Invalid credentials',400);

        }

        const hashedPassword = user.password;
        const isValidPassword = await argon2.verify(hashedPassword, password)

        if(!isValidPassword){
            throw new HttpException(' Invalid credentials', 400);
        }
        return this.generateJWT(user.name , user.id);
        

    }

   private   generateJWT (name:string, id:number){
        return jwt.sign({
            name, 
            id
        },process.env.JSON_TOKEN_KEY,
         {
            expiresIn:36000000
        },
    );
    };

    generateProductKey(email: string, userType:UserType){
        const string = `${email}-${userType}-${process.env.PRODUCT_KEY_SECRET}`;
        return argon2.hash(string)
    }
}
