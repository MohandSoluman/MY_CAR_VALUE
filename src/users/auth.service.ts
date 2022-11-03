import { BadRequestException, Injectable } from "@nestjs/common";
import { randomBytes ,scrypt as _scrypt} from "crypto";
import { promisify } from "util";
import { UsersService } from "./users.service";
const scrypt = promisify(_scrypt);

@Injectable()
export class AuthService{
    constructor(private userservice:UsersService){}


   async signUp(email:string,password:string){
       try{ //1)check if email in use 
        const users = await this.userservice.find(email);
        if(users.length){
            throw new BadRequestException('email in use')
        }
        //2)hash password
        //--generate salt
        const salt =randomBytes(8).toString('hex');
        //-- hash the salt and the password together
        const hash=(await scrypt(password,salt,32)) as Buffer
        //--join hash and salt
        const result = salt + '.' + hash.toString('hex'); 
        //3) create new user
        const user =await this.userservice.create(email,result);

        return user ;
        }catch(err){
            console.log(err);
            
        }
    }

    async signIn(email:string,password:string){
        try {
            
            const [user] = await this.userservice.find(email);
            
            if(!user){
                throw new BadRequestException('user not found');
            }
            
            const [salt,storedHash]=user.password.split('.');
            
            const hash =( await scrypt(password,salt,32)) as Buffer;
            
            if ( storedHash !== hash.toString('hex') ){
                throw new BadRequestException('in  correct passw0rd');
            }
            
            return user;
        } catch (error) {
            console.log(error);    
        }


    }
}