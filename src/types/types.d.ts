import { Request } from 'express';
import jwt from "jsonwebtoken";

declare module 'express-serve-static-core' {
    interface Request {
        user?: { id: number };
        decodedToken?: jwt.JwtPayload;// Define the type of the user object
    }
}
