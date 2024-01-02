import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import prisma from "../utils/prismaInstance";
import {routeErrorHandler} from "../utils/routeErrorHandler";
const JWT_SECRET = process.env.JWT_SECRET as string;

export async function checkUserExists(req: Request, res: Response, next: NextFunction) {
    const { email } = req.body;
    try {
        const user = await prisma.user.findUnique({
            where: { email },
        });
        if (user) {
            return res.status(409).json({ message: 'User already exists' });
        }
        next();
    } catch (error) {
        routeErrorHandler("check user middleware", error, res)
    }
}

export function decodeToken(req: Request, res: Response, next: NextFunction) {
    const token = req.headers.authorization?.split(' ')[1]; // Assumes token is sent in the Authorization header

    if (!token) {
        return res.status(401).json({ message: "No token provided" });
    }
    try {
        req.body.decodedToken =  jwt.verify(token, JWT_SECRET) as JwtPayload;
        next();
    } catch (error) {
        routeErrorHandler("decode token middleware", error, res)
    }
}

export async function checkRefreshToken(req: Request, res: Response, next: NextFunction) {
    const { refreshToken } = req.body;
    if (!refreshToken) {
        return res.status(401).json({ message: "Refresh token is required" });
    }
    try {
        const decoded = jwt.verify(refreshToken, JWT_SECRET) as jwt.JwtPayload;
        const storedToken = await prisma.refreshToken.findUnique({
            where: { token: refreshToken },
        });

        if (!storedToken || !storedToken.valid) {
            return res.status(401).json({ message: "Invalid or expired refresh token" });
        }
        req.body.user = { id: decoded.profileId };

        next();
    } catch (error) {
        routeErrorHandler("refresh token middleware", error, res)
    }
}

