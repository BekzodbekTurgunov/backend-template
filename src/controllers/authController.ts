import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import useragent from 'useragent';
import jwt from 'jsonwebtoken';
import {routeErrorHandler} from "../utils/routeErrorHandler";
import prisma from "../utils/prismaInstance";
const JWT_SECRET = process.env.JWT_SECRET as string;
const ACCESS_TOKEN_LIFE = process.env.ACCESS_TOKEN_LIFE || '15m';
const REFRESH_TOKEN_LIFE = process.env.REFRESH_TOKEN_LIFE || '7d';

export async function register(req: Request, res: Response) {
    const { email, password, role = 'USER' } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await prisma.user.create({
            data: {
                email,
                password: hashedPassword,
                profiles: {
                    create: [{ role, isActive: true }]
                }
            },
        });
        res.status(201).json({ message: 'User created', userId: user.id });
    } catch (error) {
        routeErrorHandler("Register", error, res)
    }
}

export async function login(req: Request, res: Response) {
    const { email, password, role } = req.body;
    const agent = useragent.parse(req.headers['user-agent']);
    try {
        const user = await prisma.user.findUnique({
            where: { email },
            include: { profiles: true }
        });
        if (!user) return res.status(404).json({ message: 'User not found' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

        const selectedProfile = user.profiles.find((profile) => profile.role === role);
        if (!selectedProfile) {
            return res.status(401).json({ message: `No profile found with the specified role: ${role}` });
        }

        const accessToken = jwt.sign(
            { userId: user.id, email: user.email, profileId: selectedProfile.id, role: selectedProfile.role },
            JWT_SECRET,
            { expiresIn: ACCESS_TOKEN_LIFE }
        );

        const refreshToken = jwt.sign(
            { profileId: selectedProfile.id },
            JWT_SECRET,
            { expiresIn: REFRESH_TOKEN_LIFE }
        );

        await prisma.refreshToken.create({
            data: {
                token: refreshToken,
                profileId: selectedProfile.id,
                userAgent: agent.toString(),
                valid: true,
            },
        });

        res.status(200).json({
            accessToken,
            refreshToken,
            message: 'Logged in successfully'
        });
    } catch (error) {
        routeErrorHandler("login", error, res);
    }
}
export async function viewSessions(req: Request, res: Response) {
    // @ts-ignore
    const userId = req.user.id;  // Assuming you have user info in req.user
    try {
        const profiles = await prisma.profile.findMany({
            where: { userId },
            include: { refreshTokens: true }
        });
        const sessionsInfo = profiles.map((profile) => ({
            role: profile.role,
            sessions: profile.refreshTokens.filter(token => token.valid).map(token => ({
                id: token.id,
                role: profile.role,
                userAgent: token.userAgent,
                createdAt: token.createdAt
            }))
        }));

        res.status(200).json(sessionsInfo);
    } catch (error) {
        routeErrorHandler("viewSessions", error, res);
    }
}




export async function refresh(req: Request, res: Response) {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(401).json({ message: "Refresh Token is required!" });
    }

    try {
        const storedToken = await prisma.refreshToken.findUnique({
            where: { token: refreshToken },
            include: { profile: true }
        });

        if (!storedToken || !storedToken.valid || !storedToken.profile) {
            return res.status(401).json({ message: "Invalid or expired refresh token" });
        }

        const newAccessToken = jwt.sign(
            { userId: storedToken.profile.userId, profileId: storedToken.profileId, role: storedToken.profile.role},
            JWT_SECRET,
            { expiresIn: ACCESS_TOKEN_LIFE }
        );
        const newRefreshToken = jwt.sign(
            { profileId: storedToken.profileId },
            JWT_SECRET,
            { expiresIn: REFRESH_TOKEN_LIFE }
        );
        await prisma.refreshToken.update({
            where: { id: storedToken.id },
            data: { token: newRefreshToken, valid: true, userAgent: useragent.parse(req.headers['user-agent']).toString() }
        });

        res.status(200).json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
        });

    } catch (error) {
        routeErrorHandler("refresh", error, res);
    }
}

export async function logout(req: Request, res: Response) {
    const { refreshToken } = req.body;

    try {
        // Check if the refresh token is in the database
        const token = await prisma.refreshToken.findUnique({
            where: { token: refreshToken },
        });

        if (token) {
            // Invalidate the refresh token
            await prisma.refreshToken.update({
                where: { token: refreshToken },
                data: { valid: false },
            });
        }

        // Respond to the client that the user has been logged out
        res.status(200).json({ message: 'Logged out successfully' });
    } catch (error) {
        routeErrorHandler("logout", error, res);
    }
}