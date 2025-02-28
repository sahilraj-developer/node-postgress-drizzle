import express from 'express';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { getUserByEmail } from '../db/users';

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    throw new Error("JWT_SECRET is not defined in the environment variables.");
}

// Extend Express Request Type to include `user`
declare module 'express-serve-static-core' {
    interface Request {
        user?: any; // Replace `any` with your user type if available
    }
}

export const isAuthenticated = async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(403).json({ message: "Access Denied: No token provided" });
        }

        const token = authHeader.split(" ")[1]; // Extract JWT token

        // Verify token
        const decoded = jwt.verify(token, JWT_SECRET) as { id: string; email: string };

        if (!decoded || !decoded.email) {
            return res.status(403).json({ message: "Invalid token" });
        }

        // Get user from database
        const user = await getUserByEmail(decoded.email);
        if (!user || user.length === 0) {
            return res.status(403).json({ message: "User not found" });
        }

        req.user = user[0]; // ✅ Now TypeScript recognizes `req.user`

        return next();
    } catch (error) {
        console.error("Authentication Error:", error);
        return res.status(401).json({ message: "Unauthorized: Invalid or expired token" });
    }
};
