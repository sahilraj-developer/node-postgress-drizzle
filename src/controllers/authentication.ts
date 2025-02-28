import express from 'express';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import { createUser, getUserByEmail } from '../db/users';

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRY = '1h'; // Token expiration time
const SALT_ROUNDS = 10; // Number of salt rounds for bcrypt

if (!JWT_SECRET) {
    throw new Error("JWT_SECRET is not defined in the environment variables.");
}

export const register = async (req: express.Request, res: express.Response) => {
    try {
        const { username, email, password } = req.body;
        console.log(req.body);

        if (!username || !email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        const existingUsers = await getUserByEmail(email);
        if (existingUsers.length > 0) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash the password using bcrypt
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        const user: any = await createUser({
            username,
            email,
            password: hashedPassword,
        });

        if (!user || !user.id || !user.email) {
            return res.status(500).json({ message: 'User creation failed' });
        }

        // Generate JWT token
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
            expiresIn: JWT_EXPIRY,
        });

        return res.status(201).json({ message: 'User registered successfully', user, token });
    } catch (error) {
        console.error('Register Error:', error);
        return res.status(500).json({ message: 'Internal Server Error' });
    }
};

export const login = async (req: express.Request, res: express.Response) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const users = await getUserByEmail(email);
        if (users.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const user = users[0];

        if (!user || !user.password) {
            return res.status(500).json({ message: 'User data is incomplete' });
        }

        // Compare the hashed password with the provided password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(403).json({ message: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
            expiresIn: JWT_EXPIRY,
        });

        return res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        console.error('Login Error:', error);
        return res.status(500).json({ message: 'Internal Server Error' });
    }
};
