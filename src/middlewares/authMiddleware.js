import { AUTH_COOKIE_NAME } from "../constants.js"
import jwt from "../lib/jwt.js";
import User from '../models/User.js';

export const authMiddleware = async (req, res, next) => {
    const token = req.cookies[AUTH_COOKIE_NAME];

    if(!token){
        return next();
    }

    try {
        const decodetToken = await jwt.verify(token, process.env.JWT_SECRET);

        req.user = decodetToken;
        req.isAuthenticated = true;
        res.locals.user = decodetToken;
        res.locals.isAuthenticated = true;
        
        next()
    } catch (err) {
        res.clearCookie(AUTH_COOKIE_NAME);

        res.redirect('/auth/login');
    }
}

export const isAuth = (req, res, next) => {
    if(!req.user){
        return res.redirect('/auth/login');
    };
    next()
}

export const checkPermission = (permission) => {
    return async (req, res, next) => {
        try {
            // Assuming user is attached to req by your authentication middleware
            const user = await User.findById(req.user._id);
            
            if (!user) {
                return res.status(401).json({ message: 'User not found' });
            }

            if (user.hasPermission(permission)) {
                next();
            } else {
                res.status(403).json({ message: 'Permission denied' });
            }
        } catch (error) {
            res.status(500).json({ message: 'Server error' });
        }
    };
};

export const isAdmin = async (req, res, next) => {
    try {
        const user = await User.findById(req.user._id);
        
        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }

        if (user.isAdmin()) {
            next();
        } else {
            res.status(403).json({ message: 'Admin access required' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
};