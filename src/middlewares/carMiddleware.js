import Car from '../models/Car.js';
import User from '../models/User.js';

export const checkCarOwnership = async (req, res, next) => {
    try {
        const carId = req.params.id;
        const car = await Car.findById(carId);
        
        if (!car) {
            return res.status(404).json({ message: 'Car not found' });
        }

        const user = await User.findById(req.user._id);
        
        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }

        // Admin can do anything
        if (user.isAdmin()) {
            req.car = car;
            return next();
        }

        // Check if user owns the car
        if (car.owner.toString() === req.user._id.toString()) {
            req.car = car;
            return next();
        }

        res.status(403).json({ message: 'You do not have permission to modify this car' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
};

export const canDeleteCar = async (req, res, next) => {
    try {
        const user = await User.findById(req.user._id);
        
        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }

        // Admin can delete any car
        if (user.isAdmin()) {
            return next();
        }

        // Regular users can only delete their own cars
        const car = await Car.findById(req.params.id);
        if (!car) {
            return res.status(404).json({ message: 'Car not found' });
        }

        if (car.owner.toString() === req.user._id.toString()) {
            return next();
        }

        res.status(403).json({ message: 'You can only delete your own cars' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
}; 