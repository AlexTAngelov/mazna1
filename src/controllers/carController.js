import { Router } from 'express';
import carService from '../services/carService.js';
import { getErrorMessage } from '../utils/errorUtils.js';
import { isAuth } from '../middlewares/authMiddleware.js';


const carController = Router();

carController.get('/', async (req, res) => {
    const cars = await carService.getAll().lean();
    console.log(cars);
    res.render('car', { cars, title: 'Inventory'});
});

carController.get('/:carId/details', async (req, res) => {
    const carId = req.params.carId;
    const car = await carService.getOne(carId).lean();

    const isOwner = car.owner && car.owner.toString() === req.user?._id;

    res.render('car/details', {car, isOwner, title: 'Details Page'});
});

carController.get('/create', (req, res) => {
    res.render('car/create', {title: 'Create Page'});
});

carController.post('/create', async (req, res) => {
    const carData = req.body;
    const userId = req.user._id;

    try {
        await carService.create(carData, userId);
        res.redirect('/car');
    } catch (err) {
        const error = getErrorMessage(err);
        console.log(error);
        return res.render('car/create', {car: carData, error, title: 'Create Page'});
    }

});

carController.get('/search', async (req, res) => {
    const cars = await carService.getAll().lean();

    res.render('car/search', {title: 'Search Page', cars});
});

carController.get('/:carId/edit', isAuth, async(req, res) => {
    const carId = req.params.carId;
    const car = await carService.getOne(carId).lean();

    res.render('car/edit', {car, title: 'Edit Page'});
});

carController.post('/:carId/edit', isAuth, async(req, res) => {
    const carData = req.body;
    const carId = req. params.carId;

    await carService.edit(carId, carData);

    res.redirect(`/car/${carId}/details`);
});

carController.get('/:carId/delete', isAuth, async (req, res) => {
    const carId = req.params.carId;
    const car = await carService.getOne(carId).lean();

    if(car.owner?.toString() !== req.user._id){
        res.setError('You cannot delete this car!');
        return res.redirect('/404');
    };

    await carService.delete(carId);

    res.redirect('/');
});
export default carController;