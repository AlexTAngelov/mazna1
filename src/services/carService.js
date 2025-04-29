import Car from '../models/Car.js';

const carService = {
    getAll(){
        return Car.find();
    },
    getOne(carId){
        return Car.findById(carId);
    },
    edit(carId, carData){
        return Car.findByIdAndUpdate(carId, carData);
    },
    delete(carId){
        return Car.findByIdAndDelete(carId);
    },
    create(carData, userId){
        return Car.create({...carData, owner: userId});
    }
};

export default carService;