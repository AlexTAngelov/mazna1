import { Schema, model, Types } from 'mongoose';

const carSchema = new Schema({
    brand: {
        type: String,
        required: [true, 'Brand is required']
    },
    model: {
        type: String,
        required: [true, 'Model is required']
    },
    mileage: {
        type: Number,
        required: true
    },
    engine: {
        type: String,
        required: true
    },
    price: {
        type: Number,
        required: true
    },
    phoneNum: {
        type: Number,
        required: true
    },
    description: {
        type: String,
        required: true
    },
    image: {
        type: String,
        required: true
    },
    owner: {
        type: Types.ObjectId,
        ref: 'User'
    }
});

const Car = model('Car', carSchema);

export default Car;