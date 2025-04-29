import { Schema, model } from 'mongoose';
import bcrypt from 'bcrypt'

const SALT_ROUNDS = 10;

const userSchema = new Schema({
    username: {
        type: String,
        required: [true, 'Username is required']
    },
    email: {
        type: String,
        required: [true, 'Email is required']
    },
    password: {
        type: String,
        required: [true, 'Password is required']
    },
    role: {
        type: String,
        enum: ['admin', 'user'],
        default: 'user'
    }
});

userSchema.pre('save', async function(){
    const hash = await bcrypt.hash(this.password, SALT_ROUNDS);

    this.password = hash;   
});

// Method to check if user is admin
userSchema.methods.isAdmin = function() {
    return this.role === 'admin';
};

// Method to check if user has permission
userSchema.methods.hasPermission = function(permission) {
    if (this.isAdmin()) return true;
    
    // Add specific permission checks for regular users here
    const userPermissions = {
        'view_cars': true,
        'create_cars': true,
        'edit_own_cars': true,
        'delete_own_cars': true,
        'edit_all_cars': false,
        'delete_all_cars': false
    };
    
    return userPermissions[permission] || false;
};

const User = model('User', userSchema);

export default User;
