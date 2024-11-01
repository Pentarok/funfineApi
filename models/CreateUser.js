const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    username:String,
    email:String,
    password:String,
    suspensionReason:String,
    isSuspended: { type: Boolean, default: false }, // New field
    role:{
        type:String,
        default:'visitor'
    }
},{
    timestamps:true
})

const UserModel = mongoose.model('user',UserSchema);
module.exports=UserModel;