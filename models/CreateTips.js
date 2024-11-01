const mongoose = require('mongoose');
const TipsShema = new mongoose.Schema({
    title:'String',
    content:'String',
    summary:'String',
    file:'String',
    author:'String',
    userId:'String',

},{
    timestamps:true
})
const TipsModel = mongoose.model('tips',TipsShema)
module.exports=TipsModel;