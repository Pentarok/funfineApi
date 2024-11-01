const mongoose = require('mongoose');
const NewsSchema = new mongoose.Schema({
    title:'String',
    content:'String',
    summary:'String',
    file:'String',
    author:'String',
    userId:'String',

},{
    timestamps:true
})
const NewsModel = mongoose.model('news',NewsSchema)
module.exports=NewsModel;