const mongoose = require('mongoose');
const EventSchema = new mongoose.Schema({
    title:'String',
    content:'String',
    summary:'String',
    file:'String',
    author:'String',
    userId:'String',

},{
    timestamps:true
})
const EventModel = mongoose.model('event',EventSchema)
module.exports=EventModel;