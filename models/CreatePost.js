const mongoose = require('mongoose');

const PostSchema = new mongoose.Schema({
    title: 'String',
    content: 'String',
    summary: 'String',
    file: 'String',          // File for the event poster
    coverPhoto: 'String',    // File for the event's cover photo after it has passed
    author: 'String',
    userId: 'String',
    startDateTime: {         // Start date and time of the event
      type: Date,
      required: true
    },
    endDateTime: {           // End date and time of the event
      type: Date,
      required: true
    },
    venue: 'String',
    contacts: [String],      // Array of contact numbers
    isPast: {                // Boolean to track if the event is past or upcoming
      type: Boolean,
      default: false
    },
    isEditable: {            // Boolean to track if the event can be edited after it passes
      type: Boolean,
      default: true
    },
    pastRender: {            // Tracks if the event should be rendered as past
      type: Boolean,
      default: false
    }
}, {
    timestamps: true
});

const PostModel = mongoose.model('happenings', PostSchema);
module.exports = PostModel;
