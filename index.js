
require('dotenv').config();
//const http = require('http');

const express = require('express');
const { htmlToText } = require('html-to-text');
const app = express();
/* const { Server } = require('socket.io'); // Add this import

const server = http.createServer(app); // Create the server */

const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const multer = require('multer');
const streamifier = require('streamifier');
const cors = require('cors');
const ResetToken = require('./models/ResetPasswordToken')
const jwt = require('jsonwebtoken');


const bcrypt = require('bcryptjs');


const UserModel = require('./models/CreateUser');
const checkDbConnection = require('./routers/CheckConnection');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('cloudinary').v2;
const PostModel = require('./models/CreatePost');



const NewsModel = require('./models/CreateNews');
const EventModel = require('./models/CreateEvent.');
const TipsModel = require('./models/CreateTips');

const FrontEndEnpoint=process.env.FRONT_END_URL;
app.use(express.json());
app.use(cors({
  origin:FrontEndEnpoint,
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));
/* 
const io = new Server(server, {
  cors: {
    origin: "https://funfine.vercel.app", // Replace with your actual frontend URL
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true
  }
});


io.on('connection', (socket) => {
  console.log('A user connected');
  
  socket.on('disconnect', () => {
    console.log('User disconnected');
  });
});*/
app.listen(3000,()=>{
  console.log('server is running on port 3000')
}) 
// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});

// Set up storage for images, videos, and audio
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: (req, file) => {
    const fileType = file.mimetype.split('/')[0];
    let folder;

    switch (fileType) {
      case 'image':
        folder = 'images';
        break;
      case 'video':
        folder = 'videos';
        break;
      case 'audio':
        folder = 'audios';
        break;
      default:
        folder = 'assets';
    }

    console.log(`Uploading to folder: ${folder}`);
    return {
      folder: folder,
      allowed_formats: ['jpg', 'png', 'gif', 'mp4', 'mp3'],
    };
  },
});

const upload = multer({
  storage: multer.memoryStorage()
});
//original middleware
 const uploadToCloudinary = (req, res, next) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      console.error('Error with Multer upload:', err.message);
      return res.status(500).json({ error: 'File upload failed', details: err.message });
    }

    console.log('Multer file:', req.file);

    if (!req.file) {
      req.file = { location: null };
      return next();
    }

    const streamUpload = (fileBuffer) => {
      return new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { timeout: 90000 },
          (error, result) => {
            if (error) {
              console.error('Error during Cloudinary upload:', error);
              reject(error);
            } else {
              resolve(result);
            }
          }
        );
        streamifier.createReadStream(fileBuffer).pipe(stream);
      });
    };

    const uploadWithRetry = async (fileBuffer, retries = 3) => {
      for (let i = 0; i < retries; i++) {
        try {
          const result = await streamUpload(fileBuffer);
          return result;
        } catch (error) {
          console.error(`Upload attempt ${i + 1} failed:`, error.message);
          if (i === retries - 1) throw error;
        }
      }
    };

    uploadWithRetry(req.file.buffer)
      .then((result) => {
        req.file.location = result.secure_url;
        next();
      })
      .catch((error) => {
        console.error('Error uploading to Cloudinary:', error.message);
        return res.status(500).json({ error: 'Cloudinary upload failed', details: error.message });
      });
  });
};
 

const uploadToCloudinary2 = (req, res, next) => {
  upload.single('file')(req, res, async (err) => {
    if (err) {
      console.error('Error with Multer upload:', err.message);
      return res.status(500).json({ error: 'File upload failed', details: err.message });
    }

    console.log('Multer file:', req.file);

    if (!req.file) {
      req.file = { location: null };
      return next();
    }

    try {
      const result = await streamUpload(req.file.buffer);
      req.file.location = result.secure_url;
      next();
    } catch (error) {
      console.error('Error uploading to Cloudinary:', error.message);
      return res.status(500).json({ error: 'Cloudinary upload failed', details: error.message });
    }
  });
};

// Cloudinary streaming upload function
const streamUpload = (fileBuffer) => {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { timeout: 120000, chunk_size: 6000000 }, // Increase timeout and use chunking for larger files
      (error, result) => {
        if (error) {
          console.error('Error during Cloudinary upload:', error);
          reject(error);
        } else {
          resolve(result);
        }
      }
    );
    streamifier.createReadStream(fileBuffer).pipe(stream);
  });
};

let dbUri = process.env.DB_URL || 'mongodb://127.0.0.1:27017/Employees';

mongoose.connect(dbUri, { 
  connectTimeoutMS: 30000, 
  serverSelectionTimeoutMS: 30000 
})
.then(() => {
  console.log("Connected to the database");
})
.catch((err) => {
  console.error("Failed to connect to database:", err);
});


// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.replace(/['"]+/g, '').split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  jwt.verify(token, "manu-secret-key", (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = decoded; // Attach user info to request
    next();
  });
};


const verifyAdmin=(req,res,next)=>{
  
  const authHeader = req.headers.authorization;
const token = authHeader && authHeader.replace(/['"]+/g, '').split(' ')[1];


console.log(token);  
  if (!token) {
    return res.status(401).json({ message: "Token is missing" });
  } else {
    jwt.verify(token, "manu-secret-key", (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: "Token verification failed" });
      } else {
        if (decoded.role === 'admin') {
          req.user = decoded; // Attach decoded token to the request object
          next(); // Pass control to the next middleware
        } else {
          return res.status(403).json({ message: "Invalid access" });
        }
      }
    });
  }
}
//check db connection
app.get("/api/check-db-connection", checkDbConnection);

app.get('/verifyadmin',verifyAdmin, (req, res) => {
  res.json({ message: "Success", user: req.user }); // Respond with success and user data
});


const verifyUser = (req, res, next) => {

 
  const authHeader = req.headers.authorization;
const token = authHeader && authHeader.replace(/['"]+/g, '').split(' ')[1];


console.log(token);  
  if (!token) {
    return res.status(401).json({ message: "Token is missing" });
  } else {
    jwt.verify(token, "manu-secret-key", (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: "Token verification failed" });
      } else {
        if (decoded.role === 'visitor') {
          req.user = decoded; // Attach decoded token to the request object
          next(); // Pass control to the next middleware
        } else {
          return res.status(403).json({ message: "Invalid access" });
        }
      }
    });
  }
};

// Route that returns success along with decoded token data
app.get('/verifyuser',verifyUser, (req, res) => {
  res.json({ message: "Success", user: req.user }); // Respond with success and user data
});


// for checking and updating events as past or upcoming
const updateIsPastStatus = async () => {
  const posts = await PostModel.find(); // Fetch all posts (or you can fetch individual ones)
  const currentDate = new Date();

  posts.forEach(async (post) => {
    if (new Date(post.endDateTime) < currentDate && !post.isPast) {
      // If endDateTime has passed and isPast is false, update it
      post.isPast = true;
      await post.save();
      console.log(`Updated isPast for post with ID: ${post._id}`);
    }
  });
};

// You could call this function at various points like during a scheduled job, or when fetching posts.
updateIsPastStatus();

const extractText = (htmlContent) => {
  return htmlToText(htmlContent, {
    wordwrap: false,  // Prevent wrapping text
  });
};


// Post route
app.post('/posts', uploadToCloudinary, authenticateToken, (req, res) => {
  updateIsPastStatus();
  const { content, title ,venue,endDateTime,startDateTime} = req.body;
  const contacts = JSON.parse(req.body.contacts);


  
  const summary = extractText(content).slice(0, 50) + "...";

  const author = req.user.author;
  const userId = req.user.id;

  const fileUrl = req.file ? req.file.location : null;

  if (!title || !startDateTime || !endDateTime || !content) {
    console.error("Missing required fields: title, summary, content");
    return res.status(400).json({ error: "All fields are required" });
  }

  console.log("Creating post in MongoDB...");

  PostModel.create({
    title,
    startDateTime,
    endDateTime,
    content,
    file: fileUrl,
    author: author,
    venue,
    summary,
    contacts,
    userId: userId
  })
    .then((post) => {
      console.log("Post created successfully:", post._id);

    
     
   

      res.status(201).json({ status: 'Ok', post });
    })
    .catch((err) => {
      console.error("MongoDB post creation failed:", err.message);
      res.status(500).json({ error: "Post creation failed", details: err.message });
    });
    updateIsPastStatus();
});

// Additional routes...

app.delete('/post/:id', async (req, res) => {
  updateIsPastStatus()
  try {
    const post = await PostModel.findById(req.params.id);

    if (!post) {
      console.error("Post not found:", req.params.id);
      return res.status(404).json({ message: "Post not found" });
    }

    const fileUrl = post.file;
    if (fileUrl) {
      const publicId = fileUrl.split('/').pop().split('.')[0];
      const result = await deleteFileWithRetry(publicId);

      if (result) {
        console.log("File deleted from Cloudinary:", publicId);
      } else {
        console.error("Failed to delete file from Cloudinary.");
      }
    } else {
      console.log("No file associated with this post or the file is null.");
    }

    await PostModel.findByIdAndDelete(req.params.id);
    console.log(`Post ${req.params.id} deleted successfully`);

   

    res.json({ status: 'Ok', message: 'Post and associated file deleted successfully' });
  } catch (err) {
    console.error("Error deleting post or file:", err);
    res.status(500).json({ error: "Post deletion failed", details: err.message });
  }
});

//fetch upcoming events
app.get('/upcoming/events',async(req,res)=>{
updateIsPastStatus();
try {
  const upcomingEvents = await PostModel.find({isPast:false});
  if(upcomingEvents){
    res.json(upcomingEvents)
  }else{
    res.json([]);
  }
} catch (error) {
  res.json(error)
}
})

// Fetch all posts sorted by createdAt in descending order
app.get('/posts', async (req, res) => {
  updateIsPastStatus()
  try {
    const posts = await PostModel.find({})
    res.json(posts);
  } catch (error) {
    console.error("Error fetching posts:", error);
    res.status(500).json({ error: "Failed to fetch posts" });
  }
});

app.get('/posts/past', async (req, res) => {
  updateIsPastStatus()
  try {
    const posts = await PostModel.find({isPast:true})
    res.json(posts);
  } catch (error) {
    console.error("Error fetching posts:", error);
    res.status(500).json({ error: "Failed to fetch posts" });
  }
});

app.post('/toggleEventsView/:postId',async(req,res)=>{
  try {
    const { postId }=req.params;
    const post = await PostModel.findById(postId);
    const postRender= post.postRender;
    //update post
    post.postRender = !postRender;
    const updatedPost= await post.save();
    res.json(updatedPost)
  } catch (error) {
    res.json(error)
  }
 
})
// Fetch posts by userId sorted by createdAt in descending order
app.get('/userposts/:userId', async (req, res) => {
  updateIsPastStatus();
  try {
    const { userId } = req.params;
    const userPosts = await PostModel.find({ userId: userId });
    if (userPosts.length > 0) {
      res.json(userPosts);
    } else {
      res.json("You have no posts yet!");
    }
  } catch (error) {
    console.error("Error fetching user posts:", error);
    res.status(500).json({ error: "Failed to fetch user posts" });
  }
});

app.get('/userposts/upcoming/:userId', async (req, res) => {
  updateIsPastStatus();
  try {
    const { userId } = req.params;
    const userPosts = await PostModel.find({ userId: userId ,isPast:false});
    if (userPosts.length > 0) {
      res.json(userPosts);
    } else {
      res.json("You have no posts yet!");
    }
  } catch (error) {
    console.error("Error fetching user posts:", error);
    res.status(500).json({ error: "Failed to fetch user posts" });
  }
});



app.get('/userposts/past/:userId', async (req, res) => {
  updateIsPastStatus();
  try {
    const { userId } = req.params;
    const userPosts = await PostModel.find({ userId: userId ,isPast:true});
    console.log(userPosts)
   res.json(userPosts);
  } catch (error) {
    console.error("Error fetching user posts:", error);
    res.status(500).json({ error: "Failed to fetch user posts" });
  }
});

app.get('/post/:id', async (req,res)=>{
  const {id}=req.params;
  try {
      const post = await PostModel.findById(id);
      res.json(post)
  } catch (error) {
      res.json({error:error})
  }

})









app.put('/post/update/:id', uploadToCloudinary, async (req, res) => {
  try {
    const { id } = req.params;

    // Validate input fields
    const { title, startDateTime,venue,endDateTime, content } = req.body;
   
    if (!title || !content) {
      return res.status(400).json({ error: 'Title, content, and summary are required.' });
    }

    // Find the existing post
    const post = await PostModel.findById(id);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    let fileUrl = post.file; // Keep the existing file URL

    // If a new file is uploaded, handle Cloudinary file replacement
    if (req.file && req.file.location) {
      const newFileUrl = req.file.location;

      // If the post already has a file, delete the old file from Cloudinary
      if (fileUrl) {
        try {
          // Extract publicId safely
          const publicId = fileUrl.substring(fileUrl.lastIndexOf('/') + 1, fileUrl.lastIndexOf('.'));
          console.log("Public ID for deletion:", publicId);
          
          const result = await deleteFileWithRetry(publicId);
          
          if (result.result === 'ok' || result.result === 'not found') {
            console.log(`File deleted from Cloudinary: ${publicId}`);
          } else {
            console.error('Failed to delete existing file from Cloudinary.');
            return res.status(500).json({ error: 'Failed to delete existing file from Cloudinary' });
          }
        } catch (error) {
          console.error('Error deleting file from Cloudinary:', error.message);
          return res.status(500).json({ error: 'Error during Cloudinary file deletion.' });
        }
      }

      // Set new file URL
      fileUrl = newFileUrl;
    }

    // Update the post with new data
    const updatedDoc = await PostModel.findByIdAndUpdate(id, {
      title: title,
      content: content,
   
      startDateTime,
      endDateTime,
      venue:venue,
      
      file: fileUrl, // Updated with new or existing file URL
    }, { new: true });
   
    // If update fails
    if (!updatedDoc) {
      return res.status(500).json({ error: 'Failed to update post' });
    }

  } catch (error) {
    console.error('Error updating post:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.get('/posts/updated/events',async(req,res)=>{
  try {
    const updatedPastEvents = await PostModel.find({postRender:true});
  res.json(updatedPastEvents)
  } catch (error) {
    res.json(error)
  }
  
})

app.put('/past-event/update/:id', uploadToCloudinary, async (req, res) => {
  try {
    const { id } = req.params;

    // Validate input fields
    const { title, startDateTime,venue,endDateTime, content } = req.body;
  
    if (!title || !content) {
      return res.status(400).json({ error: 'Title, content, and summary are required.' });
    }

    // Find the existing post
    const post = await PostModel.findById(id);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    
let coverPhoto;
    // If a new file is uploaded, handle Cloudinary file replacement
    if (req.file && req.file.location) {
       coverPhoto = req.file.location;

      
    }else{
      coverPhoto= null;
    }

    // Update the post with new data
    const updatedDoc = await PostModel.findByIdAndUpdate(id, {
      title: title,
      content: content,
      
      startDateTime,
      endDateTime,
      coverPhoto,
      venue:venue,

     
    }, { new: true });
   
    // If update fails
    if (!updatedDoc) {
      return res.status(500).json({ error: 'Failed to update post' });
    }

    // Successfully updated
  
    res.json(updatedDoc);

  } catch (error) {
    console.error('Error updating post:', error.message);
    res.status(500).json({ error: error.message });
  }
});




const deleteFileWithRetry = async (publicId, retries = 3) => {
  for (let i = 0; i < retries; i++) {
    try {
      const result = await cloudinary.uploader.destroy(publicId, { timeout: 180000 });
      if (result.result === 'ok' || result.result === 'not found') {
        return result;
      } else {
        console.error("Failed to delete file from Cloudinary:", result);
      }
    } catch (error) {
      console.error("Error deleting file from Cloudinary:", error.message);
      if (i === retries - 1) throw error;
    }
  }
  return null;
};




app.post('/signup',async (req,res)=>{
  
  try {
      const { username, email, password } = req.body;
    
      // Check if the user already exists
      const existingUser = await UserModel.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ error: "Account already exists with this email" });
      }
    
      const hashedPassword = await bcrypt.hash(password, 10);
      const userDoc = await UserModel.create({ username, email, password: hashedPassword });
    
      return res.json('Ok')
    } catch (err) {
      console.error(err);
      return res.status(500).json({ error: "Something went wrong. Please try again later." });
    }
    
})



app.post('/signin', async (req, res) => {

  const { email, password } = req.body;

  try {
    const userExist = await UserModel.findOne({ email: email });

    if (userExist) {
      bcrypt.compare(password, userExist.password, (err, isMatch) => {
        if (err) {
          console.error('Error comparing passwords:', err);
          return res.status(500).json({ message: 'Internal server error' });
        }

        if (isMatch) {
          const token = jwt.sign({
            email: userExist.email,
            id: userExist._id,
            role: userExist.role,
            isSuspended:userExist.isSuspended,
            author: userExist.username,
          }, 
          'manu-secret-key', 
          { expiresIn: '1d' });

          // Send the token in the response
          res.json({ token, user: userExist, message: 'Login success' });
        } else {
          
           res.status(401).json({ message: 'Your credentials are invalid' }); 
        }
      });
    } else {
      res.status(404).json({ message: 'Account does not exist' });
    }
  } catch (error) {
    console.error('Error during login:', error);
    console.log(error.response)
    res.status(500).json({ message: 'Internal server error' });
  }
});


app.post('/admin/logout',verifyAdmin, (req, res) => {

  const expiredToken = jwt.sign(
    { userId: req.user.id },
    "manu-secret-key",
    { expiresIn: '1s' } // Token expires in 1 second
  );

  // Optionally, send this expired token to the client (though this is not necessary)
  return res.status(200).json({
    message: 'Logout successful',
    token: expiredToken,
  });
});
app.post('/logout',verifyUser, (req, res) => {

  const expiredToken = jwt.sign(
    { userId: req.user.id },
    "manu-secret-key",
    { expiresIn: '1s' } // Token expires in 1 second
  );

  // Optionally, send this expired token to the client (though this is not necessary)
  return res.status(200).json({
    message: 'Logout successful',
    token: expiredToken,
  });
});

//create news

app.post('/news', uploadToCloudinary, authenticateToken, (req, res) => {
  const { content, title, summary } = req.body;
  const author = req.user.author;
  const userId = req.user.id;
  const fileUrl = req.file ? req.file.location : null;

  if (!title || !summary || !content) {
    console.error("Missing required fields: title, summary, content");
    return res.status(400).json({ error: "All fields are required" });
  }

  console.log("Creating post in MongoDB...");

  NewsModel.create({
    title,
    summary,
    content,
    file: fileUrl,
    author: author,
    userId: userId
  })
    .then((post) => {
      console.log("Post created successfully:", post._id);

     
      // Notify all clients about the new post using Socket.IO
      io.emit('postCreated', post);  // Broadcast the event to all connected clients


      res.status(201).json({ status: 'Ok', post });
    })
    .catch((err) => {
      console.error("MongoDB post creation failed:", err.message);
      res.status(500).json({ error: "Post creation failed", details: err.message });
    });
});

// Additional routes...

app.delete('/news/:id', async (req, res) => {
  try {
    const post = await NewsModel.findById(req.params.id);

    if (!post) {
      console.error("Post not found:", req.params.id);
      return res.status(404).json({ message: "Post not found" });
    }

    const fileUrl = post.file;
    if (fileUrl) {
      const publicId = fileUrl.split('/').pop().split('.')[0];
      const result = await deleteFileWithRetry(publicId);

      if (result) {
        console.log("File deleted from Cloudinary:", publicId);
      } else {
        console.error("Failed to delete file from Cloudinary.");
      }
    } else {
      console.log("No file associated with this post or the file is null.");
    }

    await NewsModel.findByIdAndDelete(req.params.id);
    console.log(`Post ${req.params.id} deleted successfully`);



    res.json({ status: 'Ok', message: 'Post and associated file deleted successfully' });
  } catch (err) {
    console.error("Error deleting post or file:", err);
    res.status(500).json({ error: "Post deletion failed", details: err.message });
  }
});


app.get('/news',async (req,res)=>{
  try {
    const news = await NewsModel.find({});
    res.json(news);
  } catch (error) {
    res.json(error);
  }
 
})


//update news

app.put('/news/update/:id', uploadToCloudinary, async (req, res) => {
  try {
    const { id } = req.params;

    // Validate input fields
    const { title, content, summary } = req.body;
    if (!title || !content || !summary) {
      return res.status(400).json({ error: 'Title, content, and summary are required.' });
    }

    // Find the existing post
    const post = await NewsModel.findById(id);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    let fileUrl = post.file; // Keep the existing file URL

    // If a new file is uploaded, handle Cloudinary file replacement
    if (req.file && req.file.location) {
      const newFileUrl = req.file.location;

      // If the post already has a file, delete the old file from Cloudinary
      if (fileUrl) {
        try {
          // Extract publicId safely
          const publicId = fileUrl.substring(fileUrl.lastIndexOf('/') + 1, fileUrl.lastIndexOf('.'));
          console.log("Public ID for deletion:", publicId);
          
          const result = await deleteFileWithRetry(publicId);
          
          if (result.result === 'ok' || result.result === 'not found') {
            console.log(`File deleted from Cloudinary: ${publicId}`);
          } else {
            console.error('Failed to delete existing file from Cloudinary.');
            return res.status(500).json({ error: 'Failed to delete existing file from Cloudinary' });
          }
        } catch (error) {
          console.error('Error deleting file from Cloudinary:', error.message);
          return res.status(500).json({ error: 'Error during Cloudinary file deletion.' });
        }
      }

      // Set new file URL
      fileUrl = newFileUrl;
    }

    // Update the post with new data
    const updatedDoc = await NewsModel.findByIdAndUpdate(id, {
      title: title,
      content: content,
      summary: summary,
      file: fileUrl, // Updated with new or existing file URL
    }, { new: true });

    // If update fails
    if (!updatedDoc) {
      return res.status(500).json({ error: 'Failed to update post' });
    }

    // Successfully updated
    res.json(updatedDoc);
    

  } catch (error) {
    console.error('Error updating post:', error.message);
    res.status(500).json({ error: error.message });
  }
});

//get news
app.get('/news/:id',async (req,res)=>{
  try {
    const { id }=req.params;
    const news = await NewsModel.findById(id);
    
    if(news){
      res.json(news)
    }else{
      res.json("No such post found")
    }
    
  } catch (error) {
    res.json(error)
  }
 
})



//create Event
app.post('/events', uploadToCloudinary, authenticateToken, (req, res) => {
  const { content, title, summary } = req.body;
  const author = req.user.author;
  const userId = req.user.id;
  const fileUrl = req.file ? req.file.location : null;


  console.log("Creating post in MongoDB...");

  EventModel.create({
    title,
    summary,
    content,
    file: fileUrl,
    author: author,
    userId: userId
  })
    .then((post) => {
      console.log("Post created successfully:", post._id);

      res.status(201).json({ status: 'Ok', post });
    })
    .catch((err) => {
      console.error("MongoDB post creation failed:", err.message);
      res.status(500).json({ error: "Post creation failed", details: err.message });
    });
});

// delete event

app.delete('/event/:id', async (req, res) => {
  try {
    const post = await EventModel.findById(req.params.id);

    if (!post) {
      console.error("Post not found:", req.params.id);
      return res.status(404).json({ message: "Post not found" });
    }

    const fileUrl = post.file;
    if (fileUrl) {
      const publicId = fileUrl.split('/').pop().split('.')[0];
      const result = await deleteFileWithRetry(publicId);

      if (result) {
        console.log("File deleted from Cloudinary:", publicId);
      } else {
        console.error("Failed to delete file from Cloudinary.");
      }
    } else {
      console.log("No file associated with this post or the file is null.");
    }

    await EventModel.findByIdAndDelete(req.params.id);
    console.log(`Post ${req.params.id} deleted successfully`);


    res.json({ status: 'Ok', message: 'Post and associated file deleted successfully' });
  } catch (err) {
    console.error("Error deleting post or file:", err);
    res.status(500).json({ error: "Post deletion failed", details: err.message });
  }
});


app.get('/events',async (req,res)=>{
  try {
    const news = await EventModel.find({});
    res.json(news);
  } catch (error) {
    res.json(error);
  }
 
})


//update news

app.put('/event/update/:id', uploadToCloudinary, async (req, res) => {
  try {
    const { id } = req.params;

    // Validate input fields
    const { title, content, summary } = req.body;
    if (!title || !content || !summary) {
      return res.status(400).json({ error: 'Title, content, and summary are required.' });
    }

    // Find the existing post
    const post = await EventModel.findById(id);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    let fileUrl = post.file; // Keep the existing file URL

    // If a new file is uploaded, handle Cloudinary file replacement
    if (req.file && req.file.location) {
      const newFileUrl = req.file.location;

      // If the post already has a file, delete the old file from Cloudinary
      if (fileUrl) {
        try {
          // Extract publicId safely
          const publicId = fileUrl.substring(fileUrl.lastIndexOf('/') + 1, fileUrl.lastIndexOf('.'));
          console.log("Public ID for deletion:", publicId);
          
          const result = await deleteFileWithRetry(publicId);
          
          if (result.result === 'ok' || result.result === 'not found') {
            console.log(`File deleted from Cloudinary: ${publicId}`);
          } else {
            console.error('Failed to delete existing file from Cloudinary.');
            return res.status(500).json({ error: 'Failed to delete existing file from Cloudinary' });
          }
        } catch (error) {
          console.error('Error deleting file from Cloudinary:', error.message);
          return res.status(500).json({ error: 'Error during Cloudinary file deletion.' });
        }
      }

      // Set new file URL
      fileUrl = newFileUrl;
    }

    // Update the post with new data
    const updatedDoc = await EventModel.findByIdAndUpdate(id, {
      title: title,
      content: content,
      summary: summary,
      file: fileUrl, // Updated with new or existing file URL
    }, { new: true });

    // If update fails
    if (!updatedDoc) {
      return res.status(500).json({ error: 'Failed to update post' });
    }



    res.json(updatedDoc);

    //notify update 
    const message = JSON.stringify({ type: 'postUpdated', post });
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  } catch (error) {
    console.error('Error updating post:', error.message);
    res.status(500).json({ error: error.message });
  }
});

//get news
app.get('/event/:id',async (req,res)=>{
  try {
    const { id }=req.params;
    const event = await EventModel.findById(id);
    
    if(event){
      res.json(event)
    }else{
      res.json("No such post found")
    }
    
  } catch (error) {
    res.json(error)
  }
 
})







app.post('/tips', uploadToCloudinary, authenticateToken, (req, res) => {
  const { content, title, summary } = req.body;
  const author = req.user.author;

  const userId = req.user.id;

  const fileUrl = req.file ? req.file.location : null;

  if (!title || !summary || !content) {
    console.error("Missing required fields: title, summary, content");
    return res.status(400).json({ error: "All fields are required" });
  }

  console.log("Creating post in MongoDB...");

  TipsModel.create({
    title,
    summary,
    content,
    file: fileUrl,
    author: author,
    userId: userId
  })
    .then((post) => {
      console.log("Post created successfully:", post._id);

    
 
      res.status(201).json({ status: 'Ok', post });
    })
    .catch((err) => {
      console.error("MongoDB post creation failed:", err.message);
      res.status(500).json({ error: "Post creation failed", details: err.message });
    });
});

// Additional routes...

app.delete('/tip/:id', async (req, res) => {
  try {
    const post = await TipsModel.findById(req.params.id);

    if (!post) {
      console.error("Post not found:", req.params.id);
      return res.status(404).json({ message: "Post not found" });
    }

    const fileUrl = post.file;
    if (fileUrl) {
      const publicId = fileUrl.split('/').pop().split('.')[0];
      const result = await deleteFileWithRetry(publicId);

      if (result) {
        console.log("File deleted from Cloudinary:", publicId);
      } else {
        console.error("Failed to delete file from Cloudinary.");
      }
    } else {
      console.log("No file associated with this post or the file is null.");
    }

    await TipsModel.findByIdAndDelete(req.params.id);
    console.log(`Post ${req.params.id} deleted successfully`);



    res.json({ status: 'Ok', message: 'Post and associated file deleted successfully' });
  } catch (err) {
    console.error("Error deleting post or file:", err);
    res.status(500).json({ error: "Post deletion failed", details: err.message });
  }
});


app.get('/tips',async (req,res)=>{
  try {
    const tips = await TipsModel.find({});
    res.json(tips);
  } catch (error) {
    res.json(error);
  }
 
})


//update news

app.put('/tip/update/:id', uploadToCloudinary, async (req, res) => {
  try {
    const { id } = req.params;

    // Validate input fields
    const { title, content, summary } = req.body;
    if (!title || !content || !summary) {
      return res.status(400).json({ error: 'Title, content, and summary are required.' });
    }

    // Find the existing post
    const post = await TipsModel.findById(id);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    let fileUrl = post.file; // Keep the existing file URL

    // If a new file is uploaded, handle Cloudinary file replacement
    if (req.file && req.file.location) {
      const newFileUrl = req.file.location;

      // If the post already has a file, delete the old file from Cloudinary
      if (fileUrl) {
        try {
          // Extract publicId safely
          const publicId = fileUrl.substring(fileUrl.lastIndexOf('/') + 1, fileUrl.lastIndexOf('.'));
          console.log("Public ID for deletion:", publicId);
          
          const result = await deleteFileWithRetry(publicId);
          
          if (result.result === 'ok' || result.result === 'not found') {
            console.log(`File deleted from Cloudinary: ${publicId}`);
          } else {
            console.error('Failed to delete existing file from Cloudinary.');
            return res.status(500).json({ error: 'Failed to delete existing file from Cloudinary' });
          }
        } catch (error) {
          console.error('Error deleting file from Cloudinary:', error.message);
          return res.status(500).json({ error: 'Error during Cloudinary file deletion.' });
        }
      }

      // Set new file URL
      fileUrl = newFileUrl;
    }

    // Update the post with new data
    const updatedDoc = await TipsModel.findByIdAndUpdate(id, {
      title: title,
      content: content,
      summary: summary,
      file: fileUrl, // Updated with new or existing file URL
    }, { new: true });

    // If update fails
    if (!updatedDoc) {
      return res.status(500).json({ error: 'Failed to update post' });
    }

    // Successfully updated
    res.json(updatedDoc);
  
  
  } catch (error) {
    console.error('Error updating post:', error.message);
    res.status(500).json({ error: error.message });
  }
});

//get news
app.get('/tip/:id',async (req,res)=>{
  try {
    const { id }=req.params;
    const tip = await TipsModel.findById(id);
    
    if(tip){
      res.json(tip)
    }else{
      res.json("No such post found")
    }
    
  } catch (error) {
    res.json(error)
  }
 
})


app.get('/users',async (req,res)=>{
  try {
    const users = await UserModel.find({});
    if (users){
      res.json(users)
    }else{
      res.json("No user found")
    }
  } catch (error) {
    res.json("Error")
  }

})


app.delete('/user/delete/:id',async(req,res)=>{


  const {id}= req.params;
  const user = await UserModel.findById(id);
  if(user){


const deletedUser= await UserModel.findByIdAndDelete(id);
if (deletedUser){
  res.json("User deleted successfully")
}else{
  res.json("Error deleting user")
}
  }else{
    res.json("User does not exist")
  }


})





// Configure Nodemailer Transporter
const transporter = nodemailer.createTransport({
  service: 'gmail', // You can use any other email service provider
  auth: {
    user: process.env.EMAIL_USER,  // Email user from .env file
    pass: process.env.EMAIL_PASS   // Email password from .env file
  }
});

// Forgot Password Route
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    // Find the user by email
    const user = await UserModel.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: "User with this email does not exist" });
    }

    // Generate a reset token (JWT)
    const resetToken = jwt.sign(
      { email: user.email, id: user._id },
      process.env.JWT_RESET_PASSWORD_KEY,
      { expiresIn: '15m' }
    );

    // Save the token in the database
    await ResetToken.create({ token: resetToken, userId: user._id });

    // Define the reset URL to be sent in the email
    const frontEndEnpoint = 'http://localhost:5173';
    const resetURL = `${frontEndEnpoint}/reset-password/${user._id}/${resetToken}`;

    // Email content
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset Request',
      html: `
        <p>You requested a password reset.</p>
        <p>Click the following link to reset your password: <a href="${resetURL}">${resetURL}</a></p>
        <p>This link will expire in 15 minutes.</p>
      `
    };

    // Send the email
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
        return res.status(500).json({ error: "Failed to send email" });
      } else {
        console.log('Email sent: ' + info.response);
        return res.json("success");
      }
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Server error" });
  }
});
app.post('/reset-password/:id/:token', async (req, res) => {
  const { id, token } = req.params;
  const { password } = req.body;

  try {
    console.log(`Resetting password for user ID: ${id}, token: ${token}`);

    // Find the reset token in the database
    const resetToken = await ResetToken.findOne({token: token,userId: id });
    console.log(resetToken); // Log the found token

    // Check if the token is valid and not used
    if (!resetToken) {
      return res.status(400).json({ error: "Invalid or expired token" });
    }

    if (resetToken.isUsed) {
      return res.status(400).json({ error: "Token has already been used" });
    }

    // Verify the JWT
    const decoded = jwt.verify(token, process.env.JWT_RESET_PASSWORD_KEY);
    console.log(`Decoded JWT: ${JSON.stringify(decoded)}`); // Log the decoded token

    // Find the user and update the password
    const user = await UserModel.findById(decoded.id);
    user.password = await bcrypt.hash(password, 10); // Ensure password is hashed
    await user.save();

    // Mark the token as used
    resetToken.isUsed = true;
    await resetToken.save();

    return res.json({ message: "Password successfully reset" });
  } catch (error) {
    console.error('Error resetting password:', error);
    return res.status(500).json({ error: "Server error" });
  }
});

const sendSuspendEmail = (userEmail,suspensionReason)=>{
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: userEmail,
    subject: 'Account suspension',
    html: `
      <p>Your account has been suspended</p>
      <p>This is due to ${suspensionReason}</p>
      <p>If you have any issue feel free to contact support.</p>
       <p>support@FunFine.com</p>
    `
  };

  // Send the email
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log(error);
      return res.status(500).json({ error: "Failed to send email" });
    } else {
      console.log('Email sent: ' + info.response);
      return res.json("success");
    }
  });

}

const sendUnsuspendEmail = (userEmail)=>{
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: userEmail,
    subject: 'Account Activation',
    html: `
      <p>Your account has been activated</p>
      <p>You can now login and access resources</p>
      <p>Thank you</p>
      <p>support@FunFine.com</p>
    `
  };

  // Send the email
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log(error);
      return res.status(500).json({ error: "Failed to send email" });
    } else {
      console.log('Email sent: ' + info.response);
      return res.json("success");
    }
  });
}
// Suspend User
app.post('/user/suspend/:id', async (req, res) => {
  try {
    const { reason } = req.body; 
    const user = await UserModel.findById(req.params.id);

    if (!user) {
      return res.status(404).send({ message: 'User not found' });
    }
    const userEmail = user.email;
    user.isSuspended = true;
    user.suspensionReason = reason; 
    await user.save();
    sendSuspendEmail(userEmail,reason);
        // Email content
     
    res.status(200).send({ message: 'User suspended successfully' });
  } catch (error) {
    res.status(500).send({ message: 'Error suspending user', error });
  }
});

// Unsuspend User
app.post('/user/unsuspend/:id', async (req, res) => {
  try {
    const user = await UserModel.findById(req.params.id);
    if (!user) {
      return res.status(404).send({ message: 'User not found' });
    }
    const userEmail = user.email;
    user.isSuspended = false;
    await user.save();
    sendUnsuspendEmail(userEmail);
    res.status(200).send({ message: 'User unsuspended successfully' });
  } catch (error) {
    res.status(500).send({ message: 'Error unsuspending user', error });
  }
});



/// send news to all users using nodemailer

// API to send news
app.post('/send-news', async (req, res) => {
  const { subject, message } = req.body;

  try {
    // Fetch all users from the database
    const users = await UserModel.find({});

    if (users.length === 0) {
      return res.status(404).json({ message: 'No users found' });
    }

    // Set up Nodemailer transport

    // Send emails to each user
    for (const user of users) {
      const mailOptions = {
        from: '"News Service" <your-email@gmail.com>',
        to: user.email,
        subject: subject,
        text: message,
      };

      await transporter.sendMail(mailOptions);
    }

    res.status(200).json({ message: 'News sent to all users' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error sending news' });
  }
});
app.get('*', (req, res) => {
res.send("Hello welcome to FineFun")
});
