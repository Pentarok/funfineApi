const mongoose = require("mongoose");
const localUri =process.env.DB_URLL;
async function checkDbConnection(req, res) {
  try {
    if (req.method === 'OPTIONS') {
      res.status(200).end()
      
    }
  
    await mongoose.connect(localUri, {
      connectTimeoutMS: 30000,
      serverSelectionTimeoutMS: 30000  
    });
    res.status(200).json({ connected: true });
  } catch (error) {
    res.status(500).json({ connected: false, error: error.message });
  }
}

module.exports = checkDbConnection;
