const mongoose = require("mongoose");

async function checkDbConnection(req, res) {
  try {
    await mongoose.connect(process.env.DB_URL, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    res.status(200).json({ connected: true });
  } catch (error) {
    res.status(500).json({ connected: false, error: error.message });
  }
}

module.exports = checkDbConnection;
