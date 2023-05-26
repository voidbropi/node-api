const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');

const app = express();
const port = 5000;

// MongoDB Connection
const username = encodeURIComponent('admin');
const password = encodeURIComponent('admin123456');
const dbName = 'united';
const mongoURI = `mongodb+srv://${username}:${password}@main.tf6adlr.mongodb.net/${dbName}`;
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;

// User Model
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  hwid: String,
  valid: Boolean,
  expiration_date: Date,
});

const User = mongoose.model('User', userSchema);

// Middleware
app.use(bodyParser.json());

// Routes
app.post('/register', async (req, res) => {
  const { username, password, hwid } = req.body;

  if (!username || !password || !hwid) {
    return res.status(400).json({ error: 'Missing username, password, or HWID' });
  }

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(409).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const expirationDate = new Date();
    expirationDate.setDate(expirationDate.getDate() + 30);

    const user = new User({
      username,
      password: hashedPassword,
      hwid,
      valid: true,
      expiration_date: expirationDate,
    });

    await user.save();

    return res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password, hwid } = req.body;

  if (!username || !password || !hwid) {
    return res.status(400).json({ error: 'Missing username, password, or HWID' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    if (user.hwid !== hwid || !user.valid) {
      const conflictingUser = await User.findOne({ hwid });
      if (conflictingUser) {
        if (conflictingUser.username !== username) {
          conflictingUser.valid = false;
          await conflictingUser.save();
        }
        user.valid = false;
        await user.save();
      }
      return res.status(401).json({ error: 'Invalid HWID' });
    }

    const currentDate = new Date();
    if (user.expiration_date && user.expiration_date < currentDate) {
      user.valid = false;
      await user.save();
      return res.status(401).json({ error: 'Subscription expired' });
    }

    return res.status(200).json({ message: 'Login successful' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
