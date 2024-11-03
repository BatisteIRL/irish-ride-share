const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true });
}).then(() => {
  console.log('Connected to MongoDB');
}).catch(err => {
  console.error('MongoDB connection error:', err);
});

// Define schemas
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  isDriver: { type: Boolean, default: false },
  expoPushToken: String
});

const RideSchema = new mongoose.Schema({
  driverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  from: { type: String, required: true },
  to: { type: String, required: true },
  date: { type: Date, required: true },
  price: { type: Number, required: true },
  seats: { type: Number, required: true },
  availableSeats: { type: Number, required: true },
  status: { type: String, enum: ['active', 'cancelled', 'completed'], default: 'active' },
  passengers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});

const User = mongoose.model('User', UserSchema);
const Ride = mongoose.model('Ride', RideSchema);

// Middleware for JWT authentication
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log('New client connected');

  socket.on('join', (userId) => {
    socket.join(userId);
    console.log(`User ${userId} joined their room`);
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

// Routes
app.post('/api/register', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
      email: req.body.email,
      password: hashedPassword,
      name: req.body.name,
      isDriver: req.body.isDriver || false
    });
    await user.save();
    res.status(201).send({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).send({ message: 'Error registering user' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (user && await bcrypt.compare(req.body.password, user.password)) {
     process.env.JWT_SECRET
      );
      res.json({ 
        token, 
        user: { 
          id: user._id, 
          name: user.name, 
          email: user.email, 
          isDriver: user.isDriver 
        } 
      });
    } else {
      res.status(400).send({ message: 'Invalid credentials' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).send({ message: 'Error logging in' });
  }
});

// Ride routes
app.get('/api/rides', async (req, res) => {
  try {
    const { from, to, date } = req.query;
    const rides = await Ride.find({ 
      from, 
      to, 
      date, 
      status: 'active' 
    }).populate('driverId', 'name');
    res.json(rides);
  } catch (error) {
    console.error('Fetch rides error:', error);
    res.status(500).send({ message: 'Error fetching rides' });
  }
});

app.post('/api/rides', authenticateJWT, async (req, res) => {
  try {
    const ride = new Ride({
      driverId: req.user.id,
      ...req.body,
      availableSeats: req.body.seats
    });
    await ride.save();
    res.status(201).json(ride);
  } catch (error) {
    console.error('Create ride error:', error);
    res.status(500).send({ message: 'Error creating ride' });
  }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
