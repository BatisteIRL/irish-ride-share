const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const winston = require('winston');
const rateLimit = require('express-rate-limit');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.CORS_ORIGIN || '*', // Ensure this matches your frontend origin
    methods: ['GET', 'POST'],
  },
});

// Middleware
app.use(express.json());
app.use(cors({ origin: process.env.CORS_ORIGIN }));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(apiLimiter);

// Logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  defaultMeta: { service: 'user-service' },
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}
console.log("MongoDB URI from environment:", process.env.MONGODB_URI);
// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, { 
  useNewUrlParser: true, 
  useUnifiedTopology: true 
}).then(() => {
  logger.info('Connected to MongoDB');
}).catch(err => {
  logger.error('MongoDB connection error:', err);
});

// Schemas
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
  logger.info('New client connected');

  socket.on('join', (userId) => {
    socket.join(userId);
    logger.info(`User ${userId} joined their room`);
  });

  socket.on('disconnect', () => {
    logger.info('Client disconnected');
  });
});

// Routes
app.post('/api/register', [
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  body('name').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

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
    logger.error('Registration error:', error);
    res.status(500).send({ message: 'Error registering user' });
  }
});

app.post('/api/login', [
  body('email').isEmail(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const user = await User.findOne({ email: req.body.email });
    if (user && await bcrypt.compare(req.body.password, user.password)) {
      const token = jwt.sign(
        { id: user._id, email: user.email }, 
        process.env.JWT_SECRET, 
        { expiresIn: '24h' }
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
    logger.error('Login error:', error);
    res.status(500).send({ message: 'Error logging in' });
  }
});

app.get('/api/rides', authenticateJWT, async (req, res) => {
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
    logger.error('Fetch rides error:', error);
    res.status(500).send({ message: 'Error fetching rides' });
  }
});

app.post('/api/rides', authenticateJWT, [
  body('from').notEmpty(),
  body('to').notEmpty(),
  body('date').isISO8601(),
  body('price').isFloat({ min: 0 }),
  body('seats').isInt({ min: 1 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const ride = new Ride({
      driverId: req.user.id,
      ...req.body,
      availableSeats: req.body.seats
    });
    await ride.save();
    res.status(201).json(ride);
  } catch (error) {
    logger.error('Create ride error:', error);
    res.status(500).send({ message: 'Error creating ride' });
  }
});

app.post('/api/rides/:id/book', authenticateJWT, async (req, res) => {
  try {
    const ride = await Ride.findById(req.params.id);
    if (!ride || ride.availableSeats === 0) {
      return res.status(400).send({ message: 'Ride not available' });
    }
    ride.passengers.push(req.user.id);
    ride.availableSeats--;
    await ride.save();
    
    const driver = await User.findById(ride.driverId);
    if (driver && driver.expoPushToken) {
      // Implement push notification logic here
    }
    
    io.to(ride.driverId.toString()).emit('rideBooked', { rideId: ride._id, passengerId: req.user.id });
    
    res.json(ride);
  } catch (error) {
    logger.error('Book ride error:', error);
    res.status(500).send({ message: 'Error booking ride' });
  }
});

app.get('/api/users/profile', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).send({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    logger.error('Fetch profile error:', error);
    res.status(500).send({ message: 'Error fetching user profile' });
  }
});

app.put('/api/users/profile', authenticateJWT, [
  body('name').optional().notEmpty(),
  body('isDriver').optional().isBoolean()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const user = await User.findByIdAndUpdate(req.user.id, req.body, { new: true }).select('-password');
    res.json(user);
  } catch (error) {
    logger.error('Update profile error:', error);
    res.status(500).send({ message: 'Error updating user profile' });
  }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  logger.info(`Server is running on port ${PORT}`);
});
