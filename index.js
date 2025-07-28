require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { GridFSBucket } = require('mongodb');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://tamil:tamil@cluster0.lxk1iio.mongodb.net/hostelDB?retryWrites=true&w=majority';

// Models
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { 
    type: String, 
    required: true, 
    unique: true,
    validate: {
      validator: function(v) {
        return /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(v);
      },
      message: props => `${props.value} is not a valid email address!`
    }
  },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'owner', 'admin'], default: 'user' }
});

const ratingSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  hostelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Hostel', required: true },
  rating: { type: Number, min: 1, max: 5, required: true },
  review: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const roomTypeSchema = new mongoose.Schema({
  hostelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Hostel', required: true },
  name: { type: String, required: true },
  description: { type: String },
  price: { type: Number, required: true },
  capacity: { type: Number, required: true },
  available: { type: Number, required: true },
  createdAt: { type: Date, default: Date.now }
});

const hostelSchema = new mongoose.Schema({
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  description: { type: String, required: true },
  email: { 
    type: String, 
    required: true,
    validate: {
      validator: function(v) {
        return /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(v);
      },
      message: props => `${props.value} is not a valid email address!`
    }
  },
  location: { type: String, required: true },
  contact: { type: String, required: true },
  images: { type: [String], default: [] },
  feedbacks: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
  }],
  averageRating: { type: Number, default: 0 },
  ratingCount: { type: Number, default: 0 },
  district: { type: String, required: true },
  minPrice: { type: Number, default: 0 },
  maxPrice: { type: Number, default: 0 },
  availableRooms: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Rating = mongoose.model('Rating', ratingSchema);
const RoomType = mongoose.model('RoomType', roomTypeSchema);
const Hostel = mongoose.model('Hostel', hostelSchema);

let gfs;
let gridFSBucket;

async function initializeDatabase() {
  try {
    const conn = await mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 5000
    });
    console.log('🚀 Connected to MongoDB Atlas');
    
    const db = conn.connection.db;
    gridFSBucket = new GridFSBucket(db, { bucketName: 'uploads' });
    gfs = db.collection('uploads.files');
    
    const adminExists = await User.findOne({ username: 'admin' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await User.create({
        username: 'admin',
        password: hashedPassword,
        role: 'admin',
        email: 'admin@gmail.com'
      });
      console.log('Admin user created');
    }
  } catch (err) {
    console.error('Database connection error:', err.message);
    process.exit(1);
  }
}

async function updateHostelRating(hostelId) {
  try {
    const hostelObjectId = new mongoose.Types.ObjectId(hostelId);

    const result = await Rating.aggregate([
      { $match: { hostelId: hostelObjectId } },
      { 
        $group: { 
          _id: null, 
          average: { $avg: '$rating' }, 
          count: { $sum: 1 } 
        } 
      }
    ]);
    
    if (result.length > 0) {
      await Hostel.findByIdAndUpdate(hostelObjectId, {
        averageRating: result[0].average,
        ratingCount: result[0].count
      });
    }
  } catch (err) {
    console.error('Error updating hostel rating:', err);
    throw err;
  }
}

async function updateHostelPricing(hostelId) {
  const result = await RoomType.aggregate([
    { $match: { hostelId: mongoose.Types.ObjectId(hostelId) } },
    { $group: { 
        _id: null, 
        minPrice: { $min: '$price' }, 
        maxPrice: { $max: '$price' },
        totalAvailable: { $sum: '$available' }
      } 
    }
  ]);
  
  if (result.length > 0) {
    await Hostel.findByIdAndUpdate(hostelId, {
      minPrice: result[0].minPrice,
      maxPrice: result[0].maxPrice,
      availableRooms: result[0].totalAvailable
    });
  }
}

app.use(cors());
app.use(express.json());

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const filetypes = /jpe?g|png|gif/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    mimetype && extname ? cb(null, true) : cb(new Error('Images only!'));
  }
});

const authenticate = (roles = []) => {
  return async (req, res, next) => {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      if (!token) return res.status(401).json({ error: 'Unauthorized' });

      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
      const user = await User.findById(decoded.userId);
      if (!user) return res.status(401).json({ error: 'Unauthorized' });

      if (roles.length && !roles.includes(user.role)) {
        return res.status(403).json({ error: 'Forbidden' });
      }

      req.user = user;
      next();
    } catch (err) {
      res.status(401).json({ error: 'Unauthorized' });
    }
  };
};

const storeImage = (file) => {
  return new Promise((resolve, reject) => {
    const uploadStream = gridFSBucket.openUploadStream(file.originalname, {
      metadata: { contentType: file.mimetype }
    });
    uploadStream.on('error', reject);
    uploadStream.on('finish', () => resolve(uploadStream.id.toString()));
    uploadStream.end(file.buffer);
  });
};

const deleteImage = async (fileId) => {
  try {
    await gridFSBucket.delete(new mongoose.Types.ObjectId(fileId));
  } catch (err) {
    console.error('Error deleting image:', err);
  }
};

// Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    
    if (!email || !/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
      return res.status(400).json({ error: 'Valid email is required' });
    }

    if (role === 'owner' || role === 'admin') {
      return res.status(403).json({ error: 'Cannot register as owner or admin' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ 
      username, 
      email,
      password: hashedPassword,
      role: role || 'user'
    });
    
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '1h' }
    );
    
    res.status(201).json({ token, role: user.role, userId: user._id });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    res.status(400).json({ error: 'Registration failed' });
  }
});
// Add this to your backend routes (before the admin routes)
app.post('/api/owner/hostels', authenticate(['owner']), upload.array('images', 10), async (req, res) => {
  try {
    const { name, description, email, location, district, contact, existingImages } = req.body;
    
    // Validate required fields
    if (!name || !description || !email || !location || !district || !contact) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Process images
    const imageUrls = [];
    
    // Handle existing images (if in edit mode)
    if (existingImages) {
      try {
        const parsedImages = JSON.parse(existingImages);
        if (Array.isArray(parsedImages)) {
          imageUrls.push(...parsedImages);
        }
      } catch (err) {
        console.error('Error parsing existing images:', err);
      }
    }

    // Handle new uploaded images
    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        try {
          const fileId = await storeImage(file);
          imageUrls.push(`/api/images/${fileId}`);
        } catch (err) {
          console.error('Error storing image:', err);
        }
      }
    }

    // Create new hostel
    const hostel = new Hostel({
      ownerId: req.user._id,
      name,
      description,
      email,
      location,
      district,
      contact,
      images: imageUrls
    });

    await hostel.save();
    res.status(201).json(hostel);
  } catch (err) {
    console.error('Error creating hostel:', err);
    res.status(500).json({ error: 'Failed to create hostel' });
  }
});
app.post('/api/auth/login', async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    
    const isEmail = usernameOrEmail.includes('@');
    const user = isEmail 
      ? await User.findOne({ email: usernameOrEmail })
      : await User.findOne({ username: usernameOrEmail });
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '1h' }
    );
    
    res.json({ token, role: user.role, userId: user._id });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});
// Backend route to get hostels for the current owner
app.get('/api/owner/hostels', authenticate(['owner']), async (req, res) => {
  try {
    const hostels = await Hostel.find({ ownerId: req.user._id });
    res.json(hostels);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch hostels' });
  }
});
app.get('/api/ratings/check', authenticate(['user']), async (req, res) => {
  try {
    const { hostel } = req.query;
    const rating = await Rating.findOne({
      userId: req.user._id,
      hostelId: hostel
    });
    res.json({ exists: !!rating, rating });
  } catch (err) {
    res.status(500).json({ error: 'Failed to check rating' });
  }
});

app.get('/api/hostels/:id/ratings', async (req, res) => {
  try {
    const ratings = await Rating.find({ hostelId: req.params.id })
      .populate('userId', 'username');
    res.json(ratings);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch ratings' });
  }
});
app.get('/api/hostels', async (req, res) => {
  try {
    const { district, minRating } = req.query;
    const query = {};
    
    if (district) query.district = district;
    if (minRating) query.averageRating = { $gte: parseFloat(minRating) };
    
    const hostels = await Hostel.find(query)
      .sort({ averageRating: -1, createdAt: -1 });
    res.json(hostels);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch hostels' });
  }
});

app.get('/api/hostels/:id', async (req, res) => {
  try {
    const hostel = await Hostel.findById(req.params.id)
      .populate('feedbacks.userId', 'username');
    if (!hostel) return res.status(404).json({ error: 'Hostel not found' });
    res.json(hostel);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch hostel' });
  }
});

app.get('/api/hostels/:id/room-types', async (req, res) => {
  try {
    const roomTypes = await RoomType.find({ hostelId: req.params.id });
    res.json(roomTypes);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch room types' });
  }
});

app.post('/api/hostels/:id/feedback', authenticate(['user']), async (req, res) => {
  try {
    const hostel = await Hostel.findById(req.params.id);
    if (!hostel) return res.status(404).json({ error: 'Hostel not found' });

    hostel.feedbacks.push({
      userId: req.user._id,
      text: req.body.feedback
    });

    await hostel.save();
    res.json(hostel);
  } catch (err) {
    res.status(500).json({ error: 'Failed to add feedback' });
  }
});

app.get('/api/images/:id', async (req, res) => {
  try {
    const fileId = new mongoose.Types.ObjectId(req.params.id);
    const file = await gfs.findOne({ _id: fileId });
    if (!file) return res.status(404).json({ error: 'Image not found' });

    res.set('Content-Type', file.metadata.contentType);
    const downloadStream = gridFSBucket.openDownloadStream(fileId);
    downloadStream.pipe(res);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve image' });
  }
});

app.post('/api/ratings', authenticate(['user']), async (req, res) => {
  try {
    const { hostel, rating, review } = req.body;
    
    if (!hostel || !rating) {
      return res.status(400).json({ 
        error: 'Hostel ID and rating are required'
      });
    }

    if (rating < 1 || rating > 5) {
      return res.status(400).json({ 
        error: 'Rating must be between 1 and 5'
      });
    }

    if (!mongoose.isValidObjectId(hostel)) {
      return res.status(400).json({ 
        error: 'Invalid hostel ID format'
      });
    }

    const hostelObjectId = new mongoose.Types.ObjectId(hostel);

    const hostelExists = await Hostel.exists({ _id: hostelObjectId });
    if (!hostelExists) {
      return res.status(404).json({ 
        error: 'Hostel not found'
      });
    }

    const existingRating = await Rating.findOne({
      userId: req.user._id,
      hostelId: hostelObjectId
    });

    if (existingRating) {
      return res.status(400).json({ 
        error: 'You have already rated this hostel'
      });
    }

    const newRating = new Rating({
      userId: req.user._id,
      hostelId: hostelObjectId,
      rating: parseInt(rating),
      review: review || undefined
    });

    await newRating.save();
    await updateHostelRating(hostelObjectId);
    
    res.status(201).json(newRating);
  } catch (err) {
    console.error('Rating submission error:', err);
    res.status(500).json({ 
      error: 'Failed to submit rating',
      details: err.message 
    });
  }
});
app.put('/api/owner/hostels/:id', authenticate(['owner']), upload.array('images', 10), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, email, location, district, contact, existingImages } = req.body;
    
    // Validate hostel ownership
    const existingHostel = await Hostel.findById(id);
    if (!existingHostel) {
      return res.status(404).json({ error: 'Hostel not found' });
    }
    
    if (existingHostel.ownerId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Not authorized to update this hostel' });
    }

    // Process images
    const imageUrls = [];
    
    // Handle existing images
    if (existingImages) {
      try {
        const parsedImages = JSON.parse(existingImages);
        if (Array.isArray(parsedImages)) {
          imageUrls.push(...parsedImages);
        }
      } catch (err) {
        console.error('Error parsing existing images:', err);
      }
    }

    // Handle new uploaded images
    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        try {
          const fileId = await storeImage(file);
          imageUrls.push(`/api/images/${fileId}`);
        } catch (err) {
          console.error('Error storing image:', err);
        }
      }
    }

    // Update hostel
    const updatedHostel = await Hostel.findByIdAndUpdate(id, {
      name,
      description,
      email,
      location,
      district,
      contact,
      images: imageUrls,
      updatedAt: Date.now()
    }, { new: true });

    res.json(updatedHostel);
  } catch (err) {
    console.error('Error updating hostel:', err);
    res.status(500).json({ error: 'Failed to update hostel' });
  }
});
app.put('/api/ratings/:id', authenticate(['user']), async (req, res) => {
  try {
    const ratingId = new mongoose.Types.ObjectId(req.params.id);
    
    const updatedRating = await Rating.findOneAndUpdate(
      { 
        _id: ratingId,
        userId: req.user._id
      },
      {
        rating: req.body.rating,
        review: req.body.review,
        updatedAt: Date.now()
      },
      { new: true }
    );

    if (!updatedRating) {
      return res.status(404).json({ error: 'Rating not found or not owned by user' });
    }

    await updateHostelRating(updatedRating.hostelId);
    
    res.json(updatedRating);
  } catch (err) {
    console.error('Error updating rating:', err);
    res.status(500).json({ 
      error: 'Failed to update rating',
      details: err.message 
    });
  }
});
app.put('/api/hostels/:hostelId/room-types/:roomTypeId', authenticate(['owner']), async (req, res) => {
  try {
    // Verify hostel ownership
    const hostel = await Hostel.findById(req.params.hostelId);
    if (!hostel) {
      return res.status(404).json({ error: 'Hostel not found' });
    }
    
    if (hostel.ownerId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Not authorized to update room types in this hostel' });
    }

    // Validate required fields
    const { name, price, capacity, available } = req.body;
    if (!name || price === undefined || capacity === undefined || available === undefined) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const roomType = await RoomType.findByIdAndUpdate(
      req.params.roomTypeId,
      {
        name,
        description: req.body.description || '',
        price: parseFloat(price),
        capacity: parseInt(capacity),
        available: parseInt(available)
      },
      { new: true }
    );

    if (!roomType) {
      return res.status(404).json({ error: 'Room type not found' });
    }

    await updateHostelPricing(req.params.hostelId);
    
    res.json(roomType);
  } catch (err) {
    console.error('Error updating room type:', err);
    res.status(500).json({ error: 'Failed to update room type' });
  }
});

app.delete('/api/hostels/:hostelId/room-types/:roomTypeId', authenticate(['owner']), async (req, res) => {
  try {
    // Verify hostel ownership
    const hostel = await Hostel.findById(req.params.hostelId);
    if (!hostel) {
      return res.status(404).json({ error: 'Hostel not found' });
    }
    
    if (hostel.ownerId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Not authorized to delete room types from this hostel' });
    }

    await RoomType.findByIdAndDelete(req.params.roomTypeId);
    await updateHostelPricing(req.params.hostelId);
    
    res.json({ message: 'Room type deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete room type' });
  }
});

// Admin routes
app.get('/api/admin/hostel-owners', authenticate(['admin']), async (req, res) => {
  try {
    const owners = await User.aggregate([
      { $match: { role: 'owner' } },
      {
        $lookup: {
          from: 'hostels',
          localField: '_id',
          foreignField: 'ownerId',
          as: 'hostels'
        }
      },
      {
        $project: {
          username: 1,
          email: 1,
          hostelCount: { $size: '$hostels' }
        }
      }
    ]);
    
    res.json(owners);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch hostel owners' });
  }
});

app.post('/api/admin/hostel-owners', authenticate(['admin']), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    if (!email || !/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
      return res.status(400).json({ error: 'Valid email is required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ 
      username, 
      email,
      password: hashedPassword,
      role: 'owner'
    });
    
    res.status(201).json(user);
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    res.status(400).json({ error: 'Failed to create owner' });
  }
});

app.delete('/api/admin/hostel-owners/:id', authenticate(['admin']), async (req, res) => {
  try {
    // Check if owner has hostels
    const hostels = await Hostel.find({ ownerId: req.params.id });
    if (hostels.length > 0) {
      return res.status(400).json({ error: 'Cannot delete owner with hostels' });
    }
    
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: 'Owner deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete owner' });
  }
});

app.get('/api/admin/hostels', authenticate(['admin']), async (req, res) => {
  try {
    const hostels = await Hostel.find()
      .populate('ownerId', 'username email')
      .sort({ createdAt: -1 });
    res.json(hostels);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch hostels' });
  }
});

app.get('/api/admin/analytics', authenticate(['admin']), async (req, res) => {
  try {
    const [totalHostels, totalUsers, totalOwners] = await Promise.all([
      Hostel.countDocuments(),
      User.countDocuments({ role: 'user' }),
      User.countDocuments({ role: 'owner' })
    ]);
    
    res.json({
      totalHostels,
      totalUsers,
      totalOwners
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get analytics' });
  }
});

initializeDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
});