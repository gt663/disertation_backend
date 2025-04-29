/******************************************************************************
 * MAIN SERVER FILE FOR AQUATIC PET SHOP APPLICATION
 * 
 * This file contains all the server-side logic including:
 * - Express server configuration
 * - MongoDB connection
 * - Authentication system
 * - API routes for products, orders, bookings
 * - Admin management endpoints
 * - Payment processing
 ******************************************************************************/

// ============================================================================
// SECTION 1: REQUIRED MODULES AND INITIAL CONFIGURATION
// ============================================================================

// Core modules
const path = require('path');
const fs = require('fs');

// Third-party modules
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const propertiesReader = require('properties-reader');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');

// ============================================================================
// SECTION 2: EXPRESS SERVER SETUP
// ============================================================================

// Initialize Express application
const app = express();

// CORS Configuration
const corsOptions = {
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST', 'PUT', 'OPTIONS'],
    credentials: true
};
app.use(cors(corsOptions));

// Body parser middleware for JSON
app.use(bodyParser.json());

// ============================================================================
// SECTION 3: MIDDLEWARES
// ============================================================================

/**
 * Logger middleware to log all incoming requests
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const logger = (req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
};
app.use(logger);

// Static files configuration
app.use('/images', express.static(path.join(__dirname, 'public/images')));

// Image not found handler
app.use((req, res, next) => {
    const imagePath = path.join(__dirname, 'public/images', req.url);
    if (req.url.startsWith('/images') && !fs.existsSync(imagePath)) {
        return res.status(404).json({ error: 'Image not found' });
    }
    next();
});

// ============================================================================
// SECTION 4: DATABASE CONNECTION
// ============================================================================

// MongoDB Configuration
require('dotenv').config();
const uri = process.env.MONGODB_URI;

const client = new MongoClient(uri);

let db; // Global database connection variable

// Connect to MongoDB Atlas
client.connect().then(() => {
    db = client.db('aquatic_pet_shop');
    console.log('Connected to MongoDB Atlas');
}).catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
});

// ============================================================================
// SECTION 5: AUTHENTICATION CONFIGURATION
// ============================================================================

const JWT_SECRET = 'your_strong_jwt_secret_here'; // Change this in production!

/**
 * Authentication middleware with role-based access control
 * @param {Array} roles - Array of allowed roles
 * @returns {Function} Express middleware function
 */
const authenticate = (roles = []) => {
    return async (req, res, next) => {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ error: 'No token provided' });

        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            const user = await db.collection('users').findOne({ username: decoded.username });
            
            if (!user || (roles.length && !roles.includes(user.role))) {
                return res.status(403).json({ error: 'Access denied' });
            }

            req.user = user;
            next();
        } catch (err) {
            res.status(401).json({ error: 'Invalid token' });
        }
    };
};

// ============================================================================
// SECTION 6: CORE ROUTES
// ============================================================================

// Root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../index.html'));
});

// ============================================================================
// SECTION 7: AUTHENTICATION ROUTES
// ============================================================================

/**
 * POST /api/auth/signup - User registration endpoint
 * @param {string} username - User's username
 * @param {string} password - User's password (5-9 characters)
 * @param {string} email - User's email
 * @returns {Object} - JWT token and user role
 */
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { username, password, email } = req.body;
        
        // Validation
        if (!username || !password || !email) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        if (password.length < 5 || password.length > 9) {
            return res.status(400).json({ error: 'Password must be 5-9 characters' });
        }

        // Check if user exists
        const existingUser = await db.collection('users').findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        // Hash password and create user
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.collection('users').insertOne({
            username,
            password: hashedPassword,
            email,
            role: 'customer'
        });

        // Generate token
        const token = jwt.sign({ username, role: 'customer' }, JWT_SECRET, { expiresIn: '1h' });
        res.status(201).json({ token, role: 'customer' });
    } catch (err) {
        console.error('Signup error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

/**
 * POST /api/auth/login - User login endpoint
 * @param {string} username - User's username
 * @param {string} password - User's password
 * @param {boolean} isAdmin - Flag for admin login
 * @returns {Object} - JWT token and user role
 */
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password, isAdmin } = req.body;
        const user = await db.collection('users').findOne({ username });

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check password
        const passwordValid = await bcrypt.compare(password, user.password);
        if (!passwordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Role check for admin
        if (isAdmin && user.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        // Generate token
        const token = jwt.sign({ username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, role: user.role });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ============================================================================
// SECTION 8: ADMIN ROUTES
// ============================================================================

/**
 * GET /api/admin/dashboard - Admin dashboard statistics
 * @requires admin role
 * @returns {Object} - Count of users and orders
 */
app.get('/api/admin/dashboard', authenticate(['admin']), async (req, res) => {
    try {
        const users = await db.collection('users').countDocuments();
        const orders = await db.collection('product_order_info').countDocuments();
        res.json({ users, orders });
    } catch (err) {
        console.error('Admin dashboard error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ============================================================================
// SECTION 9: PRODUCT ROUTES
// ============================================================================

/**
 * GET /api/product_info - Get products with optional filtering
 * @param {string} type - Product type to filter by ('fish', 'plant', etc.)
 * @returns {Array} - List of products
 */
app.get('/api/product_info', async (req, res) => {
    try {
        const { type } = req.query;
        const query = type === 'all' ? {} : (type ? { type } : { type: 'fish' });
        const products = await db.collection('product_info').find(query).toArray();
        res.json(products);
    } catch (err) {
        console.error('Error fetching products:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

/**
 * POST /api/product_info - Create new product (for admin)
 * @param {string} subject - Product name
 * @param {number} price - Product price
 * @param {string} location - Product location
 * @param {string} type - Product type
 * @param {string} img - Product image filename
 * @param {number} avail - Available quantity
 * @returns {Object} - Success message and product ID
 */
app.post('/api/product_info', async (req, res) => {
    try {
        // Validate required fields
        const { subject, price, location, type, img, avail } = req.body;
        
        if (!subject || !price || !type) {
            return res.status(400).json({ error: 'Subject, price and type are required' });
        }

        // Create new product document
        const newProduct = {
            subject,
            price: Number(price),
            location: location || 'Default Location',
            type,
            img: img || 'default.jpg',
            avail: Number(avail) || 0,
            createdAt: new Date()
        };

        // Insert into MongoDB
        const result = await db.collection('product_info').insertOne(newProduct);
        
        res.status(201).json({
            message: 'Product created successfully',
            productId: result.insertedId
        });
    } catch (err) {
        console.error('Error creating product:', err);
        res.status(500).json({ error: 'Failed to create product' });
    }
});

/**
 * PUT /api/product_info/:id - Update product information
 * @param {string} id - Product ID
 * @param {Object} updateData - Fields to update
 * @returns {Object} - Success status
 */
app.put('/api/product_info/:id', async (req, res) => {
    try {
        if (!ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid ID format' });
        }

        // Remove _id if somehow it exists in body
        const { _id, ...updateData } = req.body;

        const result = await db.collection('product_info').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: updateData }
        );

        if (result.modifiedCount === 0) {
            return res.status(404).json({ error: 'No changes made or product not found' });
        }

        res.json({ success: true });
    } catch (err) {
        console.error('Server update error:', err);
        res.status(500).json({ error: 'Database update failed' });
    }
});

/**
 * DELETE /api/product_info/:id - Delete a product
 * @param {string} id - Product ID to delete
 * @returns {Object} - Success message
 */
app.delete('/api/product_info/:id', async (req, res) => {
    try {
        const result = await db.collection('product_info').deleteOne({ 
            _id: new ObjectId(req.params.id) 
        });
        
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        res.json({ message: 'Product deleted successfully' });
    } catch (err) {
        console.error('Delete product error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

/**
 * GET /api/product_info/find - Search for product by name
 * @param {string} name - Product name to search for
 * @returns {Object} - Product information
 */
app.get('/api/product_info/find', async (req, res) => {
    try {
        const { name } = req.query;
        if (!name) {
            return res.status(400).json({ error: 'Product name is required' });
        }
        
        const product = await db.collection('product_info').findOne({ 
            subject: new RegExp(name, 'i') // Case-insensitive search
        });
        
        if (!product) {
            return res.status(404).json({ error: 'Product not found' });
        }
        
        res.json(product);
    } catch (err) {
        console.error('Find product error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

/**
 * PUT /api/update_lesson - Update product availability
 * @param {string} subject - Product name
 * @param {number} avail - New availability count
 * @returns {Object} - Success message
 */
app.put('/api/update_lesson', async (req, res) => {
    try {
        const { subject, avail } = req.body;
        const result = await db.collection('product_info').updateOne(
            { subject }, 
            { $set: { avail } }
        );

        if (result.modifiedCount === 0) {
            return res.status(404).json({ error: 'Product not found or availability not updated' });
        }
        res.json({ message: 'Product availability updated' });
    } catch (err) {
        console.error('Update error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

/**
 * GET /api/search - Search products by name or location
 * @param {string} q - Search query
 * @returns {Array} - Matching products
 */
app.get('/api/search', async (req, res) => {
    try {
        const query = req.query.q.toLowerCase();
        const products = await db.collection('product_info').find({}).toArray();
        const results = products.filter(p => 
            p.subject.toLowerCase().includes(query) || 
            p.location.toLowerCase().includes(query)
        );
        res.json(results);
    } catch (err) {
        console.error('Search error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ============================================================================
// SECTION 10: ORDER ROUTES
// ============================================================================

/**
 * POST /api/orders - Create a new order
 * @param {Object} orderData - Order information
 * @returns {Object} - Success message
 */
app.post('/api/orders', async (req, res) => {
    try {
        await db.collection('product_order_info').insertOne(req.body);
        res.status(201).json({ message: 'Order placed successfully' });
    } catch (err) {
        console.error('Error saving order:', err);
        res.status(500).json({ error: 'Failed to place order' });
    }
});

/**
 * GET /api/orders/search - Search orders by customer name
 * @param {string} name - Customer name to search for
 * @returns {Array} - Matching orders
 */
app.get('/api/orders/search', async (req, res) => {
    try {
        const { name, status } = req.query;
        let query = {};
        
        if (name) {
            query.name = new RegExp(name, 'i');
        }
        
        if (status === 'collected') {
            query.status = 'collected';
        } else if (status === 'pending') {
            query.status = { $exists: false };
        }
        
        const orders = await db.collection('product_order_info')
            .find(query)
            .toArray();
        res.json(orders);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/**
 * PUT /api/orders/:id/collect - Mark order as collected
 * @param {string} id - Order ID
 * @returns {Object} - Success status
 */
app.put('/api/orders/:id/collect', async (req, res) => {
    try {
        const result = await db.collection('product_order_info')
            .updateOne(
                { _id: new ObjectId(req.params.id) },
                { $set: { status: 'collected', collectedAt: new Date() } }
            );
        
        if (result.modifiedCount === 0) {
            return res.status(404).json({ error: 'Order not found' });
        }
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================================================
// SECTION 11: BOOKING ROUTES
// ============================================================================

/**
 * POST /api/bookings - Create a new booking
 * @param {string} date - Booking date
 * @param {Object} bookingData - Other booking information
 * @returns {Object} - Success message
 */
app.post('/api/bookings', async (req, res) => {
    try {
        const { date } = req.body;
        
        // Validate date
        const bookingDate = new Date(date);
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        if (isNaN(bookingDate.getTime())) {
            return res.status(400).json({ error: 'Invalid date format' });
        }
        
        if (bookingDate < today) {
            return res.status(400).json({ error: 'Booking date cannot be in the past' });
        }

        const bookingData = {
            ...req.body,
            date: bookingDate, // Ensure proper date format
            createdAt: new Date(),
            status: 'pending'
        };
        
        await db.collection('bookings').insertOne(bookingData);
        res.status(201).json({ message: 'Booking created successfully' });
    } catch (err) {
        console.error('Booking creation error:', err);
        res.status(500).json({ error: 'Failed to create booking' });
    }
});

/**
 * GET /api/bookings - Get bookings with optional filtering
 * @param {string} filter - Filter type ('pending', 'completed', or 'all')
 * @returns {Array} - List of bookings
 */
app.get('/api/bookings', async (req, res) => {
    try {
        const filter = req.query.filter || 'all';
        let query = {};
        
        if (filter === 'pending') {
            query = { status: 'pending' };
        } else if (filter === 'completed') {
            query = { status: 'completed' };
        }
        
        const bookings = await db.collection('bookings').find(query).toArray();
        res.json(bookings);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/**
 * GET /api/bookings/search - Search bookings by telephone number
 * @param {string} telephone - Telephone number to search for
 * @returns {Array} - Matching bookings
 */
app.get('/api/bookings/search', async (req, res) => {
    try {
        const { telephone } = req.query;
        
        if (!telephone) {
            return res.status(400).json({ error: 'Telephone number is required' });
        }
        
        // Search for exact telephone number match
        const bookings = await db.collection('bookings')
            .find({ telephone })
            .toArray();
            
        res.json(bookings);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/**
 * PUT /api/bookings/:id - Update booking status
 * @param {string} id - Booking ID
 * @param {string} status - New status ('pending', 'completed')
 * @returns {Object} - Success status
 */
app.put('/api/bookings/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;
        
        const result = await db.collection('bookings').updateOne(
            { _id: new ObjectId(id) },
            { $set: { status } }
        );
        
        if (result.modifiedCount === 0) {
            return res.status(404).json({ error: 'Booking not found or not modified' });
        }
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================================================
// SECTION 12: PAYMENT ROUTES
// ============================================================================

/**
 * POST /api/verify-payment - Verify PayPal payment (mock for sandbox)
 * @param {string} orderID - PayPal order ID
 * @returns {Object} - Payment verification status
 */
app.post('/api/verify-payment', async (req, res) => {
    try {
        const { orderID } = req.body;
        
        // In production, you would verify with PayPal API here
        // For sandbox, we'll just mock a successful verification
        res.json({
            status: 'COMPLETED',
            orderID,
            amount: req.body.amount,
            currency: 'USD'
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================================================
// SECTION 13: SERVER STARTUP AND CLEANUP
// ============================================================================

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Cleanup on exit
process.on('SIGINT', async () => {
    await client.close();
    console.log('MongoDB connection closed');
    process.exit();
});