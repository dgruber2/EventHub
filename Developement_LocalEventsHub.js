// LocalEventsHub - A secure platform for local event management
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// Application configuration
const config = {
    name: 'LocalEventsHub',
    version: '1.0.0',
    description: 'A secure platform for creating and discovering local events',
    maxEventsPerUser: 10,
    maxInterestedPerEvent: 1000,
    defaultPaginationLimit: 10
};

// Security middleware
app.use(helmet());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// MongoDB User Schema with password hashing
const userSchema = new mongoose.Schema({
    //basic user info
    username: { 
        type: String, 
        required: true, 
        unique: true,
        trim: true,
        minlength: 3
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        required: true,
        minlength: 8
    },

    //profile info
    profile: {
        name: String,
        bio: String,
        location: String,
        interests: [String]
    },

    //lockout fields
    failedLoginAttempts: {
        type: Number,
        default:0 //start at zero, increment with each failed attempt
    },
    isLocked: {
        type: Boolean,
        default: false //locked state of account
    },
    lockUntil: {
        type: Date //date and time until account is locked
    },
    //token version tracker after logout
    tokenVersion: {
        type: Number,
        default: 0 //initialize with zero
    },

    //event info
   eventsCreated: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Event'
    }],
    interestedEvents: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Event'
    }],
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 12);
    }
    next();
});

// Event Schema with enhanced validation
const eventSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        trim: true,
        minlength: 3,
        maxlength: 100
    },
    description: {
        type: String,
        required: true,
        trim: true,
        maxlength: 2000
    },
    date: {
        type: Date,
        required: true,
        validate: {
            validator: function(v) {
                return v > new Date();
            },
            message: 'Event date must be in the future'
        }
    },
    endDate: {
        type: Date,
        validate: {
            validator: function(v) {
                return !v || v > this.date;
            },
            message: 'End date must be after start date'
        }
    },
    location: {
        address: {
            type: String,
            required: true,
            trim: true
        },
        city: {
            type: String,
            required: true,
            trim: true
        },
        state: {
            type: String,
            required: true,
            trim: true
        },
        coordinates: {
            latitude: Number,
            longitude: Number
        }
    },
    category: {
        type: String,
        required: true,
        enum: ['Social', 'Professional', 'Educational', 'Sports', 'Entertainment', 'Other']
    },
    creator: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    interestedUsers: [{
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        status: {
            type: String,
            enum: ['interested', 'going', 'maybe'],
            default: 'interested'
        },
        dateAdded: {
            type: Date,
            default: Date.now
        }
    }],
    maxParticipants: {
        type: Number,
        min: 1,
        max: config.maxInterestedPerEvent
    },
    tags: [{
        type: String,
        trim: true
    }],
    visibility: {
        type: String,
        enum: ['public', 'private', 'unlisted'],
        default: 'public'
    },
    status: {
        type: String,
        enum: ['draft', 'published', 'cancelled', 'completed'],
        default: 'published'
    }
}, {
    timestamps: true
});

const User = mongoose.model('User', userSchema);
const Event = mongoose.model('Event', eventSchema);

// Enhanced authentication middleware with role checking
const authenticate = async (req, res, next) => {
    try {
        const token = req.header('Authorization').replace('Bearer ', '');
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findOne({ _id: decoded.id });

        if (!user) {
            throw new Error();
        }

        req.user = user;
        req.token = token;
        next();
    } catch (error) {
        res.status(401).send({ 
            error: 'Please authenticate.',
            application: config.name
        });
    }
};

// Enhanced validation middleware for event creation
const validateEvent = [
    body('title').trim().isLength({ min: 3, max: 100 }).escape(),
    body('description').trim().isLength({ max: 2000 }).escape(),
    body('date').isISO8601().toDate(),
    body('endDate').optional().isISO8601().toDate(),
    body('location.address').trim().notEmpty().escape(),
    body('location.city').trim().notEmpty().escape(),
    body('location.state').trim().notEmpty().escape(),
    body('category').isIn(['Social', 'Professional', 'Educational', 'Sports', 'Entertainment', 'Other']),
    body('maxParticipants').optional().isInt({ min: 1, max: config.maxInterestedPerEvent }),
    body('tags').optional().isArray(),
    body('tags.*').optional().trim().escape(),
    body('visibility').optional().isIn(['public', 'private', 'unlisted'])
];

// Application Info endpoint
app.get('/api/info', (req, res) => {
    res.json({
        name: config.name,
        version: config.version,
        description: config.description
    });
});

// User registration with enhanced validation
app.post('/api/users/register', [
    body('username').trim().isLength({ min: 3 }).escape(),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 })
        .matches(/^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!@#$%^&*])/)
        .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
    body('profile.name').optional().trim().escape(),
    body('profile.bio').optional().trim().escape(),
    body('profile.location').optional().trim().escape(),
    body('profile.interests').optional().isArray()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        //create a new user and save to the database
        const user = new User(req.body);
        await user.save();

        //generate a JWT including token tokenVersion
        const token = jwt.sign({ 
            id: user._id,
            tokenVersion: user.tokenVersion //include tokenVersion in the token
             }, process.env.JWT_SECRET, {
            expiresIn: '24h'
        });

        //respond with newly created user and token
        res.status(201).send({ 
            message: `Welcome to ${config.name}!`,
            user, 
            token 
        });
    } catch (error) {
        // using a switch statement so if there are other error codes that need to be handled we are able to.
        switch(error.code) {
            case 11000:
                res.status(400).send({ error: 'Username or email already exists' });
                break;
            default:
                res.status(400).send(error);
                break;
        }
    }
});

//User Login with account lockout mechanism, token versioning, and rate limiting
app.post('/api/users/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });

        // Check if user exists
        if (!user) {
            return res.status(400).send({ error: 'Invalid email or password' });
        }

        // Check if account is locked
        if (user.isLocked && user.lockUntil > Date.now()) {
            return res.status(403).send({
                error: 'Account is locked. Try later.',
                unlockAt: user.lockUntil
            });
        }

        // Compare password
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            // Increment failed login attempts
            user.failedLoginAttempts += 1;

            // Lock account if max attempts reached
            const MAX_ATTEMPTS = 5;
            const LOCK_TIME = 30 * 60 * 1000; // 30 minute lockout time

            if (user.failedLoginAttempts >= MAX_ATTEMPTS) {
                user.isLocked = true;
                user.lockUntil = Date.now() + LOCK_TIME;
                await user.save();
                return res.status(403).send({
                    error: 'Account locked due to too many failed attempts. Try again later.'
                });
            }

            // Save user data if login attempt failed
            await user.save();

            return res.status(400).send({ error: 'Invalid email or password' });
        }

        // Successful login - reset failed login attempts
        user.failedLoginAttempts = 0;
        user.isLocked = false;
        user.lockUntil = null;
        await user.save();

        // Generate JWT with tokenVersion
        const token = jwt.sign({ 
            id: user._id,
            tokenVersion: user.tokenVersion //include tokenVersion in the token
             }, process.env.JWT_SECRET, {
            expiresIn: '24h'
        });

        res.status(200).send({ message: 'Login successful!', user, token });
    } catch (error) {
        res.status(500).send({ error: 'Server error. Please try again later.' });
    }
});

//user logout, invalidating tokens by incrementing tokenVersion
app.post('/api/users/logout', authenticate, async (req, res) => {
    try {
        req.user.tokenVersion += 1; //invalidate all previous tokens
        await req.user.save();

        res.send({ message: 'Logged out successfully.'});
    } catch (error) {
        res.status(500).send({ error: 'Logout failed. Please try again.'});
    }
});

// Additional routes remain the same as in previous version...
// (User login, Create event, Show interest in event, Get all events)

// Custom error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send({
        error: 'Something went wrong!',
        application: config.name
    });
});

// Connect to MongoDB and start server
const PORT = process.env.PORT || 3000;
mongoose.connect(process.env.MONGODB_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    app.listen(PORT, () => {
        console.log(`${config.name} server  running on port ${PORT}`);
    });
}).catch((error) => {
    console.log(`Error connecting to ${config.name} database:`, error);
});