// server.js - Express API for Tech Details and Events
import dotenv from "dotenv";
dotenv.config(); // Load environment variables first

import express, { json } from "express";
import cors from "cors";
import mongoose from "mongoose";
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import fsp from 'fs/promises'; // Use fs.promises for async file operations
import { fileURLToPath } from 'url';
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import Joi from "joi";

// Import all models
import { TechDetail, Event, User } from "./models.js"; // Ensure models.js path is correct

// --- Core Setup & Configuration ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const UPLOADS_DIR = path.join(__dirname, 'uploads');
const PORT = process.env.PORT || 5001;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Validate essential environment variables
if (!MONGO_URI || !JWT_SECRET) {
    console.error("FATAL ERROR: MONGO_URI or JWT_SECRET is not defined in .env file.");
    process.exit(1);
}

// --- Middleware Setup ---
app.use(cors());
app.use(json());
app.use('/uploads', express.static(UPLOADS_DIR)); // Serve uploaded files

// --- MongoDB Connection ---
mongoose.connect(MONGO_URI)
    .then(() => console.log(`🔌 Connected to MongoDB`))
    .catch((err) => {
        console.error("❌ MongoDB Connection Error:", err);
        process.exit(1);
    });

// --- Helper Functions ---

// Basic async error wrapper for route handlers
const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Generates the next sequential ID (e.g., GENRE-1) for a technology genre
const generateNewDocket = async (genre) => {
    if (!genre || typeof genre !== 'string' || !genre.trim()) {
        throw new Error("Invalid genre provided for docket generation.");
    }
    // Sanitize genre: alphanumeric only, uppercase
    const sanitizedGenre = genre.trim().replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
    if (!sanitizedGenre) {
        throw new Error("Genre contains invalid characters or is empty after sanitization.");
    }

    // Find the latest tech detail with a docket matching the pattern GENRE-NUMBER
    const latestTech = await TechDetail.findOne({ docket: new RegExp(`^${sanitizedGenre}-(\\d+)$`) })
        .sort({ createdAt: -1 }) // Get the most recently created one
        .select('docket')        // Only need the docket field
        .lean();                 // Use lean for performance

    let nextTechNumber = 1;
    if (latestTech?.docket) {
        const match = latestTech.docket.match(/-(\d+)$/);
        if (match) {
            const lastNumber = parseInt(match[1], 10);
            if (!isNaN(lastNumber)) {
                nextTechNumber = lastNumber + 1;
            }
        }
    }
    return `${sanitizedGenre}-${nextTechNumber}`;
};


// Parses specific string fields from form data into arrays/objects if they are JSON strings
// Falls back to comma-separated for simple array fields if JSON parsing fails
const parseTechDataFields = (data) => {
    const fieldsToParse = ['advantages', 'applications', 'useCases', 'innovators', 'relatedLinks', 'existingImages']; // Added existingImages
    const arrayFields = ['advantages', 'applications', 'useCases']; // Basic arrays
    const objectArrayFields = ['innovators', 'relatedLinks', 'existingImages']; // Arrays of objects

    fieldsToParse.forEach(field => {
        if (data[field] && typeof data[field] === 'string') {
            try {
                const parsed = JSON.parse(data[field]);
                // Ensure array fields are actually arrays after parsing
                if ((arrayFields.includes(field) || objectArrayFields.includes(field)) && !Array.isArray(parsed)) {
                    data[field] = []; // Default to empty array if parsing gives non-array (e.g., 'null')
                } else {
                    data[field] = parsed;
                }
            } catch (e) {
                // Fallback: If it's a basic array field and not valid JSON, try splitting by comma
                if (arrayFields.includes(field)) {
                    data[field] = data[field].split(',').map(item => item.trim()).filter(Boolean);
                }
                // For object arrays or non-array fields, failed JSON parsing means keep as original string (or handle as error later if needed)
                // console.warn(`Field '${field}' could not be parsed as JSON and is not a simple array field.`);
            }
        } else if ((arrayFields.includes(field) || objectArrayFields.includes(field)) && !data[field]) {
            // Ensure array fields default to empty array if missing or empty
            data[field] = [];
        }
    });
    return data;
};


// Maps uploaded files and captions to the image schema format
const mapFilesToImageData = (files = [], body = {}) => {
    return files.map((file, index) => ({
        url: `/uploads/${file.filename}`,
        // Assumes captions are sent as 'imageCaptions[0]', 'imageCaptions[1]', etc.
        caption: body[`imageCaptions[${index}]`] || ''
    }));
};

// Deletes physical image files asynchronously
const deleteImageFiles = async (images = []) => {
    const deletionPromises = images.map(image => {
        if (image?.url) {
            const relativePath = image.url.startsWith('/') ? image.url.substring(1) : image.url;
            const imagePath = path.join(__dirname, relativePath);
            return fsp.unlink(imagePath).catch(err => {
                // Log error but don't stop other deletions
                if (err.code !== 'ENOENT') { // Ignore 'file not found' errors
                     console.error(`❌ Error deleting image ${imagePath}:`, err);
                }
            });
        }
        return Promise.resolve(); // Return resolved promise for invalid entries
    });
    await Promise.all(deletionPromises); // Wait for all deletions
};

// --- Multer Configuration (File Uploads) ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        fs.mkdirSync(UPLOADS_DIR, { recursive: true }); // Ensure directory exists
        cb(null, UPLOADS_DIR);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, `tech-${uniqueSuffix}${path.extname(file.originalname)}`);
    }
});

const fileFilter = (req, file, cb) => {
    if (!file.originalname.match(/\.(jpg|jpeg|png|gif|webp)$/i)) {
        // Attach error to request for specific handling in middleware
        req.fileValidationError = 'Invalid file type. Only JPG, JPEG, PNG, GIF, WEBP allowed.';
        return cb(new Error(req.fileValidationError), false);
    }
    cb(null, true);
};

const upload = multer({
    storage,
    fileFilter,
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit per file
});

// Multer middleware instance for handling 'images' field (up to 5 files)
const handleMulterUpload = upload.array('images', 5);

// Middleware to handle Multer-specific errors gracefully
const multerErrorHandler = (err, req, res, next) => {
    if (req.fileValidationError) { // Custom error from fileFilter
        return res.status(400).json({ message: req.fileValidationError });
    }
    if (err instanceof multer.MulterError) {
        let message = 'File upload error.';
        if (err.code === 'LIMIT_FILE_SIZE') message = 'File size exceeds 5MB limit.';
        else if (err.code === 'LIMIT_UNEXPECTED_FILE') message = 'Unexpected field or too many files (max 5).';
        return res.status(400).json({ message, code: err.code });
    }
    if (err) { // Pass other errors to the global handler
        return next(err);
    }
    next(); // No Multer error
};

// --- Joi Validation Schemas ---
const authSchemas = {
    signup: Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().min(6).required(),
    }),
    login: Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().required(), // Min length checked during bcrypt comparison
    })
};

// Middleware factory to validate request body against a Joi schema
const validateBody = (schemaName) => (req, res, next) => {
    const schema = authSchemas[schemaName];
    if (!schema) {
        console.error(`Schema ${schemaName} not found`); // Should not happen
        return next(new Error(`Server configuration error: Schema ${schemaName} missing.`));
    }
    const { error } = schema.validate(req.body);
    if (error) {
        return res.status(400).json({ message: "Validation Error", error: error.details[0].message, success: false });
    }
    next();
};

// --- Auth Controller ---

const signup = async (req, res) => {
    const { email, password } = req.body;
    const lowerCaseEmail = email.toLowerCase();
    const existingUser = await User.findOne({ email: lowerCaseEmail });
    if (existingUser) {
        return res.status(409).json({ message: "Email already registered.", success: false });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ email: lowerCaseEmail, password: hashedPassword });
    res.status(201).json({ message: "Signup successful!", success: true });
};

const login = async (req, res) => {
    const { email, password } = req.body;
    const lowerCaseEmail = email.toLowerCase();
    const user = await User.findOne({ email: lowerCaseEmail });

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: "Authentication failed. Invalid email or password.", success: false });
    }

    const payload = { email: user.email, userId: user._id };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
    res.status(200).json({
        message: "Login successful!",
        success: true,
        token,
        user: { email: user.email, id: user._id } // Send back basic user info
    });
};

// --- API Routes ---

// Auth
app.post("/auth/signup", validateBody('signup'), asyncHandler(signup));
app.post("/auth/login", validateBody('login'), asyncHandler(login));

// --- Technology CRUD ---

// GET /technologies - List all technologies
app.get("/technologies", asyncHandler(async (req, res) => {
    const techs = await TechDetail.find({}).sort({ createdAt: -1 });
    res.json(techs);
}));

// GET /technologies/:id - Get a single technology by its unique ID (docket)
app.get("/technologies/:id", asyncHandler(async (req, res) => {
    // Use the 'id' field which should be unique (enforced by schema/logic)
    const tech = await TechDetail.findOne({ id: req.params.id });
    if (!tech) {
        return res.status(404).json({ message: "Technology not found" });
    }
    res.json(tech);
}));

// POST /technologies - Create a new technology
app.post("/technologies", handleMulterUpload, multerErrorHandler, asyncHandler(async (req, res, next) => {
    // Parse specific fields before validation or processing
    let techData = parseTechDataFields({ ...req.body });
    const { genre } = techData;

    if (!genre || typeof genre !== 'string' || !genre.trim()) {
        return res.status(400).json({ message: "Genre is required to create a technology." });
    }

    try {
        const newDocket = await generateNewDocket(genre);
        techData.docket = newDocket;
        techData.id = newDocket; // Use the generated docket as the unique ID
        techData.images = mapFilesToImageData(req.files, req.body); // Process uploaded images

        const newTech = new TechDetail(techData);
        const savedTech = await newTech.save();
        res.status(201).json(savedTech);
    } catch (error) {
        // Handle potential duplicate key error specifically for the generated ID
        if (error.code === 11000 && error.keyPattern?.id) {
             return res.status(409).json({ message: `Failed to create: ID ${techData.id} conflict (likely race condition). Please try again.` });
        }
        next(error); // Pass other errors (like validation) to the global handler
    }
}));

// PUT /technologies/:id - Update an existing technology
app.put("/technologies/:id", handleMulterUpload, multerErrorHandler, asyncHandler(async (req, res, next) => {
    const currentId = req.params.id; // The ID of the tech being updated
    let incomingData = parseTechDataFields({ ...req.body }); // Parse fields like arrays, including 'existingImages'

    const currentTech = await TechDetail.findOne({ id: currentId });
    if (!currentTech) {
        return res.status(404).json({ message: `Technology with ID ${currentId} not found` });
    }

    const oldGenre = currentTech.genre;
    const newGenre = incomingData.genre ? incomingData.genre.trim() : oldGenre; // Use new genre if provided, else keep old
    let finalUpdateData = { ...incomingData }; // Start with all incoming data
    let newGeneratedId = null;

    // --- Handle Potential ID/Docket Change due to Genre Change ---
    if (newGenre.toUpperCase() !== oldGenre.toUpperCase()) {
        try {
            newGeneratedId = await generateNewDocket(newGenre);
            // Check if this new ID already exists *excluding the current document*
            const existingWithNewId = await TechDetail.findOne({ id: newGeneratedId, _id: { $ne: currentTech._id } }).lean();
            if (existingWithNewId) {
                 return res.status(409).json({ message: `Update conflict: Generated ID ${newGeneratedId} for new genre already exists.` });
            }
            finalUpdateData.docket = newGeneratedId;
            finalUpdateData.id = newGeneratedId; // Update ID
            finalUpdateData.genre = newGenre; // Ensure new genre is saved
        } catch (error) {
            return next(new Error(`Failed to generate new docket for genre '${newGenre}': ${error.message}`));
        }
    } else {
        // Genre hasn't changed, explicitly remove id/docket from update data
        // to prevent accidental modification and ensure `id` remains the unique key.
        delete finalUpdateData.id;
        delete finalUpdateData.docket;
        finalUpdateData.genre = oldGenre; // Ensure genre (even if same case) is explicitly set
    }

    // --- Handle Image Updates ---
    const newlyUploadedImages = mapFilesToImageData(req.files, req.body);

    // `existingImages` should be an array of {url, caption} objects sent from frontend
    // representing images to keep (potentially with updated captions).
    const imagesToKeepFromRequest = Array.isArray(finalUpdateData.existingImages) ? finalUpdateData.existingImages : [];

    // Determine which images currently in the DB are *not* in the keep list
    const currentImageUrls = currentTech.images?.map(img => img.url) || [];
    const urlsToKeep = imagesToKeepFromRequest.map(img => img?.url).filter(Boolean);
    const urlsToDelete = currentImageUrls.filter(url => !urlsToKeep.includes(url));
    const imagesToDelete = currentTech.images?.filter(img => urlsToDelete.includes(img.url)) || [];

    // Delete physical files for removed images
    await deleteImageFiles(imagesToDelete);

    // Combine images kept (with potentially updated captions) and new uploads
    finalUpdateData.images = [...imagesToKeepFromRequest, ...newlyUploadedImages];
    delete finalUpdateData.existingImages; // Clean up temporary field

    // --- Perform Update ---
    try {
        const updatedTech = await TechDetail.findOneAndUpdate(
            { id: currentId },       // Find by the original ID
            { $set: finalUpdateData }, // Use $set for cleaner update
            { new: true, runValidators: true } // Return updated doc, run schema validators
        );

        if (!updatedTech) { // Should be rare if findOne check passed, but handles race conditions
            return res.status(404).json({ message: "Technology not found during final update attempt." });
        }
        res.json(updatedTech);
    } catch (error) {
        // Handle potential duplicate key error if the *new* ID conflicts (only if genre changed)
        if (error.code === 11000 && newGeneratedId && error.keyPattern?.id) {
            return res.status(409).json({ message: `Update failed: Conflict with generated ID ${newGeneratedId}.` });
        }
        next(error); // Pass validation or other errors
    }
}));

// DELETE /technologies/:id - Delete a technology
app.delete("/technologies/:id", asyncHandler(async (req, res) => {
    const techId = req.params.id;
    const tech = await TechDetail.findOne({ id: techId });
    if (!tech) {
        return res.status(404).json({ message: "Technology not found" });
    }

    // Delete associated image files first
    await deleteImageFiles(tech.images);

    // Delete the database record
    const deletionResult = await TechDetail.deleteOne({ id: techId });
    if (deletionResult.deletedCount === 0) {
        // Should be rare if findOne worked, but handles race conditions
        return res.status(404).json({ message: "Technology not found during deletion attempt." });
    }
    res.json({ message: "Technology deleted successfully", id: techId });
}));

// --- Event CRUD --- (Kept simple)

app.get("/events", asyncHandler(async (req, res) => {
    const events = await Event.find({}).sort({ day: 1, title: 1 }); // Example sort
    res.json(events);
}));

app.get("/events/:title/:day", asyncHandler(async (req, res) => {
    const { title, day } = req.params;
    const event = await Event.findOne({ title, day });
    if (!event) return res.status(404).json({ message: "Event not found" });
    res.json(event);
}));

app.post("/events", asyncHandler(async (req, res) => {
    // Add validation if needed (e.g., using Joi)
    const newEvent = new Event(req.body);
    const savedEvent = await newEvent.save();
    res.status(201).json(savedEvent);
}));

app.put("/events/:title/:day", asyncHandler(async (req, res) => {
    const { title, day } = req.params;
    // Add validation if needed
    const updatedEvent = await Event.findOneAndUpdate({ title, day }, req.body, { new: true, runValidators: true });
    if (!updatedEvent) return res.status(404).json({ message: "Event not found" });
    res.json(updatedEvent);
}));

app.delete("/events/:title/:day", asyncHandler(async (req, res) => {
    const { title, day } = req.params;
    const deletedEvent = await Event.findOneAndDelete({ title, day });
    if (!deletedEvent) return res.status(404).json({ message: "Event not found" });
    res.json({ message: "Event deleted successfully", title, day });
}));

// --- Global Error Handler ---
// Catches errors from asyncHandler and unhandled sync/async errors
app.use((err, req, res, next) => {
    console.error("❌ Unhandled Error:", err.message);
    if (NODE_ENV === 'development' && err.stack) {
        console.error(err.stack); // Log stack trace only in dev
    }

    // Default error details
    let statusCode = err.status || 500;
    let message = err.message || "An internal server error occurred.";

    // Handle specific Mongoose errors for better client feedback
    if (err.name === 'ValidationError') {
        statusCode = 400; // Bad Request
        message = Object.values(err.errors).map(val => val.message).join(', ');
    } else if (err.name === 'CastError') {
        statusCode = 400; // Bad Request
        message = `Invalid format for field '${err.path}'. Expected type ${err.kind}.`;
    } else if (err.code === 11000) { // Duplicate key error (if not caught specifically earlier)
        statusCode = 409; // Conflict
        const field = Object.keys(err.keyValue)[0];
        message = field ? `Duplicate value for field: ${field}. Please use a unique value.` : "Duplicate key error.";
    }

    // If headers already sent, delegate to default Express error handler
    if (res.headersSent) {
        return next(err);
    }

    res.status(statusCode).json({ message, success: false });
});

// --- Start Server ---
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT} [${NODE_ENV}]`);
});