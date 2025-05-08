// ----- SERVER FILE (e.g., server.js) -----
import dotenv from "dotenv";
dotenv.config();

import express, { json } from "express";
import cors from "cors";
import mongoose from "mongoose";
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import fsp from 'fs/promises'; // Using fs/promises for async file operations
import { fileURLToPath } from 'url';
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import Joi from "joi";

import { TechDetail, Event, User } from "./models.js"; // Ensure this path is correct

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const UPLOADS_DIR = path.join(__dirname, 'uploads');
const PORT = process.env.PORT || 5001;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const NODE_ENV = process.env.NODE_ENV || 'development';

if (!MONGO_URI || !JWT_SECRET) {
    console.error("FATAL ERROR: MONGO_URI or JWT_SECRET is not defined in .env file.");
    process.exit(1);
}

app.use(cors());
app.use(json());
app.use('/uploads', express.static(UPLOADS_DIR));

const hardcodedAdminCredentials = [
    { email: "main_admin@example.com", password: "verySecurePassword1!", role: "admin" },
    { email: "secondary_admin@example.com", password: "anotherSecurePassword2@", role: "employee" },
];

const seedAdminUsers = async () => {
    console.log('Seeding admin users...');
    try {
        for (const admin of hardcodedAdminCredentials) {
            const lowerCaseEmail = admin.email.toLowerCase();
            const existingUser = await User.findOne({ email: lowerCaseEmail });

            if (!existingUser) {
                const hashedPassword = await bcrypt.hash(admin.password, 10);
                await User.create({
                    email: lowerCaseEmail,
                    password: hashedPassword,
                    role: admin.role
                });
                console.log(`Admin user ${lowerCaseEmail} (${admin.role}) created.`);
            } else {
                let updateNeeded = false;
                const updates = {};
                if (existingUser.role !== admin.role) {
                    updates.role = admin.role;
                    updateNeeded = true;
                }
                // Add logic here if you want to update passwords from hardcoded list (generally not recommended for existing users)
                // For example, to update password if it doesn't match (BE CAREFUL WITH THIS IN PRODUCTION):
                // const isPasswordMatch = await bcrypt.compare(admin.password, existingUser.password);
                // if (!isPasswordMatch) {
                //     updates.password = await bcrypt.hash(admin.password, 10);
                //     updateNeeded = true;
                // }

                if (updateNeeded) {
                    await User.updateOne({ email: lowerCaseEmail }, { $set: updates });
                    console.log(`Admin user ${lowerCaseEmail} details updated.`);
                } else {
                    console.log(`Admin user ${lowerCaseEmail} (${existingUser.role}) already exists and no update needed based on current logic.`);
                }
            }
        }
        console.log('Admin user seeding complete.');
    } catch (error) {
        console.error("Error seeding admin users:", error);
        process.exit(1); // Exit if seeding fails
    }
};

mongoose.connect(MONGO_URI)
    .then(() => {
        console.log(`🔌 Connected to MongoDB`);
        return seedAdminUsers(); // Ensure seeding completes before starting server potentially
    })
    .catch((err) => {
        console.error("❌ MongoDB Connection Error:", err);
        process.exit(1);
    });

const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// MODIFIED generateNewDocket function (as provided in the prompt)
const generateNewDocket = async (genre) => {
    if (!genre || typeof genre !== 'string' || !genre.trim()) {
        throw new Error("Invalid genre provided for docket generation.");
    }
    const sanitizedGenre = genre.trim().replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
    if (!sanitizedGenre) {
        throw new Error("Genre contains invalid characters or is empty after sanitization.");
    }

    const result = await TechDetail.aggregate([
        { $match: { docket: new RegExp(`^${sanitizedGenre}-(\\d+)$`) } },
        {
            $addFields: {
                numberStr: { $arrayElemAt: [{ $regexFindAll: { input: "$docket", regex: /(\d+)$/ } }, 0] }
            }
        },
        {
            $addFields: {
                numberPart: {
                    $cond: {
                        if: { $eq: [{ $type: "$numberStr.captures" }, "array"] },
                        then: { $toInt: { $arrayElemAt: ["$numberStr.captures", 0] } },
                        else: null
                    }
                }
            }
        },
        { $match: { numberPart: { $ne: null } } },
        { $sort: { numberPart: -1 } },
        { $limit: 1 }
    ]).exec();

    let nextTechNumber = 1;
    if (result.length > 0 && result[0].numberPart != null) {
        const maxNumber = result[0].numberPart;
        if (!isNaN(maxNumber)) {
            nextTechNumber = maxNumber + 1;
        }
    }
    return `${sanitizedGenre}-${nextTechNumber}`;
};


const parseTechDataFields = (data) => {
    const fieldsToParse = ['advantages', 'applications', 'useCases', 'innovators', 'relatedLinks', 'existingImages'];
    const arrayFields = ['advantages', 'applications', 'useCases'];
    const objectArrayFields = ['innovators', 'relatedLinks', 'existingImages']; // existingImages will be array of objects

    fieldsToParse.forEach(field => {
        if (data[field] && typeof data[field] === 'string') {
            try {
                const parsed = JSON.parse(data[field]);
                if ((arrayFields.includes(field) || objectArrayFields.includes(field)) && !Array.isArray(parsed)) {
                    console.warn(`Field ${field} was a string but did not parse to an array. Initializing as empty array.`);
                    data[field] = []; // Default to empty array if not array after parsing
                } else {
                    data[field] = parsed;
                }
            } catch (e) {
                // If parsing fails for simple array fields, try splitting by comma
                if (arrayFields.includes(field)) {
                    data[field] = data[field].split(',').map(item => item.trim()).filter(Boolean);
                } else {
                    // For objectArrayFields, if JSON.parse fails, it's likely malformed; initialize as empty.
                    console.warn(`Failed to parse JSON string for field ${field}: ${data[field]}. Initializing as empty array.`);
                    data[field] = [];
                }
            }
        } else if ((arrayFields.includes(field) || objectArrayFields.includes(field)) && !data[field]) {
            data[field] = []; // Initialize if field is not present or falsy
        }
    });
    // Ensure existingImages contains objects with url and caption
    if (data.existingImages && Array.isArray(data.existingImages)) {
        data.existingImages = data.existingImages.map(img => {
            if (typeof img === 'string') { // Simple URL string, convert to object
                return { url: img, caption: '' };
            }
            return img; // Assume it's already {url, caption}
        }).filter(img => img && typeof img.url === 'string');
    }

    return data;
};

const deleteImageFiles = async (imagesToDelete = []) => {
    if (!Array.isArray(imagesToDelete) || imagesToDelete.length === 0) {
        return Promise.resolve();
    }
    const deletionPromises = imagesToDelete.map(image => {
        if (image?.url && typeof image.url === 'string') {
            const relativePathFromUploadsDir = image.url.startsWith('/uploads/')
                ? image.url.substring('/uploads/'.length)
                : path.basename(image.url); // Fallback, assumes filename only if not standard path

            const imagePath = path.join(UPLOADS_DIR, relativePathFromUploadsDir);

            return fsp.unlink(imagePath)
                .then(() => console.log(`🗑️ Successfully deleted image: ${imagePath}`))
                .catch(err => {
                    if (err.code === 'ENOENT') {
                        console.warn(`⚠️ Image not found for deletion (may have been already deleted): ${imagePath}`);
                    } else {
                        console.error(`❌ Error deleting image ${imagePath}:`, err);
                    }
                });
        }
        return Promise.resolve(); // Skip if image or url is invalid
    });
    await Promise.all(deletionPromises);
};


// --- Multer Setup for Temporary Storage ---
const tempStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        fs.mkdirSync(UPLOADS_DIR, { recursive: true });
        cb(null, UPLOADS_DIR);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, `temp-${file.fieldname}-${uniqueSuffix}${path.extname(file.originalname)}`);
    }
});

const fileFilter = (req, file, cb) => {
    if (!file.originalname.match(/\.(jpg|jpeg|png|gif|webp)$/i)) {
        req.fileValidationError = 'Invalid file type. Only JPG, JPEG, PNG, GIF, WEBP allowed.';
        return cb(new Error(req.fileValidationError), false);
    }
    cb(null, true);
};

const tempUpload = multer({
    storage: tempStorage,
    fileFilter,
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Middleware to handle temporary uploads
const handleTemporaryMulterUpload = tempUpload.array('images', 5); // Max 5 images

const multerErrorHandler = (err, req, res, next) => {
    if (req.fileValidationError) {
        return res.status(400).json({ message: req.fileValidationError });
    }
    if (err instanceof multer.MulterError) {
        let message = 'File upload error.';
        if (err.code === 'LIMIT_FILE_SIZE') message = 'File size exceeds 5MB limit.';
        else if (err.code === 'LIMIT_UNEXPECTED_FILE') message = 'Unexpected field or too many files (max 5).';
        return res.status(400).json({ message, code: err.code });
    }
    if (err) { // Other errors
        return next(err);
    }
    next();
};

// --- Image Processing and Renaming Functions ---

// Renames existing image files based on the new docket and assigns them new indexed names.
const renameKeptImagesAndAssignNewNames = async (imagesToKeep, newDocketBase, startIndex = 1) => {
    const sanitizedNewDocket = newDocketBase.replace(/[^a-zA-Z0-9_-]/g, '_'); // Sanitize for filename
    const processedKeptImages = [];
    let currentIndex = startIndex;

    for (const keptImage of imagesToKeep) {
        if (!keptImage?.url || typeof keptImage.url !== 'string') continue;

        const oldFilenameRelative = keptImage.url.startsWith('/uploads/')
            ? keptImage.url.substring('/uploads/'.length)
            : path.basename(keptImage.url);

        const oldAbsolutePath = path.join(UPLOADS_DIR, oldFilenameRelative);
        const extension = path.extname(oldFilenameRelative);
        const newFilename = `${sanitizedNewDocket}-${currentIndex}${extension}`;
        const newAbsolutePath = path.join(UPLOADS_DIR, newFilename);

        if (oldAbsolutePath === newAbsolutePath) { // File already has the target name
            try {
                await fsp.access(oldAbsolutePath); // Just check existence
                processedKeptImages.push({ url: `/uploads/${newFilename}`, caption: keptImage.caption || '' });
                console.log(`✅ Kept image ${newFilename} already correctly named and exists.`);
            } catch (e) {
                console.warn(`⚠️ Kept image ${oldAbsolutePath} (intended new name ${newFilename}) not found. Skipping.`);
            }
        } else { // Rename is needed
            try {
                await fsp.access(oldAbsolutePath); // Check if old file exists
                await fsp.rename(oldAbsolutePath, newAbsolutePath);
                processedKeptImages.push({ url: `/uploads/${newFilename}`, caption: keptImage.caption || '' });
                console.log(`🔄 Renamed kept image from ${oldFilenameRelative} to ${newFilename}`);
            } catch (error) {
                console.warn(`⚠️ Failed to rename or access kept image ${oldAbsolutePath} to ${newAbsolutePath}: ${error.message}.`);
                // Fallback: if original file still exists, keep its old record. Otherwise, it's lost.
                try {
                    await fsp.access(oldAbsolutePath);
                    processedKeptImages.push({ url: keptImage.url, caption: keptImage.caption || '' });
                    console.warn(`↪️ Kept image ${oldFilenameRelative} will retain its old URL after failed rename attempt.`);
                } catch (fallbackAccessError) {
                    console.error(`❌ Old kept image ${oldAbsolutePath} is also not accessible. Image removed from kept list.`);
                }
            }
        }
        currentIndex++;
    }
    return { processedImageObjects: processedKeptImages, nextAvailableIndex: currentIndex };
};

// Processes newly uploaded temporary files: renames them according to the docket and an index.
const processNewUploadedFiles = async (tempFiles = [], docketBase, bodyForCaptions = {}, startIndex = 1) => {
    if (!tempFiles || tempFiles.length === 0) return { processedImageObjects: [], nextAvailableIndex: startIndex };

    const sanitizedDocket = docketBase.replace(/[^a-zA-Z0-9_-]/g, '_');
    const newImageObjects = [];
    let currentIndex = startIndex;

    for (let i = 0; i < tempFiles.length; i++) {
        const tempFile = tempFiles[i]; // multer file object
        const tempPath = tempFile.path;
        const originalExtension = path.extname(tempFile.originalname);
        const newFilename = `${sanitizedDocket}-${currentIndex}${originalExtension}`;
        const newAbsolutePath = path.join(UPLOADS_DIR, newFilename);

        try {
            await fsp.rename(tempPath, newAbsolutePath);
            newImageObjects.push({
                url: `/uploads/${newFilename}`,
                caption: bodyForCaptions[`imageCaptions[${i}]`] || tempFile.originalname // Captions from form using `imageCaptions[index]`
            });
            console.log(`✨ Processed new image: ${tempFile.filename} to ${newFilename}`);
        } catch (renameError) {
            console.error(`❌ Error renaming new file ${tempPath} to ${newAbsolutePath}:`, renameError);
            // Attempt to delete the temporary file if rename failed
            try { await fsp.unlink(tempPath); } catch (e) { console.error(`💀 Failed to delete temp file ${tempPath} after rename error:`, e); }
        }
        currentIndex++;
    }
    return { processedImageObjects: newImageObjects, nextAvailableIndex: currentIndex };
};


// --- Authentication & Authorization ---
const authSchemas = {
    login: Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().required(),
    })
};

const validateBody = (schemaName) => (req, res, next) => {
    const schema = authSchemas[schemaName];
    if (!schema) {
        console.error(`Schema ${schemaName} not found`);
        return next(new Error(`Server configuration error: Schema ${schemaName} missing.`));
    }
    const { error } = schema.validate(req.body);
    if (error) {
        return res.status(400).json({ message: "Validation Error", error: error.details[0].message, success: false });
    }
    next();
};

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.status(401).json({ message: 'Authentication token required.', success: false });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error("JWT Verification Error:", err.message);
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ message: 'Token expired. Please log in again.', success: false, code: 'TOKEN_EXPIRED' });
            }
            return res.status(403).json({ message: 'Invalid token.', success: false, code: 'INVALID_TOKEN' });
        }
        req.user = user;
        next();
    });
};

const checkRole = (requiredRoles) => {
    return (req, res, next) => {
        if (!req.user) { // Should ideally be caught by authenticateToken first
            return res.status(401).json({ message: 'Authentication required.', success: false });
        }

        // Ensure requiredRoles is an array for consistent processing
        const rolesArray = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];

        // Check if the user's role is included in the array of required roles.
        // Also, always allow 'admin' to bypass specific role checks if you want
        // an admin to have universal access, regardless of the specific roles listed.
        // If you want strict adherence ONLY to the roles in rolesArray, remove "|| req.user.role === 'admin'"
        if (rolesArray.includes(req.user.role) || req.user.role === 'admin') {
            next(); // User has one of the required roles (or is admin), proceed
        } else {
            return res.status(403).json({
                message: `Access denied. Requires one of the following roles: ${rolesArray.join(', ')}. You are ${req.user.role}.`,
                success: false
            });
        }
    };
};


// --- Routes ---
// In server.js, within your app.post("/auth/login", ...) route:

app.post("/auth/login", validateBody('login'), asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    const lowerCaseEmail = email.toLowerCase();

    console.log(`[LOGIN_IP_DEBUG] Attempting login for email: ${lowerCaseEmail}`);

    // Fetch user from DB. Given your schema, +role is not strictly needed but fine.
    const user = await User.findOne({ email: lowerCaseEmail }).select('+password +role');

    if (!user) {
        console.log(`[LOGIN_IP_DEBUG] User not found in DB for email: ${lowerCaseEmail}`);
        return res.status(401).json({ message: "Authentication failed. Invalid email or password.", success: false });
    }

    // --- MOST IMPORTANT LOG ---
    // Log the raw user object fetched from MongoDB
    console.log("[LOGIN_IP_DEBUG] User data fetched from DB (server-side):", JSON.stringify(user, null, 2));
    // Specifically check if 'user.role' is present here in your server logs when accessing via IP.

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        console.log(`[LOGIN_IP_DEBUG] Password mismatch for email: ${lowerCaseEmail}`);
        return res.status(401).json({ message: "Authentication failed. Invalid email or password.", success: false });
    }

    const payload = {
        email: user.email,
        userId: user._id,
        role: user.role // This depends on 'user.role' being defined from the DB fetch
    };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });

    const userResponseObject = {
        email: user.email,
        id: user._id,
        role: user.role // This is what will be sent to the client
    };

    // --- ALSO IMPORTANT LOG ---
    // Log the object that is about to be sent to the client
    console.log("[LOGIN_IP_DEBUG] User object being sent in response (server-side):", JSON.stringify(userResponseObject, null, 2));

    res.status(200).json({
        message: "Login successful!",
        success: true,
        token,
        user: userResponseObject
    });
}));

// --- Technology Routes ---
app.get("/technologies", authenticateToken, asyncHandler(async (req, res) => {
    const techs = await TechDetail.find({}).sort({ createdAt: -1 });
    res.json(techs);
}));

app.get("/technologies/:id", authenticateToken, asyncHandler(async (req, res) => {
    const tech = await TechDetail.findOne({ id: req.params.id });
    if (!tech) {
        return res.status(404).json({ message: "Technology not found" });
    }
    res.json(tech);
}));

app.post("/technologies",
    authenticateToken,
    handleTemporaryMulterUpload, // Use temporary multer upload
    multerErrorHandler,
    asyncHandler(async (req, res, next) => {
        let techData = parseTechDataFields({ ...req.body });
        const { genre } = techData;
        let tempUploadedFileObjects = req.files ? req.files.map(f => ({ url: `/uploads/${f.filename}` })) : []; // For cleanup

        if (!genre || typeof genre !== 'string' || !genre.trim()) {
            if (tempUploadedFileObjects.length > 0) await deleteImageFiles(tempUploadedFileObjects);
            return res.status(400).json({ message: "Genre is required to create a technology." });
        }

        let newDocket;
        let finalImages = [];
        try {
            newDocket = await generateNewDocket(genre);
            techData.docket = newDocket;
            techData.id = newDocket; // ID is the same as docket

            // Process uploaded images: rename and get final image data
            const { processedImageObjects } = await processNewUploadedFiles(req.files, newDocket, req.body, 1);
            finalImages = processedImageObjects;
            techData.images = finalImages;

            const newTech = new TechDetail(techData);
            const savedTech = await newTech.save();
            res.status(201).json(savedTech);
        } catch (error) {
            // Cleanup successfully renamed files if DB save fails, or temp files if renaming didn't complete
            if (finalImages.length > 0) { // Files were renamed
                await deleteImageFiles(finalImages);
            } else if (tempUploadedFileObjects.length > 0) { // Files were only temporary
                await deleteImageFiles(tempUploadedFileObjects);
            }

            if (error.code === 11000 && (error.keyPattern?.id || error.keyPattern?.docket)) {
                return res.status(409).json({ message: `Failed to create: ID/Docket ${newDocket || 'unknown'} conflict. Please try again or check data.`, code: 'DUPLICATE_ID' });
            }
            next(error); // Pass to generic error handler
        }
    })
);

app.put("/technologies/:id",
    authenticateToken,
    handleTemporaryMulterUpload, // Use temporary multer upload
    multerErrorHandler,
    asyncHandler(async (req, res, next) => {
        const currentTechId = req.params.id; // This is the OLD docket/id
        let incomingData = parseTechDataFields({ ...req.body }); // `existingImages` is parsed here
        let tempUploadedFileObjects = req.files ? req.files.map(f => ({ url: `/uploads/${f.filename}` })) : []; // For cleanup

        const currentTech = await TechDetail.findOne({ id: currentTechId });
        if (!currentTech) {
            if (tempUploadedFileObjects.length > 0) await deleteImageFiles(tempUploadedFileObjects);
            return res.status(404).json({ message: `Technology with ID ${currentTechId} not found` });
        }

        const oldDocket = currentTech.docket;
        const oldGenre = currentTech.genre;
        const newGenre = incomingData.genre ? incomingData.genre.trim() : oldGenre;

        let finalUpdateData = { ...incomingData };
        let docketForFileNaming = oldDocket; // Docket to be used for naming image files

        if (newGenre.toUpperCase() !== oldGenre.toUpperCase()) {
            try {
                const newGeneratedDocket = await generateNewDocket(newGenre);
                const existingWithNewId = await TechDetail.findOne({ id: newGeneratedDocket, _id: { $ne: currentTech._id } }).lean();
                if (existingWithNewId) {
                    if (tempUploadedFileObjects.length > 0) await deleteImageFiles(tempUploadedFileObjects);
                    return res.status(409).json({ message: `Update conflict: Generated ID ${newGeneratedDocket} for new genre already exists.`, code: 'DUPLICATE_ID_ON_UPDATE' });
                }
                finalUpdateData.docket = newGeneratedDocket;
                finalUpdateData.id = newGeneratedDocket; // Update id as well
                finalUpdateData.genre = newGenre;
                docketForFileNaming = newGeneratedDocket;
            } catch (error) {
                if (tempUploadedFileObjects.length > 0) await deleteImageFiles(tempUploadedFileObjects);
                return next(new Error(`Failed to generate new docket for genre '${newGenre}': ${error.message}`));
            }
        } else {
            // Genre didn't change, docket remains the same.
            delete finalUpdateData.id; // Prevent accidental change if sent in body
            delete finalUpdateData.docket; // Prevent accidental change
            finalUpdateData.genre = oldGenre; // Ensure it's the original genre from DB
            // docketForFileNaming remains oldDocket
        }

        // --- Image Handling ---
        const imagesToKeepFromRequest = Array.isArray(finalUpdateData.existingImages) ? finalUpdateData.existingImages : [];
        const urlsToKeepInRequest = imagesToKeepFromRequest.map(img => img?.url).filter(Boolean);

        // Identify images to delete (those in currentTech.images not in urlsToKeepInRequest)
        const imagesToDeletePhysically = currentTech.images?.filter(img => img && !urlsToKeepInRequest.includes(img.url)) || [];
        await deleteImageFiles(imagesToDeletePhysically);

        let currentFileIndex = 1;
        // Process images to keep: rename if docket changed, and assign new indexed names
        const { processedImageObjects: finalKeptImages, nextAvailableIndex: nextIndexAfterKept } =
            await renameKeptImagesAndAssignNewNames(imagesToKeepFromRequest, docketForFileNaming, currentFileIndex);
        currentFileIndex = nextIndexAfterKept;

        // Process newly uploaded files (req.files)
        const { processedImageObjects: newlyUploadedAndProcessedImages, nextAvailableIndex: finalNextIndex } =
            await processNewUploadedFiles(req.files, docketForFileNaming, req.body, currentFileIndex);

        finalUpdateData.images = [...finalKeptImages, ...newlyUploadedAndProcessedImages];
        delete finalUpdateData.existingImages; // Clean this temporary field from the update data

        try {
            const updatedTech = await TechDetail.findOneAndUpdate(
                { id: currentTechId }, // Find by the original ID
                { $set: finalUpdateData },
                { new: true, runValidators: true }
            );

            if (!updatedTech) {
                // Tech not found during final update, maybe deleted in interim. Clean up processed images.
                await deleteImageFiles(finalUpdateData.images); // These files now have final names
                return res.status(404).json({ message: "Technology not found during final update attempt." });
            }
            res.json(updatedTech);
        } catch (error) {
            // If update fails, attempt to delete newly processed files (both renamed kept and new ones)
            // This is a best-effort cleanup. A full rollback is more complex.
            await deleteImageFiles(finalUpdateData.images);

            if (error.code === 11000 && (error.keyPattern?.id || error.keyPattern?.docket)) {
                return res.status(409).json({ message: `Update failed: Conflict with ID/Docket ${finalUpdateData.id || docketForFileNaming}.`, code: 'DUPLICATE_ID_ON_UPDATE' });
            }
            next(error);
        }
    })
);


app.delete("/technologies/:id",
    authenticateToken,
    // checkRole('admin'), // Kept commented as in original
    asyncHandler(async (req, res) => {
        const techId = req.params.id;
        const tech = await TechDetail.findOne({ id: techId });

        if (!tech) {
            return res.status(404).json({ message: "Technology not found" });
        }

        // Delete associated images from filesystem
        if (tech.images && tech.images.length > 0) {
            await deleteImageFiles(tech.images);
        }

        const deletionResult = await TechDetail.deleteOne({ id: techId });
        if (deletionResult.deletedCount === 0) {
            // Should not happen if findOne found it, but as a safeguard
            return res.status(404).json({ message: "Technology not found during deletion attempt." });
        }
        res.json({ message: "Technology deleted successfully", id: techId });
    })
);


// --- Event Routes (largely unchanged, ensure checkRole for sensitive ops) ---
app.get("/events", authenticateToken, asyncHandler(async (req, res) => {
    const events = await Event.find({}).sort({ day: 1, title: 1 });
    res.json(events);
}));

app.get("/events/:title/:day", authenticateToken, asyncHandler(async (req, res) => {
    const title = decodeURIComponent(req.params.title);
    const day = decodeURIComponent(req.params.day);
    const event = await Event.findOne({ title, day });
    if (!event) return res.status(404).json({ message: "Event not found" });
    res.json(event);
}));

// Ensure this route uses the updated checkRole logic
app.post("/events", authenticateToken, checkRole(['admin', 'employee']), asyncHandler(async (req, res, next) => {
    try {
        const newEvent = new Event(req.body);
        const savedEvent = await newEvent.save();
        res.status(201).json(savedEvent);
    } catch (error) {
        if (error.code === 11000 && error.keyPattern?.title && error.keyPattern?.day) {
            return res.status(409).json({ message: `Event with title "${req.body.title}" on day "${req.body.day}" already exists.`, code: 'DUPLICATE_EVENT' });
        }
        next(error);
    }
}));

// For PUT and DELETE, you might still want to restrict to 'admin' only, or update as needed
app.put("/events/:title/:day",
    authenticateToken,
    checkRole('admin'), // Or checkRole(['admin', 'employee']) if employees can also edit
    asyncHandler(async (req, res, next) => {
        const title = decodeURIComponent(req.params.title);
        const day = decodeURIComponent(req.params.day);
        try {
            const updatedEvent = await Event.findOneAndUpdate(
                { title, day },
                req.body,
                { new: true, runValidators: true }
            );
            if (!updatedEvent) return res.status(404).json({ message: "Event not found" });
            res.json(updatedEvent);
        } catch (error) {
            if (error.code === 11000 && error.keyPattern?.title && error.keyPattern?.day) {
                const conflictingEvent = await Event.findOne({ title: req.body.title, day: req.body.day });
                // Check if the conflict is with a *different* document
                // This check assumes _id is part of req.body if you're trying to identify the current doc during an update that might change title/day
                // If _id is not reliably in req.body for this check, you might need a different approach or accept that a 409 might occur if title/day are changed to an existing combo.
                if (conflictingEvent && (!req.body._id || String(conflictingEvent._id) !== String(req.body._id))) {
                     return res.status(409).json({ message: `Update failed: An event with title "${req.body.title}" on day "${req.body.day}" already exists.`, code: 'DUPLICATE_EVENT_ON_UPDATE' });
                }
            }
            next(error);
        }
    })
);

app.delete("/events/:title/:day",
    authenticateToken,
    checkRole('admin'), // Or checkRole(['admin', 'employee']) if employees can also delete
    asyncHandler(async (req, res) => {
        const title = decodeURIComponent(req.params.title);
        const day = decodeURIComponent(req.params.day);
        const deletedEvent = await Event.findOneAndDelete({ title, day });
        if (!deletedEvent) return res.status(404).json({ message: "Event not found" });
        res.json({ message: "Event deleted successfully", title, day });
    })
);

// --- Generic Error Handler ---
app.use((err, req, res, next) => {
    console.error("❌ Unhandled Error:", err.message);
    if (NODE_ENV === 'development' && err.stack) {
        console.error(err.stack);
    }

    let statusCode = err.status || err.statusCode || 500; // Prefer err.statusCode if available
    let message = err.message || "An internal server error occurred.";
    let errorCode = err.code;

    if (err.name === 'ValidationError') { // Mongoose validation error
        statusCode = 400;
        message = Object.values(err.errors).map(val => val.message).join(', ');
        errorCode = errorCode || 'VALIDATION_ERROR';
    } else if (err.name === 'CastError') { // Mongoose cast error
        statusCode = 400;
        message = `Invalid format for field '${err.path}'. Expected type ${err.kind}. Value: "${err.value}"`;
        errorCode = errorCode || 'CAST_ERROR';
    } else if (err.code === 11000) { // MongoDB duplicate key error
        statusCode = 409;
        const field = Object.keys(err.keyValue || {})[0];
        message = field ? `Duplicate value for field: ${field}. Value: "${err.keyValue[field]}"` : "Duplicate key error.";
        errorCode = errorCode || 'DUPLICATE_KEY';
    }

    if (res.headersSent) {
        return next(err); // Pass to default Express error handler if headers already sent
    }

    res.status(statusCode).json({
        message,
        success: false,
        ...(errorCode && { code: errorCode }),
        ...(NODE_ENV === 'development' && { stack: err.stack }) // Optionally send stack in dev
    });
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT} [${NODE_ENV}]`);
});