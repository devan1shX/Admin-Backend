// server.js
import dotenv from "dotenv";
dotenv.config();

import express, { json } from "express";
import cors from "cors";
import mongoose from "mongoose";
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import fsp from 'fs/promises'; 
import { fileURLToPath } from 'url';
import admin from 'firebase-admin';

import { TechDetail, Event } from "./models.js"; 

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const UPLOADS_DIR = path.join(__dirname, 'uploads');
const PORT = process.env.PORT || 5001;
const MONGO_URI = process.env.MONGO_URI;
const NODE_ENV = process.env.NODE_ENV || 'development';

const serviceAccountPath = path.join(__dirname, 'firebase-service-account-key.json');

if (!fs.existsSync(serviceAccountPath)) {
    console.error("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    console.error("FATAL ERROR: Firebase service account key JSON file not found.");
    console.error(`Expected path: ${serviceAccountPath}`);
    console.error("Please ensure 'firebase-service-account-key.json' is in the same directory as server.js.");
    console.error("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    process.exit(1);
}

try {
    if (!admin.apps.length) {
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccountPath),
        });
        console.log("✅ Firebase Admin SDK initialized successfully.");
    } else {
        console.log("ℹ️ Firebase Admin SDK already initialized.");
    }
} catch (error) {
    console.error("❌ Firebase Admin SDK Initialization Error:", error);
    process.exit(1);
}
const firestore = admin.firestore();

if (!MONGO_URI) {
    console.error("FATAL ERROR: MONGO_URI is not defined in .env file.");
    process.exit(1);
}

app.use(cors()); 
app.use(json()); 

app.use((req, res, next) => {
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
  next();
});

app.use('/uploads', express.static(UPLOADS_DIR)); 

mongoose.connect(MONGO_URI)
    .then(() => console.log(`🔌 Connected to MongoDB`))
    .catch((err) => {
        console.error("❌ MongoDB Connection Error:", err);
        process.exit(1);
    });

const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// --- Helper Functions (generateNewDocket, etc. - assumed to be complete from previous context) ---
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
        { $addFields: { numberStr: { $arrayElemAt: [{ $regexFindAll: { input: "$docket", regex: /(\d+)$/ } }, 0] } } },
        { $addFields: { numberPart: { $cond: { if: { $eq: [{ $type: "$numberStr.captures" }, "array"] }, then: { $toInt: { $arrayElemAt: ["$numberStr.captures", 0] } }, else: null } } } },
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
    const objectArrayFields = ['innovators', 'relatedLinks', 'existingImages'];
    fieldsToParse.forEach(field => {
        if (data[field] && typeof data[field] === 'string') {
            try {
                const parsed = JSON.parse(data[field]);
                if ((arrayFields.includes(field) || objectArrayFields.includes(field)) && !Array.isArray(parsed)) {
                    data[field] = [];
                } else {
                    data[field] = parsed;
                }
            } catch (e) {
                if (arrayFields.includes(field)) {
                    data[field] = data[field].split(',').map(item => item.trim()).filter(Boolean);
                } else {
                    data[field] = [];
                }
            }
        } else if ((arrayFields.includes(field) || objectArrayFields.includes(field)) && !data[field]) {
            data[field] = [];
        }
    });
    if (data.existingImages && Array.isArray(data.existingImages)) {
        data.existingImages = data.existingImages.map(img => {
            if (typeof img === 'string') return { url: img, caption: '' };
            return img;
        }).filter(img => img && typeof img.url === 'string');
    }
    return data;
};

const deleteImageFiles = async (imagesToDelete = []) => {
    if (!Array.isArray(imagesToDelete) || imagesToDelete.length === 0) return Promise.resolve();
    const deletionPromises = imagesToDelete.map(image => {
        if (image?.url && typeof image.url === 'string') {
            const relativePathFromUploadsDir = image.url.startsWith('/uploads/') ? image.url.substring('/uploads/'.length) : path.basename(image.url);
            const imagePath = path.join(UPLOADS_DIR, relativePathFromUploadsDir);
            return fsp.unlink(imagePath).catch(err => {
                if (err.code !== 'ENOENT') console.error(`❌ Error deleting image ${imagePath}:`, err);
            });
        }
        return Promise.resolve();
    });
    await Promise.all(deletionPromises);
};

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
        req.fileValidationError = 'Invalid file type.';
        return cb(new Error(req.fileValidationError), false);
    }
    cb(null, true);
};

const tempUpload = multer({ storage: tempStorage, fileFilter, limits: { fileSize: 5 * 1024 * 1024 } });
const handleTemporaryMulterUpload = tempUpload.array('images', 5);

const multerErrorHandler = (err, req, res, next) => {
    if (req.fileValidationError) return res.status(400).json({ message: req.fileValidationError });
    if (err instanceof multer.MulterError) {
        let message = 'File upload error.';
        if (err.code === 'LIMIT_FILE_SIZE') message = 'File size exceeds 5MB limit.';
        else if (err.code === 'LIMIT_UNEXPECTED_FILE') message = 'Unexpected field or too many files (max 5).';
        return res.status(400).json({ message, code: err.code });
    }
    if (err) return next(err);
    next();
};

const renameKeptImagesAndAssignNewNames = async (imagesToKeep, newDocketBase, startIndex = 1) => {
    const sanitizedNewDocket = newDocketBase.replace(/[^a-zA-Z0-9_-]/g, '_');
    const processedKeptImages = [];
    let currentIndex = startIndex;
    for (const keptImage of imagesToKeep) {
        if (!keptImage?.url || typeof keptImage.url !== 'string') continue;
        const oldFilenameRelative = keptImage.url.startsWith('/uploads/') ? keptImage.url.substring('/uploads/'.length) : path.basename(keptImage.url);
        const oldAbsolutePath = path.join(UPLOADS_DIR, oldFilenameRelative);
        const extension = path.extname(oldFilenameRelative);
        const newFilename = `${sanitizedNewDocket}-${currentIndex}${extension}`;
        const newAbsolutePath = path.join(UPLOADS_DIR, newFilename);
        if (oldAbsolutePath === newAbsolutePath) {
            try {
                await fsp.access(oldAbsolutePath); 
                processedKeptImages.push({ url: `/uploads/${newFilename}`, caption: keptImage.caption || '' });
            } catch (e) { /* Skip */ }
        } else {
            try {
                await fsp.access(oldAbsolutePath); 
                await fsp.rename(oldAbsolutePath, newAbsolutePath);
                processedKeptImages.push({ url: `/uploads/${newFilename}`, caption: keptImage.caption || '' });
            } catch (error) { 
                try {
                    await fsp.access(oldAbsolutePath);
                    processedKeptImages.push({ url: keptImage.url, caption: keptImage.caption || '' });
                } catch (fallbackAccessError) { /* Skip */ }
            }
        }
        currentIndex++;
    }
    return { processedImageObjects: processedKeptImages, nextAvailableIndex: currentIndex };
};

const processNewUploadedFiles = async (tempFiles = [], docketBase, bodyForCaptions = {}, startIndex = 1) => {
    if (!tempFiles || tempFiles.length === 0) return { processedImageObjects: [], nextAvailableIndex: startIndex };
    const sanitizedDocket = docketBase.replace(/[^a-zA-Z0-9_-]/g, '_');
    const newImageObjects = [];
    let currentIndex = startIndex;
    for (let i = 0; i < tempFiles.length; i++) {
        const tempFile = tempFiles[i];
        const tempPath = tempFile.path;
        const originalExtension = path.extname(tempFile.originalname);
        const newFilename = `${sanitizedDocket}-${currentIndex}${originalExtension}`;
        const newAbsolutePath = path.join(UPLOADS_DIR, newFilename);
        try {
            await fsp.rename(tempPath, newAbsolutePath);
            newImageObjects.push({ url: `/uploads/${newFilename}`, caption: bodyForCaptions[`imageCaptions[${i}]`] || tempFile.originalname });
        } catch (renameError) {
            console.error(`Error renaming temp file ${tempPath} to ${newAbsolutePath}:`, renameError);
            try { await fsp.unlink(tempPath); } catch (e) { /* Skip */ } 
        }
        currentIndex++;
    }
    return { processedImageObjects: newImageObjects, nextAvailableIndex: currentIndex };
};

// --- Authentication & Authorization Middleware ---
const verifyFirebaseToken = asyncHandler(async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const idToken = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    if (!idToken) {
        return res.status(401).json({ message: 'Authentication token required.', success: false, code: 'NO_TOKEN' });
    }
    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        req.firebaseDecodedToken = decodedToken;
        next();
    } catch (error) {
        console.error("Firebase ID Token Verification Error:", error.code, error.message);
        const errorCode = error.code === 'auth/id-token-expired' ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN';
        const message = error.code === 'auth/id-token-expired' ? 'Token expired. Please log in again.' : 'Invalid or expired token.';
        return res.status(errorCode === 'TOKEN_EXPIRED' ? 401 : 403).json({ message, success: false, code: errorCode });
    }
});

const loadFirestoreUserProfile = asyncHandler(async (req, res, next) => {
    if (!req.firebaseDecodedToken || !req.firebaseDecodedToken.uid) {
        return res.status(401).json({ message: 'Firebase token not decoded or UID missing.', success: false, code: 'TOKEN_NOT_DECODED' });
    }
    try {
        const userDoc = await firestore.collection('users').doc(req.firebaseDecodedToken.uid).get();
        if (!userDoc.exists) {
            return res.status(403).json({ message: 'Requesting admin user profile not found in database.', success: false, code: 'ADMIN_USER_PROFILE_NOT_FOUND' });
        }
        req.user = { uid: req.firebaseDecodedToken.uid, ...userDoc.data() };
        next();
    } catch (error) {
        console.error("Error loading Firestore user profile for requesting admin:", error);
        return res.status(500).json({ message: "Error loading admin user profile.", success: false, code: "ADMIN_PROFILE_LOAD_ERROR" });
    }
});

const checkPermissions = (requiredAccess) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ message: 'Admin user profile not loaded. Permission check failed.', success: false, code: 'ADMIN_PROFILE_REQUIRED_FOR_PERMISSIONS' });
        }
        const { role, editTech, deleteTech, addTech, editEvent, deleteEvent, addEvent } = req.user;
        let hasPermission = false;
        if (role === 'superAdmin') {
            hasPermission = true;
        } else if (typeof requiredAccess === 'string') {
            hasPermission = role === requiredAccess;
        } else if (Array.isArray(requiredAccess)) {
            hasPermission = requiredAccess.includes(role);
        } else if (typeof requiredAccess === 'object' && requiredAccess !== null) {
            const permissionKey = Object.keys(requiredAccess)[0];
            const requiredValue = requiredAccess[permissionKey];
            if (permissionKey === 'editTech') hasPermission = editTech === requiredValue;
            else if (permissionKey === 'deleteTech') hasPermission = deleteTech === requiredValue;
            else if (permissionKey === 'addTech') hasPermission = addTech === requiredValue;
            else if (permissionKey === 'editEvent') hasPermission = editEvent === requiredValue;
            else if (permissionKey === 'deleteEvent') hasPermission = deleteEvent === requiredValue;
            else if (permissionKey === 'addEvent') hasPermission = addEvent === requiredValue;
        }
        if (hasPermission) {
            next();
        } else {
            let requiredDescription = JSON.stringify(requiredAccess);
            if (typeof requiredAccess === 'string') requiredDescription = `role: ${requiredAccess}`;
            else if (Array.isArray(requiredAccess)) requiredDescription = `one of roles: ${requiredAccess.join(', ')}`;
            else if (typeof requiredAccess === 'object') requiredDescription = `permission: ${Object.keys(requiredAccess)[0]} = ${Object.values(requiredAccess)[0]}`;
            return res.status(403).json({ message: `Access denied. Requesting admin requires ${requiredDescription}. Your role: ${role}.`, success: false });
        }
    };
};

// --- User Profile and Permissions Routes ---
app.post("/auth/create-profile", verifyFirebaseToken, asyncHandler(async (req, res) => {
    const { uid, email, name: firebaseName, picture } = req.firebaseDecodedToken;
    const signInProvider = req.firebaseDecodedToken.firebase?.sign_in_provider || 'unknown';
    const { name: bodyName } = req.body;
    const userRef = firestore.collection('users').doc(uid);
    const userDoc = await userRef.get();
    if (userDoc.exists) {
        return res.status(200).json({ message: "User profile already exists.", success: true, user: userDoc.data() });
    }
    const displayName = bodyName || firebaseName || email.split('@')[0];
    const newUserProfile = {
        uid, email, name: displayName, photoURL: picture || null,
        role: 'employee', 
        editTech: false, deleteTech: false, addTech: true, // Default for employee
        editEvent: false, deleteEvent: false, addEvent: true, // Default for employee
        authProvider: signInProvider,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };
    await userRef.set(newUserProfile);
    res.status(201).json({ message: "User profile created successfully.", success: true, user: newUserProfile });
}));

app.get("/users/me", verifyFirebaseToken, loadFirestoreUserProfile, asyncHandler(async (req, res) => {
    res.status(200).json({ success: true, user: req.user });
}));

app.put("/users/:uid/permissions", 
    verifyFirebaseToken, 
    loadFirestoreUserProfile, 
    checkPermissions('superAdmin'), 
    asyncHandler(async (req, res) => {
        const targetUid = req.params.uid; 
        const { role, editTech, deleteTech, addTech, editEvent, deleteEvent, addEvent } = req.body;
        
        console.log(`Admin ${req.user.uid} attempting to update permissions for user ${targetUid}`);
        console.log(`Received payload:`, req.body);

        const userRef = firestore.collection('users').doc(targetUid);
        const userDoc = await userRef.get();

        if (!userDoc.exists) {
            console.warn(`Attempted to update permissions for non-existent Firestore profile: ${targetUid}`);
            return res.status(404).json({ message: `User profile for UID ${targetUid} not found in Firestore. Cannot update permissions.`, success: false });
        }
        
        // Prevent a superAdmin from changing their own role away from superAdmin
        if (req.user.uid === targetUid && userDoc.data().role === 'superAdmin' && role !== 'superAdmin' && role !== undefined) {
            return res.status(403).json({ message: "Super admin cannot change their own role.", success: false });
        }
        // Prevent changing another user to superAdmin if the requester is not also a superAdmin (already covered by checkPermissions)
        // Prevent changing any user to 'superAdmin' if that role is not explicitly allowed to be set.
        if (role === 'superAdmin' && targetUid !== req.user.uid) { // Only a superAdmin can make another user superAdmin (and they can't make themselves non-superAdmin)
             // This logic is a bit tricky. Generally, you might not want to allow assigning 'superAdmin' via this UI.
             // For now, if the target is not the current superAdmin, and the role is superAdmin, allow it.
             // But if the target *is* the current superAdmin, they can't change their role to something else.
        }


        const updates = { updatedAt: admin.firestore.FieldValue.serverTimestamp() };
        const allowedAssignableRoles = ['admin', 'employee']; 
        if (role !== undefined) {
            if (userDoc.data().role === 'superAdmin' && role !== 'superAdmin') {
                 // This case is mainly for the superAdmin trying to demote themselves, which we block above.
                 // If it's another superAdmin, this route shouldn't be hit if we block deleting/editing other superAdmins.
            } else if (allowedAssignableRoles.includes(role)) {
                updates.role = role;
            } else if (role === 'superAdmin' && userDoc.data().role === 'superAdmin') {
                // Allowing a superAdmin to "re-affirm" their role, no actual change.
                updates.role = role;
            }
            else {
                return res.status(400).json({ message: `Invalid role assignment: ${role}. Allowed: ${allowedAssignableRoles.join(', ')}.`, success: false});
            }
        }
        
        if (editTech !== undefined) updates.editTech = Boolean(editTech);
        if (deleteTech !== undefined) updates.deleteTech = Boolean(deleteTech);
        if (addTech !== undefined) updates.addTech = Boolean(addTech);
        if (editEvent !== undefined) updates.editEvent = Boolean(editEvent);
        if (deleteEvent !== undefined) updates.deleteEvent = Boolean(deleteEvent);
        if (addEvent !== undefined) updates.addEvent = Boolean(addEvent);
        
        if (Object.keys(updates).length === 1) { 
            return res.status(400).json({ message: "No valid permissions or role provided to update.", success: false });
        }
        
        await userRef.update(updates);
        const updatedUserDoc = await userRef.get();
        console.log(`Permissions updated successfully for user ${targetUid}`);
        res.status(200).json({ message: "User permissions updated successfully.", success: true, user: updatedUserDoc.data() });
}));

// --- API Endpoint to List All Users ---
app.get(
    "/api/admin/all-users",
    verifyFirebaseToken,        
    loadFirestoreUserProfile,   
    checkPermissions('superAdmin'), 
    asyncHandler(async (req, res) => { 
        console.log(`Admin User ${req.user.uid} (Role: ${req.user.role}) is requesting all users list.`);
        try {
            const listAuthUsersResult = await admin.auth().listUsers(1000); 
            const combinedUsers = await Promise.all(
                listAuthUsersResult.users.map(async (authUserRecord) => {
                    let firestoreProfileData = {};
                    const defaultPermissions = {
                        role: 'employee', // Default to employee if no profile
                        name: authUserRecord.displayName || 'N/A',
                        photoURL: authUserRecord.photoURL || null,
                        editTech: false, addTech: true, deleteTech: false, // Employee defaults
                        editEvent: false, addEvent: true, deleteEvent: false, // Employee defaults
                    };
                    try {
                        const userDocRef = firestore.collection('users').doc(authUserRecord.uid);
                        const userDoc = await userDocRef.get();
                        if (userDoc.exists) {
                            firestoreProfileData = userDoc.data();
                        } else {
                            console.log(`No Firestore profile found for UID ${authUserRecord.uid}. Will use defaults and create if necessary during permission update.`);
                            // If no profile, we might create one with default 'employee' role when permissions are first set.
                            // For listing, use defaults.
                            firestoreProfileData = defaultPermissions; // Use default permissions for listing if no profile
                        }
                    } catch (profileError) {
                        console.warn(`Could not fetch Firestore profile for UID ${authUserRecord.uid}:`, profileError.message);
                        firestoreProfileData.role = 'Error Loading Profile'; 
                    }
                    return {
                        uid: authUserRecord.uid, email: authUserRecord.email,
                        emailVerified: authUserRecord.emailVerified, disabled: authUserRecord.disabled,
                        creationTime: authUserRecord.metadata.creationTime,
                        lastSignInTime: authUserRecord.metadata.lastSignInTime,
                        customClaims: authUserRecord.customClaims,
                        providerData: authUserRecord.providerData.map(p => ({
                            providerId: p.providerId, displayName: p.displayName,
                            email: p.email, photoURL: p.photoURL, uid: p.uid
                        })),
                        displayName: firestoreProfileData.name || authUserRecord.displayName || defaultPermissions.name,
                        photoURL: firestoreProfileData.photoURL || authUserRecord.photoURL || defaultPermissions.photoURL,
                        role: firestoreProfileData.role || defaultPermissions.role,
                        editTech: firestoreProfileData.editTech === true, 
                        addTech: firestoreProfileData.addTech === true,   
                        deleteTech: firestoreProfileData.deleteTech === true, 
                        editEvent: firestoreProfileData.editEvent === true, 
                        addEvent: firestoreProfileData.addEvent === true,   
                        deleteEvent: firestoreProfileData.deleteEvent === true, 
                    };
                })
            );
            console.log(`Successfully fetched and combined data for ${combinedUsers.length} users.`);
            res.status(200).json({ success: true, users: combinedUsers });
        } catch (error) {
            console.error("❌ Error in /api/admin/all-users main try block:", error);
            res.status(500).json({ 
                message: 'Failed to list and combine user data.', success: false, 
                code: "LIST_COMBINE_USERS_ERROR", error: error.message 
            });
        }
    })
);

// --- NEW: API Endpoint to Delete a User ---
app.delete(
    "/api/admin/users/:uid",
    verifyFirebaseToken,
    loadFirestoreUserProfile,
    checkPermissions('superAdmin'),
    asyncHandler(async (req, res) => {
        const targetUid = req.params.uid;
        const requestingAdminUid = req.user.uid; // UID of the admin making the request

        console.log(`Admin ${requestingAdminUid} attempting to delete user ${targetUid}`);

        if (targetUid === requestingAdminUid) {
            return res.status(403).json({ message: "Super admin cannot delete their own account.", success: false });
        }

        try {
            // Optional: Check if the target user is also a superAdmin
            const targetUserFirestoreDoc = await firestore.collection('users').doc(targetUid).get();
            if (targetUserFirestoreDoc.exists && targetUserFirestoreDoc.data().role === 'superAdmin') {
                return res.status(403).json({ message: "Cannot delete another super admin account for security reasons.", success: false });
            }

            // Step 1: Delete from Firebase Authentication
            await admin.auth().deleteUser(targetUid);
            console.log(`Successfully deleted user ${targetUid} from Firebase Authentication.`);

            // Step 2: Delete from Firestore 'users' collection (if exists)
            if (targetUserFirestoreDoc.exists) {
                await firestore.collection('users').doc(targetUid).delete();
                console.log(`Successfully deleted user ${targetUid} profile from Firestore.`);
            } else {
                console.log(`No Firestore profile found for user ${targetUid} to delete, but Auth user deleted.`);
            }
            

            res.status(200).json({ success: true, message: `User ${targetUid} deleted successfully from Auth and Firestore.` });

        } catch (error) {
            console.error(`❌ Failed to delete user ${targetUid}:`, error);
            if (error.code === 'auth/user-not-found') {
                return res.status(404).json({ message: `User ${targetUid} not found in Firebase Authentication.`, success: false });
            }
            res.status(500).json({ 
                message: `Failed to delete user ${targetUid}. ${error.message}`, 
                success: false, 
                code: "DELETE_USER_ERROR" 
            });
        }
    })
);


// --- TechDetail and Event routes ---
app.get("/technologies", verifyFirebaseToken, loadFirestoreUserProfile, asyncHandler(async (req, res) => {
    const techs = await TechDetail.find({}).sort({ createdAt: -1 });
    res.json(techs);
}));
app.get("/technologies/:id", verifyFirebaseToken, loadFirestoreUserProfile, asyncHandler(async (req, res) => {
    const tech = await TechDetail.findOne({ id: req.params.id });
    if (!tech) return res.status(404).json({ message: "Technology not found" });
    res.json(tech);
}));
app.post("/technologies", verifyFirebaseToken, loadFirestoreUserProfile, checkPermissions({ addTech: true }), handleTemporaryMulterUpload, multerErrorHandler, asyncHandler(async (req, res, next) => {
    let techData = parseTechDataFields({ ...req.body });
    const { genre } = techData;
    let tempUploadedFileObjects = req.files ? req.files.map(f => ({ url: `/uploads/${f.filename}` })) : [];
    if (!genre || typeof genre !== 'string' || !genre.trim()) {
        if (tempUploadedFileObjects.length > 0) await deleteImageFiles(tempUploadedFileObjects);
        return res.status(400).json({ message: "Genre is required." });
    }
    let newDocket; let finalImages = [];
    try {
        newDocket = await generateNewDocket(genre);
        techData.docket = newDocket; techData.id = newDocket;
        const { processedImageObjects } = await processNewUploadedFiles(req.files, newDocket, req.body, 1);
        finalImages = processedImageObjects; techData.images = finalImages;
        const newTech = new TechDetail(techData);
        const savedTech = await newTech.save();
        res.status(201).json(savedTech);
    } catch (error) {
        if (finalImages.length > 0) await deleteImageFiles(finalImages);
        else if (tempUploadedFileObjects.length > 0) await deleteImageFiles(tempUploadedFileObjects);
        if (error.code === 11000) return res.status(409).json({ message: `ID/Docket ${newDocket || 'unknown'} conflict.`, code: 'DUPLICATE_ID' });
        next(error);
    }
}));
app.put("/technologies/:id", verifyFirebaseToken, loadFirestoreUserProfile, checkPermissions({ editTech: true }), handleTemporaryMulterUpload, multerErrorHandler, asyncHandler(async (req, res, next) => {
    const currentTechId = req.params.id;
    let incomingData = parseTechDataFields({ ...req.body });
    let tempUploadedFileObjects = req.files ? req.files.map(f => ({ url: `/uploads/${f.filename}` })) : [];
    const currentTech = await TechDetail.findOne({ id: currentTechId });
    if (!currentTech) {
        if (tempUploadedFileObjects.length > 0) await deleteImageFiles(tempUploadedFileObjects);
        return res.status(404).json({ message: `Technology ID ${currentTechId} not found` });
    }
    const oldDocket = currentTech.docket; const oldGenre = currentTech.genre;
    const newGenre = incomingData.genre ? incomingData.genre.trim() : oldGenre;
    let finalUpdateData = { ...incomingData }; let docketForFileNaming = oldDocket;
    if (newGenre.toUpperCase() !== oldGenre.toUpperCase()) {
        try {
            const newGeneratedDocket = await generateNewDocket(newGenre);
            const existingWithNewId = await TechDetail.findOne({ id: newGeneratedDocket, _id: { $ne: currentTech._id } }).lean();
            if (existingWithNewId) {
                if (tempUploadedFileObjects.length > 0) await deleteImageFiles(tempUploadedFileObjects);
                return res.status(409).json({ message: `Generated ID ${newGeneratedDocket} already exists.`, code: 'DUPLICATE_ID_ON_UPDATE' });
            }
            finalUpdateData.docket = newGeneratedDocket; finalUpdateData.id = newGeneratedDocket;
            finalUpdateData.genre = newGenre; docketForFileNaming = newGeneratedDocket;
        } catch (error) {
            if (tempUploadedFileObjects.length > 0) await deleteImageFiles(tempUploadedFileObjects);
            return next(new Error(`Failed to generate new docket: ${error.message}`));
        }
    } else {
        delete finalUpdateData.id; delete finalUpdateData.docket;
        finalUpdateData.genre = oldGenre;
    }
    const imagesToKeepFromRequest = Array.isArray(finalUpdateData.existingImages) ? finalUpdateData.existingImages : [];
    const urlsToKeepInRequest = imagesToKeepFromRequest.map(img => img?.url).filter(Boolean);
    const imagesToDeletePhysically = currentTech.images?.filter(img => img && !urlsToKeepInRequest.includes(img.url)) || [];
    await deleteImageFiles(imagesToDeletePhysically);
    let currentFileIndex = 1;
    const { processedImageObjects: finalKeptImages, nextAvailableIndex: nextIndexAfterKept } = await renameKeptImagesAndAssignNewNames(imagesToKeepFromRequest, docketForFileNaming, currentFileIndex);
    currentFileIndex = nextIndexAfterKept;
    const { processedImageObjects: newlyUploadedAndProcessedImages } = await processNewUploadedFiles(req.files, docketForFileNaming, req.body, currentFileIndex);
    finalUpdateData.images = [...finalKeptImages, ...newlyUploadedAndProcessedImages];
    delete finalUpdateData.existingImages;
    try {
        const updatedTech = await TechDetail.findOneAndUpdate({ id: currentTechId }, { $set: finalUpdateData }, { new: true, runValidators: true });
        if (!updatedTech) {
            if (newlyUploadedAndProcessedImages.length > 0) await deleteImageFiles(newlyUploadedAndProcessedImages);
            return res.status(404).json({ message: "Technology not found during update." });
        }
        res.json(updatedTech);
    } catch (error) {
        if (newlyUploadedAndProcessedImages.length > 0) await deleteImageFiles(newlyUploadedAndProcessedImages);
        if (error.code === 11000) return res.status(409).json({ message: `Update failed: Conflict with ID/Docket.`, code: 'DUPLICATE_ID_ON_UPDATE' });
        next(error);
    }
}));
app.delete("/technologies/:id", verifyFirebaseToken, loadFirestoreUserProfile, checkPermissions({ deleteTech: true }), asyncHandler(async (req, res) => {
    const techId = req.params.id;
    const tech = await TechDetail.findOne({ id: techId });
    if (!tech) return res.status(404).json({ message: "Technology not found" });
    if (tech.images && tech.images.length > 0) await deleteImageFiles(tech.images);
    const deletionResult = await TechDetail.deleteOne({ id: techId });
    if (deletionResult.deletedCount === 0) return res.status(404).json({ message: "Technology not found during deletion." });
    res.json({ message: "Technology deleted successfully", id: techId });
}));
app.get("/events", verifyFirebaseToken, loadFirestoreUserProfile, asyncHandler(async (req, res) => {
    const events = await Event.find({}).sort({ day: 1, title: 1 });
    res.json(events);
}));
app.get("/events/:title/:day", verifyFirebaseToken, loadFirestoreUserProfile, asyncHandler(async (req, res) => {
    const title = decodeURIComponent(req.params.title);
    const day = decodeURIComponent(req.params.day);
    const event = await Event.findOne({ title, day });
    if (!event) return res.status(404).json({ message: "Event not found" });
    res.json(event);
}));
app.post("/events", verifyFirebaseToken, loadFirestoreUserProfile, checkPermissions({ addEvent: true }), asyncHandler(async (req, res, next) => {
    try {
        const newEvent = new Event(req.body);
        const savedEvent = await newEvent.save();
        res.status(201).json(savedEvent);
    } catch (error) {
        if (error.code === 11000) return res.status(409).json({ message: `Event already exists.`, code: 'DUPLICATE_EVENT' });
        next(error);
    }
}));
app.put("/events/:title/:day", verifyFirebaseToken, loadFirestoreUserProfile, checkPermissions({ editEvent: true }), asyncHandler(async (req, res, next) => {
    const title = decodeURIComponent(req.params.title);
    const day = decodeURIComponent(req.params.day);
    try {
        const updatedEvent = await Event.findOneAndUpdate({ title, day }, req.body, { new: true, runValidators: true });
        if (!updatedEvent) return res.status(404).json({ message: "Event not found" });
        res.json(updatedEvent);
    } catch (error) {
        if (error.code === 11000) {
            const conflictingEvent = await Event.findOne({ title: req.body.title, day: req.body.day });
            if (conflictingEvent && (!req.body._id || String(conflictingEvent._id) !== String(req.body._id))) {
                return res.status(409).json({ message: `Update failed: Event already exists.`, code: 'DUPLICATE_EVENT_ON_UPDATE' });
            }
        }
        next(error);
    }
}));
app.delete("/events/:title/:day", verifyFirebaseToken, loadFirestoreUserProfile, checkPermissions({ deleteEvent: true }), asyncHandler(async (req, res) => {
    const title = decodeURIComponent(req.params.title);
    const day = decodeURIComponent(req.params.day);
    const deletedEvent = await Event.findOneAndDelete({ title, day });
    if (!deletedEvent) return res.status(404).json({ message: "Event not found" });
    res.json({ message: "Event deleted successfully", title, day });
}));

// --- Global Error Handler ---
app.use((err, req, res, next) => {
    console.error("❌ Top Level Unhandled Error:", err.stack || err.message);
    let statusCode = err.status || err.statusCode || 500;
    let message = err.message || "An internal server error occurred.";
    let errorCode = err.code;
    if (err.name === 'ValidationError') {
        statusCode = 400; message = Object.values(err.errors).map(val => val.message).join(', '); errorCode = 'VALIDATION_ERROR';
    } else if (err.name === 'CastError') {
        statusCode = 400; message = `Invalid format for field '${err.path}'.`; errorCode = 'CAST_ERROR';
    } else if (err.code === 11000) {
        statusCode = 409; 
        const match = err.message.match(/index: (.+?)_1 dup key: { (.+?):/);
        if (match && match[2]) {
            message = `Duplicate value for ${match[2].replace(/"/g, '')}. This value must be unique.`;
        } else {
            message = `Duplicate key error. A record with this identifier already exists.`;
        }
        errorCode = 'DUPLICATE_KEY';
    }
    if (res.headersSent) return next(err);
    res.status(statusCode).json({ 
        message, success: false, 
        ...(errorCode && { code: errorCode }), 
        ...(NODE_ENV === 'development' && { stack: err.stack }) 
    });
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT} [${NODE_ENV}]`);
    console.log(`🔗 CORS enabled. Ensure your frontend is running on a whitelisted origin if not open.`);
    console.log(`🛡️ Cross-Origin-Opener-Policy is set to "same-origin-allow-popups"`);
});
