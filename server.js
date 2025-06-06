import dotenv from "dotenv";
dotenv.config();

import express, { json } from "express";
import cors from "cors";
import mongoose from "mongoose";
import multer from "multer";
import path from "path";
import fs from "fs";
import fsp from "fs/promises";
import { fileURLToPath } from "url";
import admin from "firebase-admin";

import { TechDetail, Event } from "./models.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const UPLOADS_DIR = path.join(__dirname, "uploads");
const BROCHURES_DIR_ABS = path.join(__dirname, "brochures");

const PORT = process.env.PORT || 5001;
const MONGO_URI = process.env.MONGO_URI;
const NODE_ENV = process.env.NODE_ENV || "development";

const serviceAccountPath = path.join(
  __dirname,
  "firebase-service-account-key.json"
);

if (!fs.existsSync(serviceAccountPath)) {
  console.error("Firebase service account key file not found!");
  process.exit(1);
}

try {
  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccountPath),
    });
  }
} catch (error) {
  console.error("Firebase admin initialization error:", error);
  process.exit(1);
}
const firestore = admin.firestore();

if (!MONGO_URI) {
  console.error("MONGO_URI not found in environment variables!");
  process.exit(1);
}

app.use(cors());
app.use(json());

app.use((req, res, next) => {
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
  next();
});

app.use("/uploads", express.static(UPLOADS_DIR));
app.use("/brochures", express.static(BROCHURES_DIR_ABS));

mongoose
  .connect(MONGO_URI)
  .then(() => {
    // console.log("MongoDB connected successfully."); // Uncomment for debugging
  })
  .catch((err) => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const generateNewDocket = async (genre) => {
  if (!genre || typeof genre !== "string" || !genre.trim()) {
    throw new Error("Invalid genre provided for docket generation.");
  }
  const sanitizedGenre = genre
    .trim()
    .replace(/[^a-zA-Z0-9]/g, "")
    .toUpperCase();
  if (!sanitizedGenre) {
    throw new Error(
      "Genre contains invalid characters or is empty after sanitization."
    );
  }
  const result = await TechDetail.aggregate([
    { $match: { docket: new RegExp(`^${sanitizedGenre}-(\\d+)$`) } },
    {
      $addFields: {
        numberStr: {
          $arrayElemAt: [
            { $regexFindAll: { input: "$docket", regex: /(\d+)$/ } },
            0,
          ],
        },
      },
    },
    {
      $addFields: {
        numberPart: {
          $cond: {
            if: { $eq: [{ $type: "$numberStr.captures" }, "array"] },
            then: { $toInt: { $arrayElemAt: ["$numberStr.captures", 0] } },
            else: null,
          },
        },
      },
    },
    { $match: { numberPart: { $ne: null } } },
    { $sort: { numberPart: -1 } },
    { $limit: 1 },
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
  const fieldsToParse = [
    "advantages",
    "applications",
    "useCases",
    "innovators",
    "relatedLinks",
    "existingImages",
    "existingBrochures",
  ];
  const arrayFields = ["advantages", "applications", "useCases"];
  const objectArrayFields = [
    "innovators",
    "relatedLinks",
    "existingImages",
    "existingBrochures",
  ];

  fieldsToParse.forEach((field) => {
    if (data[field] && typeof data[field] === "string") {
      try {
        const parsed = JSON.parse(data[field]);
        if (
          (arrayFields.includes(field) || objectArrayFields.includes(field)) &&
          !Array.isArray(parsed)
        ) {
          data[field] = [];
        } else {
          data[field] = parsed;
        }
      } catch (e) {
        if (arrayFields.includes(field)) {
          data[field] = data[field]
            .split(",")
            .map((item) => item.trim())
            .filter(Boolean);
        } else {
          data[field] = [];
        }
      }
    } else if (
      (arrayFields.includes(field) || objectArrayFields.includes(field)) &&
      !data[field]
    ) {
      data[field] = [];
    }
  });

  if (data.existingImages && Array.isArray(data.existingImages)) {
    data.existingImages = data.existingImages
      .map((img) => {
        if (typeof img === "string") return { url: img, caption: "" };
        return img;
      })
      .filter((img) => img && typeof img.url === "string");
  }

  if (data.existingBrochures && Array.isArray(data.existingBrochures)) {
    data.existingBrochures = data.existingBrochures.filter(
      (b) =>
        b && typeof b.url === "string" && typeof b.originalName === "string"
    );
  }
  return data;
};

const deleteImageFiles = async (imagesToDelete = []) => {
  if (!Array.isArray(imagesToDelete) || imagesToDelete.length === 0)
    return Promise.resolve();
  const deletionPromises = imagesToDelete.map((image) => {
    if (
      image?.url &&
      typeof image.url === "string" &&
      image.url.startsWith("/uploads/")
    ) {
      const relativePathFromUploadsDir = image.url.substring(
        "/uploads/".length
      );
      const imagePath = path.join(UPLOADS_DIR, relativePathFromUploadsDir);
      return fsp.unlink(imagePath).catch((err) => {
        if (err.code !== "ENOENT") {
          console.error(`Failed to delete image: ${imagePath}`, err);
        }
      });
    }
    return Promise.resolve();
  });
  await Promise.all(deletionPromises);
};

const deleteUploadedFile = async (fileServerPath) => {
  if (!fileServerPath || typeof fileServerPath !== "string")
    return Promise.resolve();
  let physicalPath;
  if (fileServerPath.startsWith("/brochures/")) {
    const fileName = fileServerPath.substring("/brochures/".length);
    physicalPath = path.join(BROCHURES_DIR_ABS, fileName);
  } else if (fileServerPath.startsWith("/uploads/")) {
    const relativePath = fileServerPath.substring("/uploads/".length);
    physicalPath = path.join(UPLOADS_DIR, relativePath);
  } else {
    return Promise.resolve();
  }
  try {
    await fsp.access(physicalPath);
    await fsp.unlink(physicalPath);
  } catch (err) {
    if (err.code !== "ENOENT") {
      console.error(`Failed to delete file: ${physicalPath}`, err);
    }
  }
  return Promise.resolve();
};

const tempStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
    cb(null, UPLOADS_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(
      null,
      `temp-${file.fieldname}-${uniqueSuffix}${path.extname(file.originalname)}`
    );
  },
});

const fileFilter = (req, file, cb) => {
  let originalFilenameForValidation = file.originalname;
  if (
    file.originalname &&
    Buffer.byteLength(file.originalname, "utf8") !== file.originalname.length
  ) {
    try {
      originalFilenameForValidation = Buffer.from(
        file.originalname,
        "latin1"
      ).toString("utf8");
    } catch (e) { }
  }

  if (file.fieldname === "brochureFiles") {
    if (!originalFilenameForValidation.match(/\.(pdf|doc|docx|txt|odt)$/i)) {
      req.fileValidationError =
        "Invalid brochure file type. Allowed: PDF, DOC, DOCX, TXT, ODT.";
      return cb(new Error(req.fileValidationError), false);
    }
  } else if (file.fieldname === "images") {
    if (!originalFilenameForValidation.match(/\.(jpg|jpeg|png|gif|webp)$/i)) {
      req.fileValidationError = "Invalid image file type.";
      return cb(new Error(req.fileValidationError), false);
    }
  } else {
    req.fileValidationError = `Unexpected file field: ${file.fieldname}.`;
    return cb(new Error(req.fileValidationError), false);
  }
  cb(null, true);
};

const tempUpload = multer({
  storage: tempStorage,
  fileFilter,
  limits: { fileSize: 10 * 1024 * 1024 },
});

const handleTemporaryMulterUpload = tempUpload.fields([
  { name: "images", maxCount: 5 },
  { name: "brochureFiles", maxCount: 5 },
]);

const multerErrorHandler = (err, req, res, next) => {
  if (req.fileValidationError)
    return res.status(400).json({ message: req.fileValidationError });
  if (err instanceof multer.MulterError) {
    let message = "File upload error.";
    if (err.code === "LIMIT_FILE_SIZE")
      message = "File size exceeds 10MB limit.";
    else if (err.code === "LIMIT_UNEXPECTED_FILE")
      message = "Unexpected field or too many files.";
    else if (err.code === "LIMIT_FIELD_COUNT")
      message = `Too many files for a field (e.g. >5 images or >5 brochures).`;
    return res.status(400).json({ message, code: err.code });
  }
  if (err) return next(err);
  next();
};

const renameKeptImagesAndAssignNewNames = async (
  imagesToKeep,
  newDocketBase,
  startIndex = 1
) => {
  const sanitizedNewDocket = newDocketBase.replace(/[^a-zA-Z0-9_-]/g, "_");
  const processedKeptImages = [];
  let currentIndex = startIndex;
  for (const keptImage of imagesToKeep) {
    if (
      !keptImage?.url ||
      typeof keptImage.url !== "string" ||
      !keptImage.url.startsWith("/uploads/")
    ) {
      if (keptImage?.url)
        processedKeptImages.push({
          url: keptImage.url,
          caption: keptImage.caption || "",
        });
      continue;
    }
    const oldFilenameRelative = keptImage.url.substring("/uploads/".length);
    const oldAbsolutePath = path.join(UPLOADS_DIR, oldFilenameRelative);
    const extension = path.extname(oldFilenameRelative);
    const newFilename = `${sanitizedNewDocket}-${currentIndex}${extension}`;
    const newAbsolutePath = path.join(UPLOADS_DIR, newFilename);

    if (oldAbsolutePath === newAbsolutePath) {
      try {
        await fsp.access(oldAbsolutePath);
        processedKeptImages.push({
          url: `/uploads/${newFilename}`,
          caption: keptImage.caption || "",
        });
      } catch (e) { }
    } else {
      try {
        await fsp.access(oldAbsolutePath);
        await fsp.rename(oldAbsolutePath, newAbsolutePath);
        processedKeptImages.push({
          url: `/uploads/${newFilename}`,
          caption: keptImage.caption || "",
        });
      } catch (error) {
        try {
          await fsp.access(oldAbsolutePath);
          processedKeptImages.push({
            url: keptImage.url,
            caption: keptImage.caption || "",
          });
        } catch (fallbackAccessError) { }
      }
    }
    currentIndex++;
  }
  return {
    processedImageObjects: processedKeptImages,
    nextAvailableIndex: currentIndex,
  };
};

const processNewUploadedFiles = async (
  tempFiles = [],
  docketBase,
  bodyForCaptions = {},
  startIndex = 1
) => {
  if (!tempFiles || tempFiles.length === 0)
    return { processedImageObjects: [], nextAvailableIndex: startIndex };
  const sanitizedDocket = docketBase.replace(/[^a-zA-Z0-9_-]/g, "_");
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
      newImageObjects.push({
        url: `/uploads/${newFilename}`,
        caption:
          bodyForCaptions[`imageCaptions[${i}]`] || tempFile.originalname,
      });
    } catch (renameError) {
      try {
        await fsp.unlink(tempPath);
      } catch (e) { }
    }
    currentIndex++;
  }
  return {
    processedImageObjects: newImageObjects,
    nextAvailableIndex: currentIndex,
  };
};

const processNewBrochureFiles = async (tempBrochureFiles = []) => {
  if (!tempBrochureFiles || tempBrochureFiles.length === 0) return [];

  const processedBrochures = [];
  await fsp.mkdir(BROCHURES_DIR_ABS, { recursive: true });

  for (const tempFile of tempBrochureFiles) {
    const tempPath = tempFile.path;
    const originalFileNameForSave = path
      .basename(tempFile.originalname)
      .replace(/[^a-zA-Z0-9._-]/g, "_");
    const finalBrochurePhysicalPath = path.join(
      BROCHURES_DIR_ABS,
      originalFileNameForSave
    );

    try {
      await fsp.rename(tempPath, finalBrochurePhysicalPath);
      processedBrochures.push({
        url: `/brochures/${originalFileNameForSave}`,
        originalName: tempFile.originalname,
        physicalPath: finalBrochurePhysicalPath,
      });
    } catch (renameError) {
      try {
        await fsp.unlink(tempPath);
      } catch (e) { }
    }
  }
  return processedBrochures;
};

const verifyFirebaseToken = asyncHandler(async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const idToken =
    authHeader && authHeader.startsWith("Bearer ")
      ? authHeader.split(" ")[1]
      : null;
  if (!idToken) {
    return res
      .status(401)
      .json({
        message: "Authentication token required.",
        success: false,
        code: "NO_TOKEN",
      });
  }
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.firebaseDecodedToken = decodedToken;
    next();
  } catch (error) {
    const errorCode =
      error.code === "auth/id-token-expired"
        ? "TOKEN_EXPIRED"
        : "INVALID_TOKEN";
    const message =
      error.code === "auth/id-token-expired"
        ? "Token expired. Please log in again."
        : "Invalid or expired token.";
    return res
      .status(errorCode === "TOKEN_EXPIRED" ? 401 : 403)
      .json({ message, success: false, code: errorCode });
  }
});

const loadFirestoreUserProfile = asyncHandler(async (req, res, next) => {
  if (!req.firebaseDecodedToken || !req.firebaseDecodedToken.uid) {
    return res
      .status(401)
      .json({
        message: "Firebase token not decoded or UID missing.",
        success: false,
        code: "TOKEN_NOT_DECODED",
      });
  }
  try {
    const userDoc = await firestore
      .collection("users")
      .doc(req.firebaseDecodedToken.uid)
      .get();
    if (!userDoc.exists) {
      return res
        .status(403)
        .json({
          message: "Requesting admin user profile not found in database.",
          success: false,
          code: "ADMIN_USER_PROFILE_NOT_FOUND",
        });
    }
    req.user = { uid: req.firebaseDecodedToken.uid, ...userDoc.data() };
    next();
  } catch (error) {
    return res
      .status(500)
      .json({
        message: "Error loading admin user profile.",
        success: false,
        code: "ADMIN_PROFILE_LOAD_ERROR",
      });
  }
});

const checkPermissions = (requiredAccess) => {
  return (req, res, next) => {
    if (!req.user) {
      return res
        .status(401)
        .json({
          message: "Admin user profile not loaded. Permission check failed.",
          success: false,
          code: "ADMIN_PROFILE_REQUIRED_FOR_PERMISSIONS",
        });
    }
    const {
      role,
      editTech,
      deleteTech,
      addTech,
      editEvent,
      deleteEvent,
      addEvent,
    } = req.user;
    let hasPermission = false;
    if (role === "superAdmin") {
      hasPermission = true;
    } else if (typeof requiredAccess === "string") {
      hasPermission = role === requiredAccess;
    } else if (Array.isArray(requiredAccess)) {
      hasPermission = requiredAccess.includes(role);
    } else if (typeof requiredAccess === "object" && requiredAccess !== null) {
      const permissionKey = Object.keys(requiredAccess)[0];
      const requiredValue = requiredAccess[permissionKey];
      if (permissionKey === "editTech")
        hasPermission = editTech === requiredValue;
      else if (permissionKey === "deleteTech")
        hasPermission = deleteTech === requiredValue;
      else if (permissionKey === "addTech")
        hasPermission = addTech === requiredValue;
      else if (permissionKey === "editEvent")
        hasPermission = editEvent === requiredValue;
      else if (permissionKey === "deleteEvent")
        hasPermission = deleteEvent === requiredValue;
      else if (permissionKey === "addEvent")
        hasPermission = addEvent === requiredValue;
    }
    if (hasPermission) {
      next();
    } else {
      let requiredDescription = JSON.stringify(requiredAccess);
      if (typeof requiredAccess === "string")
        requiredDescription = `role: ${requiredAccess}`;
      else if (Array.isArray(requiredAccess))
        requiredDescription = `one of roles: ${requiredAccess.join(", ")}`;
      else if (typeof requiredAccess === "object")
        requiredDescription = `permission: ${
          Object.keys(requiredAccess)[0]
        } = ${Object.values(requiredAccess)[0]}`;
      return res
        .status(403)
        .json({
          message: `Access denied. Requesting admin requires ${requiredDescription}. Your role: ${role}.`,
          success: false,
        });
    }
  };
};

app.post(
  "/api/auth/create-profile", // CORRECTED
  verifyFirebaseToken,
  asyncHandler(async (req, res) => {
    const {
      uid,
      email,
      name: firebaseName,
      picture,
    } = req.firebaseDecodedToken;
    const signInProvider =
      req.firebaseDecodedToken.firebase?.sign_in_provider || "unknown";
    const { name: bodyName } = req.body;
    const userRef = firestore.collection("users").doc(uid);
    const userDoc = await userRef.get();
    if (userDoc.exists) {
      return res
        .status(200)
        .json({
          message: "User profile already exists.",
          success: true,
          user: userDoc.data(),
        });
    }
    const displayName = bodyName || firebaseName || email.split("@")[0];
    const newUserProfile = {
      uid,
      email,
      name: displayName,
      photoURL: picture || null,
      role: "employee",
      editTech: false,
      deleteTech: false,
      addTech: true,
      editEvent: false,
      deleteEvent: false,
      addEvent: true,
      authProvider: signInProvider,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };
    await userRef.set(newUserProfile);
    res
      .status(201)
      .json({
        message: "User profile created successfully.",
        success: true,
        user: newUserProfile,
      });
  })
);

app.get(
  "/api/users/me", // CORRECTED
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  asyncHandler(async (req, res) => {
    res.status(200).json({ success: true, user: req.user });
  })
);

app.put(
  "/api/users/:uid/permissions", // CORRECTED
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  checkPermissions("superAdmin"),
  asyncHandler(async (req, res) => {
    const targetUid = req.params.uid;
    const {
      role,
      editTech,
      deleteTech,
      addTech,
      editEvent,
      deleteEvent,
      addEvent,
    } = req.body;

    const userRef = firestore.collection("users").doc(targetUid);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res
        .status(404)
        .json({
          message: `User profile for UID ${targetUid} not found.`,
          success: false,
        });
    }

    if (
      req.user.uid === targetUid &&
      userDoc.data().role === "superAdmin" &&
      role !== "superAdmin" &&
      role !== undefined
    ) {
      return res
        .status(403)
        .json({
          message: "Super admin cannot change their own role.",
          success: false,
        });
    }

    const updates = { updatedAt: admin.firestore.FieldValue.serverTimestamp() };
    const allowedAssignableRoles = ["admin", "employee"];
    if (role !== undefined) {
      if (userDoc.data().role === "superAdmin" && role !== "superAdmin") {
      }
      if (allowedAssignableRoles.includes(role)) {
        updates.role = role;
      } else if (
        role === "superAdmin" &&
        (userDoc.data().role === "superAdmin" || req.user.role === "superAdmin")
      ) {
        updates.role = role;
      } else {
        return res
          .status(400)
          .json({
            message: `Invalid role assignment: ${role}. Allowed: ${allowedAssignableRoles.join(
              ", "
            )}.`,
            success: false,
          });
      }
    }

    if (editTech !== undefined) updates.editTech = Boolean(editTech);
    if (deleteTech !== undefined) updates.deleteTech = Boolean(deleteTech);
    if (addTech !== undefined) updates.addTech = Boolean(addTech);
    if (editEvent !== undefined) updates.editEvent = Boolean(editEvent);
    if (deleteEvent !== undefined) updates.deleteEvent = Boolean(deleteEvent);
    if (addEvent !== undefined) updates.addEvent = Boolean(addEvent);

    if (Object.keys(updates).length === 1 && !updates.role) {
      return res
        .status(400)
        .json({
          message: "No valid permissions or role provided to update.",
          success: false,
        });
    }

    await userRef.update(updates);
    const updatedUserDoc = await userRef.get();
    res
      .status(200)
      .json({
        message: "User permissions updated successfully.",
        success: true,
        user: updatedUserDoc.data(),
      });
  })
);

// This route already has /api, so it's left unchanged
app.get(
  "/api/admin/all-users",
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  checkPermissions("superAdmin"),
  asyncHandler(async (req, res) => {
    const listAuthUsersResult = await admin.auth().listUsers(1000);
    const combinedUsers = await Promise.all(
      listAuthUsersResult.users.map(async (authUserRecord) => {
        let firestoreProfileData = {};
        const defaultPermissions = {
          role: "employee",
          name:
            authUserRecord.displayName ||
            authUserRecord.email?.split("@")[0] ||
            "N/A",
          photoURL: authUserRecord.photoURL || null,
          editTech: false,
          addTech: true,
          deleteTech: false,
          editEvent: false,
          addEvent: true,
          deleteEvent: false,
        };
        try {
          const userDocRef = firestore
            .collection("users")
            .doc(authUserRecord.uid);
          const userDoc = await userDocRef.get();
          if (userDoc.exists) {
            firestoreProfileData = userDoc.data();
          } else {
            firestoreProfileData = defaultPermissions;
          }
        } catch (profileError) {
          firestoreProfileData.role = "Error Loading Profile";
        }
        return {
          uid: authUserRecord.uid,
          email: authUserRecord.email,
          emailVerified: authUserRecord.emailVerified,
          disabled: authUserRecord.disabled,
          creationTime: authUserRecord.metadata.creationTime,
          lastSignInTime: authUserRecord.metadata.lastSignInTime,
          customClaims: authUserRecord.customClaims,
          providerData: authUserRecord.providerData.map((p) => ({
            providerId: p.providerId,
            displayName: p.displayName,
            email: p.email,
            photoURL: p.photoURL,
            uid: p.uid,
          })),
          displayName:
            firestoreProfileData.name ||
            authUserRecord.displayName ||
            defaultPermissions.name,
          photoURL:
            firestoreProfileData.photoURL ||
            authUserRecord.photoURL ||
            defaultPermissions.photoURL,
          role: firestoreProfileData.role || defaultPermissions.role,
          editTech: firestoreProfileData.editTech === true,
          addTech:
            firestoreProfileData.addTech !== undefined
              ? firestoreProfileData.addTech === true
              : defaultPermissions.addTech,
          deleteTech: firestoreProfileData.deleteTech === true,
          editEvent: firestoreProfileData.editEvent === true,
          addEvent:
            firestoreProfileData.addEvent !== undefined
              ? firestoreProfileData.addEvent === true
              : defaultPermissions.addEvent,
          deleteEvent: firestoreProfileData.deleteEvent === true,
        };
      })
    );
    res.status(200).json({ success: true, users: combinedUsers });
  })
);

// This route already has /api, so it's left unchanged
app.delete(
  "/api/admin/users/:uid",
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  checkPermissions("superAdmin"),
  asyncHandler(async (req, res) => {
    const targetUid = req.params.uid;
    const requestingAdminUid = req.user.uid;

    if (targetUid === requestingAdminUid) {
      return res
        .status(403)
        .json({
          message: "Super admin cannot delete their own account.",
          success: false,
          code: "CANNOT_DELETE_SELF",
        });
    }

    const targetUserFirestoreRef = firestore.collection("users").doc(targetUid);
    let targetUserFirestoreDoc;
    try {
      targetUserFirestoreDoc = await targetUserFirestoreRef.get();
    } catch (fsFetchError) {
      return res
        .status(500)
        .json({
          message: `Error fetching user profile before deletion: ${fsFetchError.message}`,
          success: false,
          code: "FIRESTORE_FETCH_ERROR_ON_DELETE",
        });
    }

    if (
      targetUserFirestoreDoc.exists &&
      targetUserFirestoreDoc.data().role === "superAdmin"
    ) {
      return res
        .status(403)
        .json({
          message: "Cannot delete another super admin account.",
          success: false,
          code: "CANNOT_DELETE_OTHER_SUPERADMIN",
        });
    }

    try {
      await admin.auth().deleteUser(targetUid);
      let firestoreMessage = "Firebase Auth user deleted.";

      if (targetUserFirestoreDoc.exists) {
        try {
          await targetUserFirestoreRef.delete();
          firestoreMessage += " Firestore profile also deleted.";
        } catch (firestoreError) {
          return res.status(500).json({
            message: `User ${targetUid} was deleted from Firebase Authentication, but their Firestore profile could not be deleted. ${firestoreError.message}`,
            success: false,
            code: "AUTH_DELETED_FIRESTORE_FAILED",
          });
        }
      } else {
        firestoreMessage +=
          " No corresponding Firestore profile found to delete.";
      }

      res
        .status(200)
        .json({
          success: true,
          message: `User ${targetUid} processed: ${firestoreMessage}`,
          code: "USER_DELETED_SUCCESSFULLY",
        });
    } catch (error) {
      if (error.code === "auth/user-not-found") {
        if (targetUserFirestoreDoc.exists) {
          try {
            await targetUserFirestoreRef.delete();
            return res.status(200).json({
              success: true,
              message: `User ${targetUid} was not found in Firebase Authentication, but their orphaned Firestore profile was successfully deleted.`,
              code: "AUTH_NOT_FOUND_FIRESTORE_DELETED",
            });
          } catch (fsCleanupError) {
            return res.status(500).json({
              message: `User ${targetUid} was not found in Firebase Authentication. An error occurred while attempting to delete their orphaned Firestore profile: ${fsCleanupError.message}`,
              success: false,
              code: "FIRESTORE_ORPHAN_CLEANUP_ERROR",
            });
          }
        } else {
          return res
            .status(404)
            .json({
              message: `User ${targetUid} not found in Firebase Authentication and no corresponding Firestore profile found.`,
              success: false,
              code: "USER_COMPLETELY_NOT_FOUND",
            });
        }
      }

      let responseMessage = `Failed to delete user ${targetUid}.`;
      if (error.message) responseMessage += ` ${error.message}`;
      if (targetUserFirestoreDoc.exists)
        responseMessage += ` Firestore profile might still exist.`;

      return res.status(500).json({
        message: responseMessage,
        success: false,
        code: "DELETE_USER_GENERAL_ERROR",
      });
    }
  })
);

app.get(
  "/api/technologies", // CORRECTED
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  asyncHandler(async (req, res) => {
    const techs = await TechDetail.find({}).sort({ createdAt: -1 });
    res.json(techs);
  })
);

app.get(
  "/api/technologies/:id", // CORRECTED
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  asyncHandler(async (req, res) => {
    const tech = await TechDetail.findOne({ id: req.params.id });
    if (!tech) return res.status(404).json({ message: "Technology not found" });
    res.json(tech);
  })
);

app.post(
  "/api/technologies", // CORRECTED
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  checkPermissions({ addTech: true }),
  handleTemporaryMulterUpload,
  multerErrorHandler,
  asyncHandler(async (req, res, next) => {
    let techData = parseTechDataFields({ ...req.body });
    const { genre } = techData;

    const tempImageFiles = req.files?.images || [];
    const tempBrochureFiles = req.files?.brochureFiles || [];

    let tempUploadedImageObjectsForCleanup = tempImageFiles.map((f) => ({
      url: `/uploads/${f.filename}`,
    }));
    let tempBrochureFilePathsForCleanup = tempBrochureFiles.map(
      (f) => `/uploads/${f.filename}`
    );

    let newDocket;
    let finalImages = [];
    let processedBrochureObjectsForDB = [];
    let processedBrochurePhysicalFiles = [];

    if (!genre || typeof genre !== "string" || !genre.trim()) {
      if (tempImageFiles.length > 0)
        await deleteImageFiles(tempUploadedImageObjectsForCleanup);
      for (const p of tempBrochureFilePathsForCleanup)
        await deleteUploadedFile(p);
      return res.status(400).json({ message: "Genre is required." });
    }

    try {
      newDocket = await generateNewDocket(genre);
      techData.docket = newDocket;
      techData.id = newDocket;

      const imageProcessingResult = await processNewUploadedFiles(
        tempImageFiles,
        newDocket,
        req.body,
        1
      );
      finalImages = imageProcessingResult.processedImageObjects;
      techData.images = finalImages.map(({ url, caption }) => ({
        url,
        caption,
      }));

      const brochureProcessingResult = await processNewBrochureFiles(
        tempBrochureFiles
      );
      processedBrochurePhysicalFiles = brochureProcessingResult;
      processedBrochureObjectsForDB = brochureProcessingResult.map(
        ({ url, originalName }) => ({ url, originalName })
      );
      techData.brochures = processedBrochureObjectsForDB;

      const newTech = new TechDetail(techData);
      const savedTech = await newTech.save();
      res.status(201).json(savedTech);
    } catch (error) {
      if (finalImages.length > 0) await deleteImageFiles(finalImages);
      else if (tempImageFiles.length > 0)
        await deleteImageFiles(tempUploadedImageObjectsForCleanup);

      for (const brochure of processedBrochurePhysicalFiles) {
        if (brochure.physicalPath) await deleteUploadedFile(brochure.url);
      }

      if (
        processedBrochurePhysicalFiles.length === 0 &&
        tempBrochureFiles.length > 0
      ) {
        for (const p of tempBrochureFilePathsForCleanup)
          await deleteUploadedFile(p);
      }

      if (error.code === 11000)
        return res
          .status(409)
          .json({
            message: `ID/Docket ${newDocket || "unknown"} conflict.`,
            code: "DUPLICATE_ID",
          });
      next(error);
    }
  })
);

app.put(
  "/api/technologies/:id", // CORRECTED
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  checkPermissions({ editTech: true }),
  handleTemporaryMulterUpload,
  multerErrorHandler,
  asyncHandler(async (req, res, next) => {
    const currentTechId = req.params.id;
    let incomingData = parseTechDataFields({ ...req.body });

    const tempNewImageFiles = req.files?.images || [];
    const tempNewBrochureFiles = req.files?.brochureFiles || [];

    let tempUploadedImageObjectsForCleanup = tempNewImageFiles.map((f) => ({
      url: `/uploads/${f.filename}`,
    }));
    let tempNewBrochureFilePathsForCleanup = tempNewBrochureFiles.map(
      (f) => `/uploads/${f.filename}`
    );

    const currentTech = await TechDetail.findOne({ id: currentTechId });
    if (!currentTech) {
      if (tempNewImageFiles.length > 0)
        await deleteImageFiles(tempUploadedImageObjectsForCleanup);
      for (const p of tempNewBrochureFilePathsForCleanup)
        await deleteUploadedFile(p);
      return res
        .status(404)
        .json({ message: `Technology ID ${currentTechId} not found` });
    }

    const oldDocket = currentTech.docket;
    const oldGenre = currentTech.genre;
    let finalUpdateData = { ...incomingData };
    let docketForFileNaming = oldDocket;

    if (
      incomingData.genre &&
      incomingData.genre.trim().toUpperCase() !== oldGenre.toUpperCase()
    ) {
      const newGenre = incomingData.genre.trim();
      try {
        const newGeneratedDocket = await generateNewDocket(newGenre);
        const existingWithNewId = await TechDetail.findOne({
          id: newGeneratedDocket,
          _id: { $ne: currentTech._id },
        }).lean();
        if (existingWithNewId) {
          if (tempNewImageFiles.length > 0)
            await deleteImageFiles(tempUploadedImageObjectsForCleanup);
          for (const p of tempNewBrochureFilePathsForCleanup)
            await deleteUploadedFile(p);
          return res
            .status(409)
            .json({
              message: `Generated ID ${newGeneratedDocket} for new genre already exists.`,
              code: "DUPLICATE_ID_ON_UPDATE",
            });
        }
        finalUpdateData.docket = newGeneratedDocket;
        finalUpdateData.id = newGeneratedDocket;
        finalUpdateData.genre = newGenre;
        docketForFileNaming = newGeneratedDocket;
      } catch (error) {
        if (tempNewImageFiles.length > 0)
          await deleteImageFiles(tempUploadedImageObjectsForCleanup);
        for (const p of tempNewBrochureFilePathsForCleanup)
          await deleteUploadedFile(p);
        return next(
          new Error(
            `Failed to generate new docket for genre change: ${error.message}`
          )
        );
      }
    } else {
      delete finalUpdateData.id;
      delete finalUpdateData.docket;
      finalUpdateData.genre = oldGenre;
    }

    const imagesToKeepFromRequest = Array.isArray(
      finalUpdateData.existingImages
    )
      ? finalUpdateData.existingImages
      : [];
    const urlsToKeepInRequest = imagesToKeepFromRequest
      .map((img) => img?.url)
      .filter(Boolean);
    const imagesOnServerToDelete =
      currentTech.images?.filter(
        (img) => img && !urlsToKeepInRequest.includes(img.url)
      ) || [];

    let currentFileIndex = 1;
    const {
      processedImageObjects: finalKeptImages,
      nextAvailableIndex: nextIndexAfterKept,
    } = await renameKeptImagesAndAssignNewNames(
      imagesToKeepFromRequest,
      docketForFileNaming,
      currentFileIndex
    );
    currentFileIndex = nextIndexAfterKept;
    const { processedImageObjects: newlyUploadedAndProcessedImages } =
      await processNewUploadedFiles(
        tempNewImageFiles,
        docketForFileNaming,
        req.body,
        currentFileIndex
      );
    finalUpdateData.images = [
      ...finalKeptImages,
      ...newlyUploadedAndProcessedImages,
    ].map(({ url, caption }) => ({ url, caption }));
    delete finalUpdateData.existingImages;

    const existingBrochuresToKeep = Array.isArray(
      finalUpdateData.existingBrochures
    )
      ? finalUpdateData.existingBrochures
      : [];
    const keptBrochureUrls = existingBrochuresToKeep.map((b) => b.url);
    const brochuresOnServerToDelete =
      currentTech.brochures?.filter(
        (b) => b && b.url && !keptBrochureUrls.includes(b.url)
      ) || [];

    let newlyProcessedBrochureObjectsWithPhysicalPath = [];

    try {
      newlyProcessedBrochureObjectsWithPhysicalPath =
        await processNewBrochureFiles(tempNewBrochureFiles);
      const newBrochureDbObjects =
        newlyProcessedBrochureObjectsWithPhysicalPath.map(
          ({ url, originalName }) => ({ url, originalName })
        );

      finalUpdateData.brochures = [
        ...existingBrochuresToKeep,
        ...newBrochureDbObjects,
      ];
      delete finalUpdateData.existingBrochures;

      const updatedTech = await TechDetail.findOneAndUpdate(
        { id: currentTechId },
        { $set: finalUpdateData },
        { new: true, runValidators: true }
      );
      if (!updatedTech) {
        if (newlyUploadedAndProcessedImages.length > 0)
          await deleteImageFiles(newlyUploadedAndProcessedImages);
        for (const brochure of newlyProcessedBrochureObjectsWithPhysicalPath) {
          if (brochure.physicalPath) await deleteUploadedFile(brochure.url);
        }
        return res
          .status(404)
          .json({
            message: "Technology not found during final update attempt.",
          });
      }

      await deleteImageFiles(imagesOnServerToDelete);
      for (const brochure of brochuresOnServerToDelete) {
        await deleteUploadedFile(brochure.url);
      }

      res.json(updatedTech);
    } catch (error) {
      if (newlyUploadedAndProcessedImages.length > 0)
        await deleteImageFiles(newlyUploadedAndProcessedImages);
      for (const brochure of newlyProcessedBrochureObjectsWithPhysicalPath) {
        if (brochure.physicalPath) await deleteUploadedFile(brochure.url);
      }
      if (
        newlyProcessedBrochureObjectsWithPhysicalPath.length === 0 &&
        tempNewBrochureFiles.length > 0
      ) {
        for (const p of tempNewBrochureFilePathsForCleanup)
          await deleteUploadedFile(p);
      }

      if (error.code === 11000)
        return res
          .status(409)
          .json({
            message: `Update failed: Conflict with ID/Docket.`,
            code: "DUPLICATE_ID_ON_UPDATE",
          });
      next(error);
    }
  })
);

app.delete(
  "/api/technologies/:id", // CORRECTED
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  checkPermissions({ deleteTech: true }),
  asyncHandler(async (req, res) => {
    const techId = req.params.id;
    const tech = await TechDetail.findOne({ id: techId });
    if (!tech) return res.status(404).json({ message: "Technology not found" });

    if (tech.images && tech.images.length > 0) {
      await deleteImageFiles(tech.images);
    }
    if (tech.brochures && tech.brochures.length > 0) {
      for (const brochure of tech.brochures) {
        if (brochure.url) await deleteUploadedFile(brochure.url);
      }
    }

    const deletionResult = await TechDetail.deleteOne({ id: techId });
    if (deletionResult.deletedCount === 0)
      return res
        .status(404)
        .json({ message: "Technology not found during deletion." });

    res.json({ message: "Technology deleted successfully", id: techId });
  })
);

app.get(
  "/api/events", // CORRECTED
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  asyncHandler(async (req, res) => {
    const events = await Event.find({}).sort({ day: 1, title: 1 });
    res.json(events);
  })
);

app.get(
  "/api/events/:title/:day", // CORRECTED
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  asyncHandler(async (req, res) => {
    const title = decodeURIComponent(req.params.title);
    const day = decodeURIComponent(req.params.day);
    const event = await Event.findOne({ title, day });
    if (!event) return res.status(404).json({ message: "Event not found" });
    res.json(event);
  })
);

app.post(
  "/api/events", // CORRECTED
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  checkPermissions({ addEvent: true }),
  asyncHandler(async (req, res, next) => {
    try {
      const newEvent = new Event(req.body);
      const savedEvent = await newEvent.save();
      res.status(201).json(savedEvent);
    } catch (error) {
      if (error.code === 11000)
        return res
          .status(409)
          .json({ message: `Event already exists.`, code: "DUPLICATE_EVENT" });
      next(error);
    }
  })
);

app.put(
  "/api/events/:title/:day", // CORRECTED
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  checkPermissions({ editEvent: true }),
  asyncHandler(async (req, res, next) => {
    const title = decodeURIComponent(req.params.title);
    const day = decodeURIComponent(req.params.day);
    try {
      const updatedEvent = await Event.findOneAndUpdate(
        { title, day },
        req.body,
        { new: true, runValidators: true }
      );
      if (!updatedEvent)
        return res.status(404).json({ message: "Event not found" });
      res.json(updatedEvent);
    } catch (error) {
      if (error.code === 11000) {
        const newTitle = req.body.title || title;
        const newDay = req.body.day || day;
        const conflictingEvent = await Event.findOne({
          title: newTitle,
          day: newDay,
        });
        if (
          conflictingEvent &&
          (String(conflictingEvent.title) !== title ||
            String(conflictingEvent.day) !== day)
        ) {
          return res
            .status(409)
            .json({
              message: `Update failed: An event with title '${newTitle}' and day '${newDay}' already exists.`,
              code: "DUPLICATE_EVENT_ON_UPDATE",
            });
        }
      }
      next(error);
    }
  })
);

app.delete(
  "/api/events/:title/:day", // CORRECTED
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  checkPermissions({ deleteEvent: true }),
  asyncHandler(async (req, res) => {
    const title = decodeURIComponent(req.params.title);
    const day = decodeURIComponent(req.params.day);
    const deletedEvent = await Event.findOneAndDelete({ title, day });
    if (!deletedEvent)
      return res.status(404).json({ message: "Event not found" });
    res.json({ message: "Event deleted successfully", title, day });
  })
);

app.use((err, req, res, next) => {
  let statusCode = err.status || err.statusCode || 500;
  let message = err.message || "An internal server error occurred.";
  let errorCode = err.code;

  if (err.name === "ValidationError") {
    statusCode = 400;
    message = Object.values(err.errors)
      .map((val) => val.message)
      .join(", ");
    errorCode = "VALIDATION_ERROR";
  } else if (err.name === "CastError") {
    statusCode = 400;
    message = `Invalid format for field '${err.path}'. Expected ${err.kind}.`;
    errorCode = "CAST_ERROR";
  } else if (err.code === 11000) {
    statusCode = 409;
    const field = Object.keys(err.keyPattern || {})[0];
    message = field
      ? `An entry with this ${field} already exists.`
      : `Duplicate key error. A record with this identifier already exists.`;
    errorCode = "DUPLICATE_KEY";
  }

  if (res.headersSent) return next(err);

  res.status(statusCode).json({
    message,
    success: false,
    ...(errorCode && { code: errorCode }),
    ...(NODE_ENV === "development" && { stack: err.stack }),
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`); // Added log for confirmation
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  fs.mkdirSync(BROCHURES_DIR_ABS, { recursive: true });
});
