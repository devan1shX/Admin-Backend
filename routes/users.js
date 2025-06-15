import express from "express";
import { admin, firestore } from "../firebase.js";
import { asyncHandler } from "../utils.js";

const router = express.Router();

// =================================================================
// MIDDLEWARE (No changes made here)
// =================================================================

export const verifyFirebaseToken = asyncHandler(async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const idToken =
    authHeader && authHeader.startsWith("Bearer ")
      ? authHeader.split(" ")[1]
      : null;
  if (!idToken) {
    return res.status(401).json({
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

export const loadFirestoreUserProfile = asyncHandler(async (req, res, next) => {
  if (!req.firebaseDecodedToken || !req.firebaseDecodedToken.uid) {
    return res.status(401).json({
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
      return res.status(403).json({
        message: "Requesting admin user profile not found in database.",
        success: false,
        code: "ADMIN_USER_PROFILE_NOT_FOUND",
      });
    }
    req.user = { uid: req.firebaseDecodedToken.uid, ...userDoc.data() };
    console.log("User object being passed to permissions check:", req.user);

    next();
  } catch (error) {
    return res.status(500).json({
      message: "Error loading admin user profile.",
      success: false,
      code: "ADMIN_PROFILE_LOAD_ERROR",
    });
  }
});

// REPLACE your old checkPermissions function with this new one.

export const checkPermissions = (requiredAccess) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        message: "User profile not loaded. Permission check failed.",
        success: false,
        code: "ADMIN_PROFILE_REQUIRED_FOR_PERMISSIONS",
      });
    }

    const { role, ...permissions } = req.user;

    // 1. Super admin always has permission
    if (role === "superAdmin") {
      return next();
    }

    let hasPermission = false;
    let requiredDescription = "";

    // 2. Check for specific properties (like { addTech: true })
    if (typeof requiredAccess === 'object' && !Array.isArray(requiredAccess) && requiredAccess !== null) {
        requiredDescription = Object.keys(requiredAccess).map(key => `${key}: ${requiredAccess[key]}`).join(', ');
        hasPermission = Object.keys(requiredAccess).every(key => {
            // Check if the user has the key and its value matches
            return permissions[key] === requiredAccess[key];
        });

    // 3. Check for specific roles (like ["admin", "superAdmin"])
    } else if (Array.isArray(requiredAccess)) {
        requiredDescription = `one of roles: ${requiredAccess.join(", ")}`;
        hasPermission = requiredAccess.includes(role);
    } else if (typeof requiredAccess === 'string') {
        requiredDescription = `role: ${requiredAccess}`;
        hasPermission = (role === requiredAccess);
    }

    if (hasPermission) {
      return next();
    } else {
      return res.status(403).json({
        message: `Access denied. Action requires permissions (${requiredDescription}). Your role is '${role}'.`,
        success: false,
      });
    }
  };
};


// =================================================================
// EXISTING ROUTES (No changes made here)
// =================================================================

router.post(
  "/auth/create-profile",
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
      return res.status(200).json({
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
      editTech: true,
      deleteTech: false,
      addTech: true,
      editEvent: true,
      deleteEvent: false,
      addEvent: true,
      authProvider: signInProvider,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    await userRef.set(newUserProfile);

    res.status(201).json({
      message: "User profile created successfully.",
      success: true,
      user: newUserProfile,
    });
  })
);

router.get(
  "/users/me",
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  asyncHandler(async (req, res) => {
    res.status(200).json({ success: true, user: req.user });
  })
);


// =================================================================
// NEW ADMIN PANEL ROUTES (Added to fix the errors)
// =================================================================

// 1. GET ALL USERS (Fixes the initial 404 error on page load)
router.get(
    "/admin/all-users",
    verifyFirebaseToken,
    loadFirestoreUserProfile,
    checkPermissions(["admin", "superAdmin"]),
    asyncHandler(async (req, res) => {
        const usersSnapshot = await firestore.collection("users").get();
        if (usersSnapshot.empty) {
            return res.status(200).json({ success: true, users: [] });
        }
        const users = usersSnapshot.docs.map(doc => ({ ...doc.data(), uid: doc.id }));
        res.status(200).json({ success: true, users });
    })
);

// 2. UPDATE USER PERMISSIONS (Handles the "Save Changes" functionality)
router.put(
    "/users/:uid/permissions",
    verifyFirebaseToken,
    loadFirestoreUserProfile,
    checkPermissions(["admin", "superAdmin"]),
    asyncHandler(async (req, res) => {
        const { uid } = req.params;
        const { role, addTech, editTech, deleteTech, addEvent, editEvent, deleteEvent } = req.body;

        // Prevent a user from being updated to "superAdmin" via the API
        if (role === 'superAdmin') {
            return res.status(403).json({ success: false, message: "Cannot assign superAdmin role." });
        }
        
        const userRef = firestore.collection("users").doc(uid);
        await userRef.update({
            role,
            addTech,
            editTech,
            deleteTech,
            addEvent,
            editEvent,
            deleteEvent,
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        
        res.status(200).json({ success: true, message: "User permissions updated successfully." });
    })
);

// 3. DELETE A USER (Handles the "Delete User" functionality)
router.delete(
    "/admin/users/:uid",
    verifyFirebaseToken,
    loadFirestoreUserProfile,
    checkPermissions(["admin", "superAdmin"]),
    asyncHandler(async (req, res) => {
        const { uid } = req.params;
        const requestingUser = req.user;

        if (uid === requestingUser.uid) {
            return res.status(400).json({ success: false, message: "Cannot delete your own account." });
        }

        const userToDeleteDoc = await firestore.collection("users").doc(uid).get();
        if (!userToDeleteDoc.exists) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        if (userToDeleteDoc.data().role === "superAdmin") {
            return res.status(403).json({ success: false, message: "Cannot delete a superAdmin account." });
        }
        
        // Delete from Firestore and Firebase Auth
        await firestore.collection("users").doc(uid).delete();
        await admin.auth().deleteUser(uid);
        
        res.status(200).json({ success: true, message: "User deleted successfully." });
    })
);


export default router;
