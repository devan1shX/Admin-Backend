import express from "express";
import { admin, firestore } from "../firebase.js";
import { asyncHandler } from "../utils.js";

const router = express.Router();

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
    next();
  } catch (error) {
    return res.status(500).json({
      message: "Error loading admin user profile.",
      success: false,
      code: "ADMIN_PROFILE_LOAD_ERROR",
    });
  }
});

export const checkPermissions = (requiredAccess) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
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
      return res.status(403).json({
        message: `Access denied. Requesting admin requires ${requiredDescription}. Your role: ${role}.`,
        success: false,
      });
    }
  };
};

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

export default router;
