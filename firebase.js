import admin from "firebase-admin";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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

export { admin, firestore };