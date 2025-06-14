import dotenv from "dotenv";
dotenv.config();

import express, { json } from "express";
import cors from "cors";
import mongoose from "mongoose";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

import technologiesRouter from "./routes/technologies.js";
import eventsRouter from "./routes/events.js";
import usersRouter from "./routes/users.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const UPLOADS_DIR = path.join(__dirname, "uploads");
const BROCHURES_DIR_ABS = path.join(__dirname, "brochures");

const PORT = process.env.PORT || 5001;
const MONGO_URI = process.env.MONGO_URI;
const NODE_ENV = process.env.NODE_ENV || "development";

if (!MONGO_URI) {
  console.error(
    "FATAL ERROR: MONGO_URI is not defined in environment variables."
  );
  process.exit(1);
}

app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

app.use((req, res, next) => {
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
  next();
});

app.use("/uploads", express.static(UPLOADS_DIR));
app.use("/brochures", express.static(BROCHURES_DIR_ABS));

mongoose.connect(MONGO_URI).catch((err) => {
  console.error("MongoDB connection error:", err);
  process.exit(1);
});

app.use("/api/technologies", technologiesRouter);
app.use("/api/events", eventsRouter);
app.use("/api", usersRouter);

app.use((err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }

  let statusCode = err.statusCode || 500;
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
    message = `Invalid format for field '${err.path}'. Expected type ${err.kind}.`;
    errorCode = "CAST_ERROR";
  } else if (err.code === 11000) {
    statusCode = 409;
    const field = Object.keys(err.keyPattern || {})[0] || "identifier";
    message = `An entry with this ${field} already exists.`;
    errorCode = "DUPLICATE_KEY";
  }

  const errorResponse = {
    message,
    success: false,
    ...(errorCode && { code: errorCode }),
  };

  if (NODE_ENV === "development") {
    errorResponse.stack = err.stack;
  }

  res.status(statusCode).json(errorResponse);
});

app.listen(PORT, () => {
  console.log(`Server running in ${NODE_ENV} mode on port ${PORT}`);
  try {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
    fs.mkdirSync(BROCHURES_DIR_ABS, { recursive: true });
  } catch (error) {
    console.error("Error creating upload directories on startup:", error);
  }
});
