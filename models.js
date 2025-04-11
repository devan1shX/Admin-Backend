// models.js
import { Schema, model } from "mongoose";

// -----------------------------------------
// Mongoose Schemas & Models
// -----------------------------------------

// --- TechDetail Schema ---
// Collection: Detailed_tech (explicitly set)
const techDetailSchema = new Schema({
  id: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  description: String,
  overview: String,
  detailedDescription: String,
  genre: String,
  docket: { type: String, required: true, unique: true },
  innovators: [
    {
      name: String,
      mail : String
    }
  ],
  advantages: [String],
  applications: [String],
  useCases: [String],
  relatedLinks: [
    {
      title: String,
      url: String,
    },
  ],
  technicalSpecifications: String,
  trl: { type: Number, default: 1 },
  spotlight: { type: Boolean, default: false },
  images: [
    {
      url: String,
      caption: String,
    }
  ],
  patent: String,
});

// Optional text index
techDetailSchema.index({ overview: "text", detailedDescription: "text" });

// Export TechDetail model
export const TechDetail = model("TechDetail", techDetailSchema, "Detailed_tech");


// --- Event Schema ---
// Collection: Events (explicitly set)
const eventSchema = new Schema({
  title: { type: String, required: true },
  month: { type: String, required: true },
  day: { type: String, required: true },
  location: String,
  time: String,
  description: String,
  registration: String,
  isActive: { type: Boolean, default: false }
});

// Export Event model
export const Event = model("Event", eventSchema, "Events");


// --- User Schema (Moved from auth.js) ---
// Collection: users (default derived from model name 'User')
const userSchema = new Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true }, // Added lowercase/trim
  password: { type: String, required: true },
}, { timestamps: true }); // Optional: Add timestamps

// Export User model
export const User = model("User", userSchema); // Will use 'users' collection