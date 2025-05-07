// ----- MODELS FILE (e.g., models.js) -----
import { Schema, model } from "mongoose";

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
            mail: String
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

techDetailSchema.index({ overview: "text", detailedDescription: "text" });

export const TechDetail = model("TechDetail", techDetailSchema, "Detailed_tech");

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

eventSchema.index({ title: 1, day: 1 }, { unique: true });

export const Event = model("Event", eventSchema, "Events");

const userSchema = new Schema({
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    role: {
        type: String,
        required: true,
        enum: ['admin', 'employee'],
        default: 'employee'
    }
}, { timestamps: true });

export const User = model("User", userSchema);