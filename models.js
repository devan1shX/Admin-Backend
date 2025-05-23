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
            mail: String,
            _id: false
        }
    ],
    advantages: [String],
    applications: [String],
    useCases: [String],
    relatedLinks: [
        {
            title: String,
            url: String,
            _id: false
        },
    ],
    technicalSpecifications: String,
    trl: { type: Number, default: 1 },
    spotlight: { type: Boolean, default: false },
    images: [
        {
            url: String,
            caption: String,
            _id: false
        }
    ],
    patent: {
        type: String,
        enum: ["Not Filed", "Application Filed", "Under Examination", "Granted", "Abandoned/Lapsed"], // Updated professional terms
        required: true
    },
    patentId: { type: String },
    patentApplicationNumber: { type: String },
    patentFilingDate: { type: Date },
    patentGrantDate: { type: Date },
    patentDocumentUrl: { type: String },
    brochures: [
        {
            url: { type: String, required: true },
            originalName: { type: String, required: true },
            _id: false
        }
    ],
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