import express from "express";
import { Event } from "../models.js";
import { asyncHandler } from "../utils.js";
import {
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  checkPermissions,
} from "./users.js";

const router = express.Router();

router.get(
  "/",
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  asyncHandler(async (req, res) => {
    const events = await Event.find({}).sort({ day: 1, title: 1 });
    res.json(events);
  })
);

router.get(
  "/:title/:day",
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

router.post(
  "/",
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

router.put(
  "/:title/:day",
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
          return res.status(409).json({
            message: `Update failed: An event with title '${newTitle}' and day '${newDay}' already exists.`,
            code: "DUPLICATE_EVENT_ON_UPDATE",
          });
        }
      }
      next(error);
    }
  })
);

router.delete(
  "/:title/:day",
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

export default router;
