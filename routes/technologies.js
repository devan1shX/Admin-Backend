import express from "express";
import multer from "multer";
import path from "path";
import fs from "fs";
import fsp from "fs/promises";
import { fileURLToPath } from "url";
import { TechDetail, DeletedTech } from "../models.js";
import { asyncHandler } from "../utils.js";
import {
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  checkPermissions,
} from "./users.js";
import cron from "node-cron";

const router = express.Router();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const UPLOADS_DIR = path.join(__dirname, "..", "uploads");
const BROCHURES_DIR_ABS = path.join(__dirname, "..", "brochures");


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

  const getHighestNumberPipeline = [
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
    { $project: { numberPart: 1 } }, 
  ];

  const [activeResult, deletedResult] = await Promise.all([
    TechDetail.aggregate(getHighestNumberPipeline).exec(),
    DeletedTech.aggregate(getHighestNumberPipeline).exec(),
  ]);

  const maxNumberActive = activeResult[0]?.numberPart || 0;
  const maxNumberDeleted = deletedResult[0]?.numberPart || 0;

  const maxNumber = Math.max(maxNumberActive, maxNumberDeleted);

  const nextTechNumber = maxNumber + 1;

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

const deleteFileByServerPath = async (serverPath) => {
  if (!serverPath || typeof serverPath !== "string") return;

  let physicalPath;
  if (serverPath.startsWith("/brochures/")) {
    const fileName = path.basename(serverPath);
    physicalPath = path.join(BROCHURES_DIR_ABS, fileName);
  } else if (serverPath.startsWith("/uploads/")) {
    const relativePath = serverPath.substring("/uploads/".length);
    physicalPath = path.join(UPLOADS_DIR, relativePath);
  } else {
    return;
  }

  try {
    await fsp.unlink(physicalPath);
  } catch (err) {
    if (err.code !== "ENOENT") {
      console.error(`Failed to delete file: ${physicalPath}`, err);
    }
  }
};

const deleteImageFiles = async (imagesToDelete = []) => {
  if (!Array.isArray(imagesToDelete) || imagesToDelete.length === 0) return;
  const deletionPromises = imagesToDelete
    .filter((img) => img?.url && typeof img.url === "string")
    .map((img) => deleteFileByServerPath(img.url));
  await Promise.all(deletionPromises);
};

const tempStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
    cb(null, UPLOADS_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    cb(
      null,
      `temp-${file.fieldname}-${uniqueSuffix}${path.extname(file.originalname)}`
    );
  },
});

const fileFilter = (req, file, cb) => {
  let originalFilenameForValidation = file.originalname;
  try {
    originalFilenameForValidation = Buffer.from(
      file.originalname,
      "latin1"
    ).toString("utf8");
  } catch (e) {
    // Fallback to original name if decoding fails
  }

  const allowedBrochureTypes = /\.(pdf|doc|docx|txt|odt)$/i;
  const allowedImageTypes = /\.(jpg|jpeg|png|gif|webp)$/i;

  if (file.fieldname === "brochureFiles") {
    if (!allowedBrochureTypes.test(originalFilenameForValidation)) {
      req.fileValidationError =
        "Invalid brochure file type. Allowed: PDF, DOC, DOCX, TXT, ODT.";
      return cb(new Error(req.fileValidationError), false);
    }
  } else if (file.fieldname === "images") {
    if (!allowedImageTypes.test(originalFilenameForValidation)) {
      req.fileValidationError =
        "Invalid image file type. Allowed: JPG, JPEG, PNG, GIF, WEBP.";
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
  limits: {
    fileSize: 25 * 1024 * 1024,
  },
});

const handleTemporaryMulterUpload = tempUpload.fields([
  { name: "images", maxCount: 5 },
  { name: "brochureFiles", maxCount: 5 },
]);

const multerErrorHandler = (err, req, res, next) => {
  if (req.fileValidationError) {
    return res.status(400).json({ message: req.fileValidationError });
  }
  if (err instanceof multer.MulterError) {
    const errorMessages = {
      LIMIT_FILE_SIZE: "File size exceeds the 25MB limit.",
      LIMIT_UNEXPECTED_FILE: "Unexpected field or too many files.",
      LIMIT_FIELD_COUNT:
        "Too many files for a field (e.g., >5 images or >5 brochures).",
    };
    const message = errorMessages[err.code] || "File upload error.";
    return res.status(400).json({ message, code: err.code });
  }
  if (err) {
    return next(err);
  }
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
    if (!keptImage?.url || typeof keptImage.url !== "string") continue;

    if (!keptImage.url.startsWith("/uploads/")) {
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

    try {
      await fsp.access(oldAbsolutePath);
      if (oldAbsolutePath !== newAbsolutePath) {
        await fsp.rename(oldAbsolutePath, newAbsolutePath);
      }
      processedKeptImages.push({
        url: `/uploads/${newFilename}`,
        caption: keptImage.caption || "",
      });
      currentIndex++;
    } catch (error) {
      if (error.code !== "ENOENT") {
        console.error(`Error processing kept image ${oldAbsolutePath}:`, error);
      }
    }
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
  if (!tempFiles?.length) {
    return { processedImageObjects: [], nextAvailableIndex: startIndex };
  }
  const sanitizedDocket = docketBase.replace(/[^a-zA-Z0-9_-]/g, "_");
  const newImageObjects = [];
  let currentIndex = startIndex;

  for (const [i, tempFile] of tempFiles.entries()) {
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
      currentIndex++;
    } catch (moveError) {
      console.error(`Failed to move new upload ${tempPath}:`, moveError);
      try {
        await fsp.unlink(tempPath);
      } catch (e) {
        /* ignore */
      }
    }
  }
  return {
    processedImageObjects: newImageObjects,
    nextAvailableIndex: currentIndex,
  };
};

const processNewBrochureFiles = async (tempBrochureFiles = []) => {
  if (!tempBrochureFiles?.length) return [];

  const processedBrochures = [];
  await fsp.mkdir(BROCHURES_DIR_ABS, { recursive: true });

  for (const tempFile of tempBrochureFiles) {
    const tempPath = tempFile.path;
    const decodedOriginalName = Buffer.from(
      tempFile.originalname,
      "latin1"
    ).toString("utf8");
    const safeFileName = `${Date.now()}-${path
      .basename(decodedOriginalName)
      .replace(/[^a-zA-Z0-9._-]/g, "_")}`;
    const finalBrochurePhysicalPath = path.join(
      BROCHURES_DIR_ABS,
      safeFileName
    );

    try {
      await fsp.rename(tempPath, finalBrochurePhysicalPath);
      processedBrochures.push({
        url: `/brochures/${safeFileName}`,
        originalName: decodedOriginalName,
      });
    } catch (renameError) {
      console.error(`Failed to move brochure ${tempPath}:`, renameError);
      try {
        await fsp.unlink(tempPath);
      } catch (e) {
        /* ignore */
      }
    }
  }
  return processedBrochures;
};

router.get(
  "/",
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  asyncHandler(async (req, res) => {
    const { uid, role } = req.user;
    const query = role === "superAdmin" ? {} : { "createdBy.userId": uid };
    const techs = await TechDetail.find(query).sort({ createdAt: -1 });
    res.json(techs);
  })
);

router.get(
  "/deleted",
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  asyncHandler(async (req, res) => {
    const { uid, role } = req.user;
    const query = role === "superAdmin" ? {} : { "createdBy.userId": uid };
    const deletedTechs = await DeletedTech.find(query).sort({ deletedAt: -1 });
    res.json(deletedTechs);
  })
);

router.get(
  "/:id",
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  asyncHandler(async (req, res) => {
    const { uid, role } = req.user;
    const query = { id: req.params.id };
    if (role !== "superAdmin") {
      query["createdBy.userId"] = uid;
    }
    const tech = await TechDetail.findOne(query);
    if (!tech)
      return res
        .status(404)
        .json({ message: "Technology not found or access denied" });
    res.json(tech);
  })
);

router.post(
  "/",
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  checkPermissions({ addTech: true }),
  handleTemporaryMulterUpload,
  multerErrorHandler,
  asyncHandler(async (req, res, next) => {
    const tempImageFiles = req.files?.images || [];
    const tempBrochureFiles = req.files?.brochureFiles || [];

    const cleanupTempFiles = async () => {
      const imageCleanupPromises = tempImageFiles.map((f) =>
        deleteFileByServerPath(`/uploads/${f.filename}`)
      );
      const brochureCleanupPromises = tempBrochureFiles.map((f) =>
        deleteFileByServerPath(`/uploads/${f.filename}`)
      );
      await Promise.all([...imageCleanupPromises, ...brochureCleanupPromises]);
    };

    let techData = parseTechDataFields({ ...req.body });
    const { genre } = techData;

    if (!genre || typeof genre !== "string" || !genre.trim()) {
      await cleanupTempFiles();
      return res.status(400).json({ message: "Genre is required." });
    }

    let newDocket;
    let finalImages = [];
    let finalBrochures = [];

    try {
      newDocket = await generateNewDocket(genre);
      techData.docket = newDocket;
      techData.id = newDocket;
      techData.createdBy = {
        userId: req.user.uid,
        name: req.user.name,
        email: req.user.email,
      };

      const imageProcessingResult = await processNewUploadedFiles(
        tempImageFiles,
        newDocket,
        req.body,
        1
      );
      finalImages = imageProcessingResult.processedImageObjects;
      techData.images = finalImages;

      finalBrochures = await processNewBrochureFiles(tempBrochureFiles);
      techData.brochures = finalBrochures;

      const newTech = new TechDetail(techData);
      const savedTech = await newTech.save();
      res.status(201).json(savedTech);
    } catch (error) {
      await deleteImageFiles(finalImages);
      const brochureUrls = finalBrochures.map((b) => b.url);
      await Promise.all(brochureUrls.map((url) => deleteFileByServerPath(url)));

      if (error.code === 11000) {
        return res.status(409).json({
          message: `A technology with ID/Docket '${newDocket}' already exists.`,
          code: "DUPLICATE_ID",
        });
      }
      next(error);
    }
  })
);

router.post(
  "/:id/restore",
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  checkPermissions({ deleteTech: true }),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { uid, role } = req.user;

    const deletedTech = await DeletedTech.findOne({ id: id }).lean();

    if (!deletedTech) {
      return res
        .status(404)
        .json({ message: "Archived technology not found." });
    }

    if (role !== "superAdmin" && deletedTech.createdBy.userId !== uid) {
      return res
        .status(403)
        .json({
          message: "Forbidden: You do not have permission to restore this.",
        });
    }

    const existingTech = await TechDetail.findOne({
      id: deletedTech.id,
    }).lean();
    if (existingTech) {
      return res.status(409).json({
        message: `A technology with ID ${deletedTech.id} already exists. Cannot restore.`,
        code: "DUPLICATE_ID_ON_RESTORE",
      });
    }

    const techToRestore = { ...deletedTech };
    delete techToRestore._id;
    delete techToRestore.deletedAt;
    techToRestore.editedAt = new Date();

    const newTech = new TechDetail(techToRestore);
    await newTech.save();
    await DeletedTech.deleteOne({ _id: deletedTech._id });

    res.json({
      message: "Technology restored successfully",
      technology: newTech,
    });
  })
);



router.put(
  "/:id",
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  checkPermissions({ editTech: true }),
  handleTemporaryMulterUpload,
  multerErrorHandler,
  asyncHandler(async (req, res, next) => {
    const currentTechId = req.params.id;
    const tempNewImageFiles = req.files?.images || [];
    const tempNewBrochureFiles = req.files?.brochureFiles || [];

    const cleanupTempFiles = async () => {
      const imageCleanupPromises = tempNewImageFiles.map((f) =>
        deleteFileByServerPath(`/uploads/${f.filename}`)
      );
      const brochureCleanupPromises = tempNewBrochureFiles.map((f) =>
        deleteFileByServerPath(`/uploads/${f.filename}`)
      );
      await Promise.all([...imageCleanupPromises, ...brochureCleanupPromises]);
    };

    const currentTech = await TechDetail.findOne({ id: currentTechId });

    if (!currentTech) {
      await cleanupTempFiles();
      return res
        .status(404)
        .json({ message: `Technology ID ${currentTechId} not found` });
    }

    const { uid, role } = req.user;
    if (role !== "superAdmin" && currentTech.createdBy.userId !== uid) {
      await cleanupTempFiles();
      return res
        .status(403)
        .json({
          message:
            "Forbidden: You do not have permission to edit this technology.",
        });
    }

    let incomingData = parseTechDataFields({ ...req.body });
    let finalUpdateData = { ...incomingData };
    delete finalUpdateData.createdAt;
    delete finalUpdateData.editedAt;
    delete finalUpdateData.createdBy;

    let docketForFileNaming = currentTech.docket;
    const newGenre = incomingData.genre?.trim();

    if (
      newGenre &&
      newGenre.toUpperCase() !== currentTech.genre.toUpperCase()
    ) {
      try {
        const newGeneratedDocket = await generateNewDocket(newGenre);
        const existingWithNewId = await TechDetail.findOne({
          id: newGeneratedDocket,
          _id: { $ne: currentTech._id },
        }).lean();

        if (existingWithNewId) {
          await cleanupTempFiles();
          return res.status(409).json({
            message: `Generated ID ${newGeneratedDocket} for the new genre already exists.`,
            code: "DUPLICATE_ID_ON_UPDATE",
          });
        }
        finalUpdateData.docket = newGeneratedDocket;
        finalUpdateData.id = newGeneratedDocket;
        finalUpdateData.genre = newGenre;
        docketForFileNaming = newGeneratedDocket;
      } catch (error) {
        await cleanupTempFiles();
        return next(
          new Error(
            `Failed to generate new docket for genre change: ${error.message}`
          )
        );
      }
    } else {
      delete finalUpdateData.id;
      delete finalUpdateData.docket;
      finalUpdateData.genre = currentTech.genre;
    }

    const imagesToKeepFromRequest = finalUpdateData.existingImages || [];
    const urlsToKeepInRequest = new Set(
      imagesToKeepFromRequest.map((img) => img?.url).filter(Boolean)
    );
    const imagesOnServerToDelete =
      currentTech.images?.filter(
        (img) => img?.url && !urlsToKeepInRequest.has(img.url)
      ) || [];

    let newlyUploadedAndProcessedImages = [];
    let newlyProcessedBrochureObjects = [];

    try {
      const { processedImageObjects: finalKeptImages, nextAvailableIndex } =
        await renameKeptImagesAndAssignNewNames(
          imagesToKeepFromRequest,
          docketForFileNaming,
          1
        );

      const { processedImageObjects: newImages } =
        await processNewUploadedFiles(
          tempNewImageFiles,
          docketForFileNaming,
          req.body,
          nextAvailableIndex
        );
      newlyUploadedAndProcessedImages = newImages;

      finalUpdateData.images = [
        ...finalKeptImages,
        ...newlyUploadedAndProcessedImages,
      ];
      delete finalUpdateData.existingImages;

      const existingBrochuresToKeep = finalUpdateData.existingBrochures || [];
      const keptBrochureUrls = new Set(
        existingBrochuresToKeep.map((b) => b.url)
      );
      const brochuresOnServerToDelete =
        currentTech.brochures?.filter(
          (b) => b?.url && !keptBrochureUrls.has(b.url)
        ) || [];

      newlyProcessedBrochureObjects = await processNewBrochureFiles(
        tempNewBrochureFiles
      );

      finalUpdateData.brochures = [
        ...existingBrochuresToKeep,
        ...newlyProcessedBrochureObjects,
      ];
      delete finalUpdateData.existingBrochures;

      const updatedTech = await TechDetail.findOneAndUpdate(
        { id: currentTechId },
        { $set: finalUpdateData },
        { new: true, runValidators: true }
      );

      if (!updatedTech) {
        throw new Error("Technology not found during final update attempt.");
      }

      await deleteImageFiles(imagesOnServerToDelete);
      await Promise.all(
        brochuresOnServerToDelete.map((b) => deleteFileByServerPath(b.url))
      );

      res.json(updatedTech);
    } catch (error) {
      await deleteImageFiles(newlyUploadedAndProcessedImages);
      await Promise.all(
        newlyProcessedBrochureObjects.map((b) => deleteFileByServerPath(b.url))
      );

      if (error.code === 11000) {
        return res.status(409).json({
          message: `Update failed: Conflict with ID/Docket '${docketForFileNaming}'.`,
          code: "DUPLICATE_ID_ON_UPDATE",
        });
      }
      next(error);
    }
  })
);

router.delete(
  "/:id",
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  checkPermissions({ deleteTech: true }),
  asyncHandler(async (req, res) => {
    const techId = req.params.id;
    const tech = await TechDetail.findOne({ id: techId });

    if (!tech) {
      return res.status(404).json({ message: "Technology not found" });
    }

    const { uid, role } = req.user;
    if (role !== "superAdmin" && tech.createdBy.userId !== uid) {
      return res
        .status(403)
        .json({
          message:
            "Forbidden: You do not have permission to delete this technology.",
        });
    }

    const techData = tech.toObject();
    delete techData._id;

    const deletedTech = new DeletedTech({ ...techData, deletedAt: new Date() });
    await deletedTech.save();
    await TechDetail.deleteOne({ id: techId });

    res.json({
      message:
        "Technology archived. It will be permanently deleted in 30 days.",
      id: techId,
    });
  })
);


router.delete(
  "/deleted/:id",
  verifyFirebaseToken,
  loadFirestoreUserProfile,
  checkPermissions({ deleteTech: true }), // Or a more specific/restrictive permission
  asyncHandler(async (req, res) => {
    const techId = req.params.id;
    const { role } = req.user;

    if (role !== "superAdmin") {
      return res.status(403).json({
        message: "Forbidden: You do not have permission for this action.",
      });
    }

    const techToDelete = await DeletedTech.findOne({ id: techId }).lean();

    if (!techToDelete) {
      return res
        .status(404)
        .json({ message: "Archived technology not found." });
    }

    // --- Start Deletion of Files ---
    try {
      if (techToDelete.images?.length) {
        await deleteImageFiles(techToDelete.images);
      }
      if (techToDelete.brochures?.length) {
        const brochureDeletionPromises = techToDelete.brochures.map((b) =>
          deleteFileByServerPath(b.url)
        );
        await Promise.all(brochureDeletionPromises);
      }
    } catch (fileError) {
      console.error(
        `Error during file deletion for tech ${techId}:`,
        fileError
      );
      return res.status(500).json({
        message: "An error occurred while deleting associated files. The record was not deleted.",
      });
    }
    // --- End Deletion of Files ---


    // --- Delete the Database Record ---
    await DeletedTech.deleteOne({ _id: techToDelete._id });

    res.json({
      message: `Technology ${techId} and all associated files have been permanently deleted.`,
    });
  })
);


const cleanupExpiredTechFiles = async () => {
  console.log(
    `[${new Date().toISOString()}] Running scheduled job: Cleaning up expired technologies...`
  );
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - 30);

  try {
    const expiredTechs = await DeletedTech.find({
      deletedAt: { $lte: cutoffDate },
    }).lean();

    if (expiredTechs.length === 0) {
      console.log("No expired technologies to permanently delete.");
      return;
    }

    console.log(
      `Found ${expiredTechs.length} expired technologies to permanently delete.`
    );
    const allFileDeletionPromises = [];
    const expiredTechIds = [];

    for (const tech of expiredTechs) {
      expiredTechIds.push(tech._id);
      console.log(`- Preparing to delete files for expired tech: ${tech.id}`);
      if (tech.images?.length) {
        allFileDeletionPromises.push(deleteImageFiles(tech.images));
      }
      if (tech.brochures?.length) {
        for (const brochure of tech.brochures) {
          if (brochure.url) {
            allFileDeletionPromises.push(deleteFileByServerPath(brochure.url));
          }
        }
      }
    }

    // 1. Await all file deletions
    await Promise.all(allFileDeletionPromises);
    console.log("Associated files for expired technologies deleted successfully.");

    // 2. Delete the database records
    if (expiredTechIds.length > 0) {
      await DeletedTech.deleteMany({ _id: { $in: expiredTechIds } });
      console.log(
        `${expiredTechIds.length} expired technology records permanently deleted from the database.`
      );
    }

    console.log("Permanent deletion job finished successfully.");
  } catch (error) {
    console.error("Error during scheduled permanent deletion:", error);
  }
};

cron.schedule("0 2 * * *", cleanupExpiredTechFiles, {
  scheduled: true,
  timezone: "Asia/Kolkata",
});

console.log(
  "Scheduled file cleanup for expired technologies is active. Will run daily at 2:00 AM (Asia/Kolkata)."
);

export default router;
