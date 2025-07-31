const express = require("express");
const multer = require("multer");
const {
  uploadMediaToCloudinary,
  deleteMediaFromCloudinary,
} = require("../../helpers/cloudinary");
const authenticateAdmin = require("../../middleware/admin-auth-middleware");

const router = express.Router();

const upload = multer({ dest: "uploads/" });

// Allowed MIME types for images and videos
const allowedMimeTypes = [
  "image/jpeg",
  "image/png",
  "image/gif",
  "image/webp",
  "video/mp4",
  "video/mpeg",
  "video/webm",
  "video/ogg"
];

router.post("/upload", authenticateAdmin, upload.single("file"), async (req, res) => {
  try {
    // Validate file type
    if (!req.file || !allowedMimeTypes.includes(req.file.mimetype)) {
      return res.status(400).json({
        success: false,
        message: "Invalid file type. Only images (JPEG, PNG, GIF, WebP) and videos (MP4, MPEG, WebM, OGG) are allowed."
      });
    }

    const result = await uploadMediaToCloudinary(req.file.path);
    res.status(200).json({
      success: true,
      data: result,
    });
  } catch (e) {
    console.log(e);
    res.status(500).json({ 
      success: false, 
      message: "Error uploading file" 
    });
  }
});

router.delete("/delete/:id", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({
        success: false,
        message: "Asset Id is required",
      });
    }

    await deleteMediaFromCloudinary(id);

    res.status(200).json({
      success: true,
      message: "Asset deleted successfully from Cloudinary",
    });
  } catch (e) {
    console.log(e);
    res.status(500).json({ 
      success: false, 
      message: "Error deleting file" 
    });
  }
});

router.post("/bulk-upload", authenticateAdmin, upload.array("files", 10), async (req, res) => {
  try {
    // Validate all files are either images or videos
    const invalidFiles = req.files.filter(file => !allowedMimeTypes.includes(file.mimetype));
    if (invalidFiles.length > 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid file types detected. Only images (JPEG, PNG, GIF, WebP) and videos (MP4, MPEG, WebM, OGG) are allowed."
      });
    }

    const uploadPromises = req.files.map((fileItem) =>
      uploadMediaToCloudinary(fileItem.path)
    );

    const results = await Promise.all(uploadPromises);

    res.status(200).json({
      success: true,
      data: results,
    });
  } catch (e) {
    console.log(e);
    res.status(500).json({ 
      success: false, 
      message: "Error in bulk uploading files" 
    });
  }
});

module.exports = router;