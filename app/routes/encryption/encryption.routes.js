// app/routes/encryption/encryption.routes.js
const express = require("express")
const router = express.Router()
const db = require("../../models")
const { buildRotationController } = require("../../controllers/encryption/encryption.rotation.controller")
const casbinMiddleware = require("../../middlewares/casbinMiddleware")
const { RotationService } = require("../../service/encryption/rotation.service")

const rotationService = new RotationService({ RotationModel: db.EncryptionRotation })
const controller = buildRotationController({ rotationService })

router.post("/rotations", casbinMiddleware("encryption/rotate"), controller.createRotation)
router.get("/rotations/:id", casbinMiddleware("encryption/rotate"), controller.getRotation)
router.post("/rotations/:id/cancel", casbinMiddleware("encryption/rotate"), controller.cancelRotation)

module.exports = router