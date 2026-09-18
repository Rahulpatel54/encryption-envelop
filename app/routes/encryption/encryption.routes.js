// app/routes/encryption/encryption.routes.js
const express = require("express")
const router = express.Router()
const db = require("../../models")
const { buildRotationController } = require("../../controllers/encryption/encryption.rotation.controller")
const casbinMiddleware = require("../../middlewares/casbinMiddleware")
const { RotationService } = require("../../service/encryption/rotation.service")
const { KeyService } = require("../../service/encryption/key.service")

const keyService = new KeyService({ EncryptionKeyModel: db.EncryptionKey })
const rotationService = new RotationService({ RotationModel: db.EncryptionRotation, keyService })
const controller = buildRotationController({ rotationService })

router.post("/rotations", controller.createRotation)
router.get("/rotations/:id", controller.getRotation)
router.post("/rotations/:id/cancel", controller.cancelRotation)

module.exports = router