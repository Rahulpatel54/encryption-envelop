const express = require("express")
const router = express.Router()
const { buildRotationController } = require("../../controllers/encryption/encryption.rotation.controller")
const casbinMiddleware = require("../../middlewares/casbinMiddleware")
const { RotationService } = require("../../service/encryption/rotation.service")

function buildEncryptionRoutes({ RotationModel, io }) {
  const rotationService = new RotationService({ RotationModel, io })
  const controller = buildRotationController({ rotationService })

  router.post("/rotations", casbinMiddleware("encryption/rotate"), controller.createRotation)
  router.get("/rotations/:id", casbinMiddleware("encryption/rotate"), controller.getRotation)
  router.post("/rotations/:id/cancel", casbinMiddleware("encryption/rotate"), controller.cancelRotation)

  return router
}

module.exports = buildEncryptionRoutes

// app/routes/index.js — add
// const db = require("../models")
// const buildEncryptionRoutes = require("./encryption/encryption.routes")
// router.use("/api/encryption", buildEncryptionRoutes({ RotationModel: db.EncryptionRotation }))