module.exports = (sequelize, Sequelize) => {
  const EncryptionRotation = sequelize.define(
    "encryption_rotations",
    {
      id: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4,
        primaryKey: true,
      },
      type: {
        // this architecture only rotates DEKs (KEK is env/KMS-only and never rotates here)
        type: Sequelize.STRING(16),
        allowNull: false,
        defaultValue: "DEK_ROTATION",
        validate: { isIn: [["DEK_ROTATION"]] },
      },
      status: {
        type: Sequelize.STRING(16),
        allowNull: false,
        defaultValue: "QUEUED",
        validate: { isIn: [["QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"]] },
      },
      provider: { type: Sequelize.STRING(32), allowNull: false },
      target: { type: Sequelize.STRING(128), allowNull: false },
      from_version: { type: Sequelize.INTEGER, allowNull: true },
      to_version: { type: Sequelize.INTEGER, allowNull: true },
      total_records: { type: Sequelize.BIGINT, allowNull: true },
      processed_records: { type: Sequelize.BIGINT, allowNull: false, defaultValue: 0 },
      failed_records: { type: Sequelize.BIGINT, allowNull: false, defaultValue: 0 },
      last_processed_id: { type: Sequelize.BIGINT, allowNull: true },
      started_at: { type: Sequelize.DATE, allowNull: true },
      completed_at: { type: Sequelize.DATE, allowNull: true },
      cancelled_at: { type: Sequelize.DATE, allowNull: true },
      error: { type: Sequelize.TEXT, allowNull: true },
      created_by: { type: Sequelize.STRING(128), allowNull: true },
    },
    {
      underscored: true,
      timestamps: true,
      createdAt: "created_at",
      updatedAt: "updated_at",
      indexes: [
        { fields: ["status"] },
        { fields: ["target"] },
        { fields: ["type", "target", "status"], name: "idx_encryption_rotations_type_target_status" },
      ],
    }
  )

  return EncryptionRotation
}