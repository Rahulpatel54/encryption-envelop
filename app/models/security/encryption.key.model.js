module.exports = (sequelize, Sequelize) => {
  const EncryptionKey = sequelize.define(
    "encryption_keys",
    {
      id: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4,
        primaryKey: true,
      },
      provider: {
        type: Sequelize.STRING(32),
        allowNull: false,
        validate: { isIn: [["env", "kms"]] },
      },
      key_type: {
        type: Sequelize.STRING(16),
        allowNull: false,
        defaultValue: "KEK",
      },
      version: {
        type: Sequelize.INTEGER,
        allowNull: false,
      },
      provider_key_id: {
        type: Sequelize.STRING(512),
        allowNull: true,
      },
      status: {
        type: Sequelize.STRING(16),
        allowNull: false,
        defaultValue: "PENDING",
        validate: { isIn: [["PENDING", "ACTIVE", "RETIRED"]] },
      },
      activated_at: { type: Sequelize.DATE, allowNull: true },
      retired_at: { type: Sequelize.DATE, allowNull: true },
      metadata: {
        type: Sequelize.JSONB,
        allowNull: false,
        defaultValue: {},
      },
    },
    {
      underscored: true,
      timestamps: true,
      createdAt: "created_at",
      updatedAt: false,
      indexes: [
        { unique: true, fields: ["key_type", "version"], name: "uq_encryption_keys_type_version" },
        { fields: ["status"] },
      ],
    }
  )

  return EncryptionKey
}