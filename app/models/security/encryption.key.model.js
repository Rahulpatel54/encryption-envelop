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
        // name of the KEK provider that wrapped this DEK ('env' | 'kms')
        type: Sequelize.STRING(32),
        allowNull: false,
        validate: { isIn: [["env", "kms"]] },
      },
      key_type: {
        // this table stores Data Encryption Keys (DEKs), wrapped by the KEK.
        // The KEK itself is never stored anywhere (env/KMS only).
        type: Sequelize.STRING(16),
        allowNull: false,
        defaultValue: "DEK",
      },
      version: {
        // the DEK's own version (v1, v2, ...) — this is the "key_version"
        // every encrypted credential is tagged with.
        type: Sequelize.INTEGER,
        allowNull: false,
      },
      provider_key_id: {
        // opaque KMS key identifier used to wrap this DEK, when provider = 'kms'
        type: Sequelize.STRING(512),
        allowNull: true,
      },
      wrapped_dek: {
        // base64 ciphertext of the DEK, encrypted under the KEK
        type: Sequelize.TEXT,
        allowNull: true,
      },
      wrap_iv: {
        // base64 IV used when wrapping (env provider only; KMS manages this internally)
        type: Sequelize.TEXT,
        allowNull: true,
      },
      wrap_tag: {
        // base64 auth tag from wrapping (env provider only)
        type: Sequelize.TEXT,
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