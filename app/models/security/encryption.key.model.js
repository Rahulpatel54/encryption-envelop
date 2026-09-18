'use strict';

const { Model, DataTypes } = require('sequelize');

/**
 * Metadata-only record of a KEK version's lifecycle. Never stores key material.
 */
module.exports = (sequelize) => {
  class EncryptionKey extends Model {}

  EncryptionKey.init(
    {
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
      },
      provider: {
        type: DataTypes.STRING(32),
        allowNull: false,
        validate: { isIn: [['env', 'kms']] },
      },
      key_type: {
        type: DataTypes.STRING(16),
        allowNull: false,
        defaultValue: 'KEK',
      },
      version: {
        type: DataTypes.INTEGER,
        allowNull: false,
      },
      provider_key_id: {
        type: DataTypes.STRING(512),
        allowNull: true,
      },
      status: {
        type: DataTypes.STRING(16),
        allowNull: false,
        defaultValue: 'PENDING',
        validate: { isIn: [['PENDING', 'ACTIVE', 'RETIRED']] },
      },
      activated_at: { type: DataTypes.DATE, allowNull: true },
      retired_at: { type: DataTypes.DATE, allowNull: true },
      metadata: {
        type: DataTypes.JSONB,
        allowNull: false,
        defaultValue: {},
      },
    },
    {
      sequelize,
      modelName: 'EncryptionKey',
      tableName: 'encryption_keys',
      underscored: true,
      timestamps: true,
      createdAt: 'created_at',
      updatedAt: false,
      indexes: [
        { unique: true, fields: ['key_type', 'version'], name: 'uq_encryption_keys_type_version' },
        { fields: ['status'] },
      ],
    }
  );

  return EncryptionKey;
};