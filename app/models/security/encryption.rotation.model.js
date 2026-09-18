'use strict';

const { Model, DataTypes } = require('sequelize');

module.exports = (sequelize) => {
  class EncryptionRotation extends Model {}

  EncryptionRotation.init(
    {
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
      },
      type: {
        type: DataTypes.STRING(16),
        allowNull: false,
        validate: { isIn: [['KEK_REWRAP', 'DEK_ROTATION']] },
      },
      status: {
        type: DataTypes.STRING(16),
        allowNull: false,
        defaultValue: 'QUEUED',
        validate: { isIn: [['QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED']] },
      },
      provider: { type: DataTypes.STRING(32), allowNull: false },
      target: { type: DataTypes.STRING(128), allowNull: false },
      from_version: { type: DataTypes.INTEGER, allowNull: true },
      to_version: { type: DataTypes.INTEGER, allowNull: true },
      total_records: { type: DataTypes.BIGINT, allowNull: true },
      processed_records: { type: DataTypes.BIGINT, allowNull: false, defaultValue: 0 },
      failed_records: { type: DataTypes.BIGINT, allowNull: false, defaultValue: 0 },
      last_processed_id: { type: DataTypes.BIGINT, allowNull: true },
      started_at: { type: DataTypes.DATE, allowNull: true },
      completed_at: { type: DataTypes.DATE, allowNull: true },
      cancelled_at: { type: DataTypes.DATE, allowNull: true },
      error: { type: DataTypes.TEXT, allowNull: true },
      created_by: { type: DataTypes.STRING(128), allowNull: true },
    },
    {
      sequelize,
      modelName: 'EncryptionRotation',
      tableName: 'encryption_rotations',
      underscored: true,
      timestamps: true,
      createdAt: 'created_at',
      updatedAt: 'updated_at',
      indexes: [
        { fields: ['status'] },
        { fields: ['target'] },
        { fields: ['type', 'target', 'status'], name: 'idx_encryption_rotations_type_target_status' },
      ],
    }
  );

  return EncryptionRotation;
};