'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('encryption_rotations', {
      id: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4,
        primaryKey: true,
      },
      type: { type: Sequelize.STRING(16), allowNull: false },
      status: { type: Sequelize.STRING(16), allowNull: false, defaultValue: 'QUEUED' },
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
      created_at: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.NOW },
      updated_at: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.NOW },
    });

    await queryInterface.addIndex('encryption_rotations', ['status'], {
      name: 'idx_encryption_rotations_status',
    });
    await queryInterface.addIndex('encryption_rotations', ['target'], {
      name: 'idx_encryption_rotations_target',
    });
    await queryInterface.addIndex(
      'encryption_rotations',
      ['type', 'target', 'status'],
      { name: 'idx_encryption_rotations_type_target_status' }
    );
  },

  async down(queryInterface) {
    await queryInterface.dropTable('encryption_rotations');
  },
};