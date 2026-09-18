'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('encryption_keys', {
      id: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4,
        primaryKey: true,
      },
      provider: { type: Sequelize.STRING(32), allowNull: false },
      key_type: { type: Sequelize.STRING(16), allowNull: false, defaultValue: 'KEK' },
      version: { type: Sequelize.INTEGER, allowNull: false },
      provider_key_id: { type: Sequelize.STRING(512), allowNull: true },
      status: { type: Sequelize.STRING(16), allowNull: false, defaultValue: 'PENDING' },
      activated_at: { type: Sequelize.DATE, allowNull: true },
      retired_at: { type: Sequelize.DATE, allowNull: true },
      metadata: { type: Sequelize.JSONB, allowNull: false, defaultValue: {} },
      created_at: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.NOW },
    });

    await queryInterface.addConstraint('encryption_keys', {
      fields: ['key_type', 'version'],
      type: 'unique',
      name: 'uq_encryption_keys_type_version',
    });

    await queryInterface.addIndex('encryption_keys', ['status'], {
      name: 'idx_encryption_keys_status',
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('encryption_keys');
  },
};