'use strict';

/**
 * Registry of rotation targets: encrypted Sequelize models/fields that the
 * rotation worker is allowed to touch. Nothing is auto-discovered — a
 * target must be explicitly registered by application code (see
 * rotation.targets.js for the wiring point).
 */

const targets = new Map();

/**
 * @param {string} name unique target key, referenced by rotations (e.g. "users.ssn")
 * @param {object} config
 * @param {import('sequelize').ModelStatic} config.model
 * @param {string} config.primaryKey primary key column name, must be integer/bigint for keyset pagination
 * @param {string[]} config.encryptedFields column names holding serialized envelopes
 */
function registerTarget(name, config) {
  if (!name || typeof name !== 'string') {
    throw new Error('rotation.registry: target name must be a non-empty string');
  }
  if (!config || !config.model || !config.primaryKey || !Array.isArray(config.encryptedFields) || config.encryptedFields.length === 0) {
    throw new Error(`rotation.registry: invalid config for target "${name}"`);
  }
  if (targets.has(name)) {
    throw new Error(`rotation.registry: target "${name}" is already registered`);
  }
  targets.set(name, {
    model: config.model,
    primaryKey: config.primaryKey,
    encryptedFields: config.encryptedFields.slice(),
  });
}

/** @returns {object|undefined} */
function getTarget(name) {
  return targets.get(name);
}

function listTargets() {
  return Array.from(targets.keys());
}

/** For tests only. */
function _clearRegistry() {
  targets.clear();
}

module.exports = { registerTarget, getTarget, listTargets, _clearRegistry };