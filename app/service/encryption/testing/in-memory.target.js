'use strict';

const { Op } = require('sequelize');

/**
 * Minimal in-memory stand-in for a Sequelize model, implementing only the
 * surface area EncryptionRotationWorker actually touches:
 *
 *   model.count()
 *   model.findAll({ where: { [pk]: { [Op.gt]: lastId } }, order, limit })
 *   record.get(field)
 *   record.update(updates, { transaction })
 *   record.constructor.name        (used to build AAD for DEK_ROTATION)
 *
 * Registering this as a rotation target lets you push a REAL KEK_REWRAP or
 * DEK_ROTATION job through the production RotationService -> BullMQ ->
 * EncryptionRotationWorker pipeline (advisory lock, checkpointing, progress
 * events, the works) against disposable data — no schema changes, no new
 * dependencies, nothing written to a real table.
 *
 * `sequelize.transaction()` and the advisory lock in the worker still use
 * the app's real Postgres connection (via encryption_rotations); only the
 * rotated "model" itself is fake.
 */
class InMemoryTestRecord {
  constructor(store, id, data) {
    this._store = store;
    this.id = id;
    this._data = { ...data };
  }

  get(field) {
    return field === 'id' ? this.id : this._data[field];
  }

  // eslint-disable-next-line no-unused-vars
  async update(updates, opts) {
    Object.assign(this._data, updates);
    this._store.set(this.id, this._data);
    return this;
  }
}
// Named separately so record.constructor.name (used in DEK_ROTATION's AAD) is stable.
Object.defineProperty(InMemoryTestRecord, 'name', { value: 'InMemoryTestRecord' });

class InMemoryTestModel {
  constructor() {
    this._store = new Map(); // id -> plain data object
    this._nextId = 1;
  }

  reset() {
    this._store.clear();
    this._nextId = 1;
  }

  /** Test-only helper (not part of the Sequelize surface). */
  insert(data) {
    const id = this._nextId++;
    this._store.set(id, { ...data });
    return id;
  }

  async count() {
    return this._store.size;
  }

  async findAll({ where, limit } = {}) {
    let ids = Array.from(this._store.keys());
    const gt = where && where.id && where.id[Op.gt];
    if (gt !== undefined && gt !== null) {
      ids = ids.filter((id) => id > gt);
    }
    ids.sort((a, b) => a - b);
    if (limit) ids = ids.slice(0, limit);
    return ids.map((id) => new InMemoryTestRecord(this._store, id, this._store.get(id)));
  }

  /** Test-only helper: plain snapshot for listing/inspection endpoints. */
  async findAllPlain() {
    return Array.from(this._store.entries())
      .sort(([a], [b]) => a - b)
      .map(([id, data]) => ({ id, ...data }));
  }
}

const testModel = new InMemoryTestModel();

/**
 * @param {{ getTarget: Function, registerTarget: Function }} registry rotation.registry module
 * @param {string} [name]
 * @returns {string} the target name, registered idempotently
 */
function registerInMemoryTestTarget(registry, name = 'test.in_memory_echo') {
  if (!registry.getTarget(name)) {
    registry.registerTarget(name, {
      model: testModel,
      primaryKey: 'id',
      encryptedFields: ['value_encrypted'],
    });
  }
  return name;
}

module.exports = { testModel, InMemoryTestModel, InMemoryTestRecord, registerInMemoryTestTarget };