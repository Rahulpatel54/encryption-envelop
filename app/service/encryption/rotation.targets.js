'use strict';

const { registerTarget } = require('./rotation.registry');

/**
 * Wiring point for rotation targets. This module intentionally registers
 * NOTHING by default, since the real application's models are not available
 * to this standalone module. When integrating, require this file once at
 * app startup (after Sequelize models are loaded) and register each
 * encrypted model/field pair here, e.g.:
 *
 *   const { User } = require('../../../models'); // your real app models
 *
 *   registerTarget('users.ssn', {
 *     model: User,
 *     primaryKey: 'id',            // must be an integer/bigint PK for keyset pagination
 *     encryptedFields: ['ssn_encrypted'],
 *   });
 *
 *   registerTarget('payment_methods.card_number', {
 *     model: PaymentMethod,
 *     primaryKey: 'id',
 *     encryptedFields: ['card_number_encrypted', 'card_cvv_encrypted'],
 *   });
 *
 * `target` on a rotation request must match one of these registered names.
 */

module.exports = { registerTarget };