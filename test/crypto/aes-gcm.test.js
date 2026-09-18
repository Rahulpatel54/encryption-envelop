'use strict';

const aesGcm = require('../../app/service/encryption/crypto/aes-gcm');

describe('aes-gcm', () => {
  test('encrypts and decrypts round-trip', () => {
    const key = aesGcm.generateKey();
    const plaintext = Buffer.from('sensitive data', 'utf8');
    const { iv, ciphertext, tag } = aesGcm.encrypt(key, plaintext);
    const result = aesGcm.decrypt(key, { iv, ciphertext, tag });
    expect(result.equals(plaintext)).toBe(true);
  });

  test('each encryption uses a unique IV', () => {
    const key = aesGcm.generateKey();
    const plaintext = Buffer.from('same input', 'utf8');
    const a = aesGcm.encrypt(key, plaintext);
    const b = aesGcm.encrypt(key, plaintext);
    expect(a.iv.equals(b.iv)).toBe(false);
    expect(a.ciphertext.equals(b.ciphertext)).toBe(false);
  });

  test('rejects tampered ciphertext', () => {
    const key = aesGcm.generateKey();
    const { iv, ciphertext, tag } = aesGcm.encrypt(key, Buffer.from('hello'));
    ciphertext[0] ^= 0xff;
    expect(() => aesGcm.decrypt(key, { iv, ciphertext, tag })).toThrow();
  });

  test('rejects tampered auth tag', () => {
    const key = aesGcm.generateKey();
    const { iv, ciphertext, tag } = aesGcm.encrypt(key, Buffer.from('hello'));
    tag[0] ^= 0xff;
    expect(() => aesGcm.decrypt(key, { iv, ciphertext, tag })).toThrow();
  });

  test('rejects decryption with the wrong key', () => {
    const key = aesGcm.generateKey();
    const wrongKey = aesGcm.generateKey();
    const { iv, ciphertext, tag } = aesGcm.encrypt(key, Buffer.from('hello'));
    expect(() => aesGcm.decrypt(wrongKey, { iv, ciphertext, tag })).toThrow();
  });

  test('AAD mismatch is rejected', () => {
    const key = aesGcm.generateKey();
    const { iv, ciphertext, tag } = aesGcm.encrypt(key, Buffer.from('hello'), Buffer.from('record-1'));
    expect(() => aesGcm.decrypt(key, { iv, ciphertext, tag }, Buffer.from('record-2'))).toThrow();
  });
});