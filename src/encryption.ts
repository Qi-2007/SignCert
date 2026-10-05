import { base64 } from './pki';

export interface EncryptedJSON {
  version: 1; algorithm: 'AES-256-GCM'; iv: string; ciphertext: string;
}
export interface Backup extends EncryptedJSON {
  type: 'signcert-backup'; kdf: 'PBKDF2-SHA256'; iterations: 600000; salt: string;
}
const encode = (value: string) => new TextEncoder().encode(value);
export const fromBase64 = (value: string) => Uint8Array.from(atob(value), c => c.charCodeAt(0));
export async function encryptJSON(value: unknown, key: CryptoKey, purpose: string): Promise<EncryptedJSON> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encode(purpose) }, key, encode(JSON.stringify(value)));
  return { version: 1, algorithm: 'AES-256-GCM', iv: base64(iv.buffer), ciphertext: base64(ciphertext) };
}
export async function decryptJSON(value: EncryptedJSON, key: CryptoKey, purpose: string): Promise<unknown> {
  if (value.version !== 1 || value.algorithm !== 'AES-256-GCM' || typeof value.iv !== 'string' || typeof value.ciphertext !== 'string') throw new Error('Unsupported encrypted bundle');
  const iv = fromBase64(value.iv);
  if (iv.length !== 12) throw new Error('Invalid encryption IV');
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: encode(purpose) }, key, fromBase64(value.ciphertext));
  return JSON.parse(new TextDecoder().decode(plaintext));
}
export async function vaultKey(master: string): Promise<CryptoKey> {
  if (!/^[0-9a-fA-F]{64}$/.test(master)) throw new Error('PKI_MASTER_KEY must contain 64 hexadecimal characters');
  const bytes = Uint8Array.from(master.match(/../g)!, b => parseInt(b, 16));
  const material = await crypto.subtle.importKey('raw', bytes, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: encode('signcert-vault-v1'), info: encode('pki-config-encryption') }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function backupKey(password: string, salt: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  if (password.length < 16 || password.length > 1024) throw new Error('Backup password must contain 16–1024 characters');
  const material = await crypto.subtle.importKey('raw', encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', iterations: 600000, salt }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
export async function encryptBackup(value: unknown, password: string): Promise<Backup> {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  return { ...await encryptJSON(value, await backupKey(password, salt), 'signcert-backup-v1'), type: 'signcert-backup', kdf: 'PBKDF2-SHA256', iterations: 600000, salt: base64(salt.buffer) };
}
export async function decryptBackup(value: Backup, password: string): Promise<unknown> {
  if (value.type !== 'signcert-backup' || value.kdf !== 'PBKDF2-SHA256' || value.iterations !== 600000) throw new Error('Unsupported backup format');
  const salt = fromBase64(value.salt);
  if (salt.length !== 32) throw new Error('Invalid backup salt');
  return decryptJSON(value, await backupKey(password, salt), 'signcert-backup-v1');
}
