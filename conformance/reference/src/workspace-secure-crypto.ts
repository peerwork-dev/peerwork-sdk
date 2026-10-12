/** Client-side cryptographic building blocks for signed workspace artifacts.
 * This module never exports private key material or contacts a server.
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const IDENTITY_DOMAIN = encoder.encode('peerwork.identity.v1\0');
const ARTIFACT_DOMAIN = 'peerwork.signed-artifact.v1\0';
const ENCRYPTION_KEY_DOMAIN = encoder.encode('peerwork.encryption-key.v1\0');
const CONTENT_DOMAIN = 'peerwork.content-object.v1';
const KEYBOX_SUITE = 'DHKEM-P256-HKDF-SHA256/HKDF-SHA256/A256GCM' as const;
const hpkeSuite = new HPKE.CipherSuite<CryptoKey>(HPKE.KEM_DHKEM_P256_HKDF_SHA256, HPKE.KDF_HKDF_SHA256, HPKE.AEAD_AES_256_GCM);
const MAX_CIPHERTEXT_BYTES = 16 * 1024 * 1024;
const CHUNK_BYTES = 6144; // 8192 base64url characters, without padding.

export type SigningIdentity = {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  actorId: string;
  keyId: string;
};

export type SignedArtifact<T> = {
  v: 1;
  domain: string;
  signer: { actor_id: string; key_id: string };
  body: T;
  signature: string;
};

export type EncryptionIdentity = {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  keyId: string;
  publicKeySpki: string;
  publicKeyJwk: SecureEncryptionKey;
};

export type CertifiedEncryptionKey = SecureKeyCertificate;
export type SealedContent = SecureCiphertext;
export type JsonValue = SecureJson;

function fail(code: string): never { throw new Error(code); }

function bytes(value: ArrayBuffer | ArrayBufferView): Uint8Array {
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
}

function b64url(value: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < value.length; i += 0x8000) {
    binary += String.fromCharCode(...value.subarray(i, Math.min(i + 0x8000, value.length)));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function unb64url(value: string, code = 'CRYPTO_FORMAT_INVALID'): Uint8Array {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) fail(code);
  let decoded: Uint8Array;
  try {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
    const binary = atob(padded);
    decoded = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) decoded[i] = binary.charCodeAt(i);
  } catch { return fail(code); }
  if (b64url(decoded) !== value) fail(code);
  return decoded;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
}

function canonical(value: unknown, seen = new Set<object>()): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) return fail('CRYPTO_UNSAFE_NUMBER');
    return String(value);
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) return fail('CRYPTO_CYCLIC_VALUE');
    seen.add(value);
    const result = `[${value.map(item => canonical(item, seen)).join(',')}]`;
    seen.delete(value);
    return result;
  }
  if (value && typeof value === 'object') {
    const object = value as Record<string, unknown>;
    if (Object.getPrototypeOf(object) !== Object.prototype && Object.getPrototypeOf(object) !== null) return fail('CRYPTO_NON_JSON_VALUE');
    if (seen.has(object)) return fail('CRYPTO_CYCLIC_VALUE');
    seen.add(object);
    const keys = Object.keys(object).sort();
    if (keys.some(key => ['__proto__', 'prototype', 'constructor'].includes(key))) return fail('CRYPTO_NON_JSON_VALUE');
    let result = '{', separator = '';
    for (const key of keys) {
      result += separator + JSON.stringify(key) + ':' + canonical(object[key], seen);
      separator = ',';
    }
    result += '}';
    seen.delete(object);
    return result;
  }
  return fail('CRYPTO_NON_JSON_VALUE');
}

export async function sha256(input: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', input as Uint8Array<ArrayBuffer>));
}

export async function actorId(publicKeyBase64url: string): Promise<string> {
  const raw = unb64url(publicKeyBase64url);
  if (raw.length !== 32) fail('CRYPTO_IDENTITY_INVALID');
  return b64url(await sha256(concat(IDENTITY_DOMAIN, raw)));
}

export async function signCanonical(domain: string, payload: JsonValue, privateKey: CryptoKey): Promise<string> {
  if (!domain || domain.includes('\0') || domain.length > 128 || privateKey.algorithm.name !== 'Ed25519' || !privateKey.usages.includes('sign')) fail('CRYPTO_SIGNING_KEY_INVALID');
  return b64url(new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, encoder.encode(`${domain}\0${canonical(payload)}`))));
}

export async function verifyCanonical(domain: string, payload: JsonValue, signature: string, publicKeyBase64url: string): Promise<boolean> {
  try {
    if (!domain || domain.includes('\0') || domain.length > 128) return false;
    const raw = unb64url(publicKeyBase64url), sig = unb64url(signature);
    if (raw.length !== 32 || sig.length !== 64) return false;
    const key = await crypto.subtle.importKey('raw', raw as Uint8Array<ArrayBuffer>, { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify('Ed25519', key, sig as Uint8Array<ArrayBuffer>, encoder.encode(`${domain}\0${canonical(payload)}`));
  } catch { return false; }
}

export async function generateSigningKeypair(): Promise<SigningIdentity> { return createSigningIdentity(); }
export async function importSigningPublicKey(publicKeyBase64url: string): Promise<CryptoKey> {
  const raw = unb64url(publicKeyBase64url);
  if (raw.length !== 32) fail('CRYPTO_IDENTITY_INVALID');
  return await crypto.subtle.importKey('raw', raw as Uint8Array<ArrayBuffer>, { name: 'Ed25519' }, false, ['verify']);
}

export async function createSigningIdentity(): Promise<SigningIdentity> {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) as CryptoKeyPair;
  const rawPublic = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  return {
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    actorId: b64url(await sha256(concat(IDENTITY_DOMAIN, rawPublic))),
    keyId: b64url(rawPublic),
  };
}

export async function signArtifact<T>(identity: SigningIdentity, domain: string, body: T): Promise<SignedArtifact<T>> {
  if (!domain || domain.includes('\0') || domain.length > 128) fail('CRYPTO_DOMAIN_INVALID');
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', identity.publicKey));
  if (b64url(raw) !== identity.keyId || b64url(await sha256(concat(IDENTITY_DOMAIN, raw))) !== identity.actorId) fail('CRYPTO_IDENTITY_MISMATCH');
  const unsigned = { v: 1 as const, domain, signer: { actor_id: identity.actorId, key_id: identity.keyId }, body };
  return { ...unsigned, signature: await signCanonical(`${ARTIFACT_DOMAIN.slice(0, -1)}:${domain}`, unsigned as unknown as SecureJson, identity.privateKey) };
}

export async function verifyArtifact<T>(artifact: SignedArtifact<T>, expected?: { domain?: string; actorId?: string }): Promise<boolean> {
  try {
    if (!artifact || artifact.v !== 1 || typeof artifact.domain !== 'string' || !artifact.domain || artifact.domain.includes('\0') ||
        !artifact.signer || typeof artifact.signer.actor_id !== 'string' || typeof artifact.signer.key_id !== 'string' ||
        (expected?.domain !== undefined && artifact.domain !== expected.domain) ||
        (expected?.actorId !== undefined && artifact.signer.actor_id !== expected.actorId)) return false;
    const raw = unb64url(artifact.signer.key_id);
    if (raw.length !== 32 || b64url(await sha256(concat(IDENTITY_DOMAIN, raw))) !== artifact.signer.actor_id) return false;
    const signature = unb64url(artifact.signature);
    if (signature.length !== 64) return false;
    const { signature: _signature, ...unsigned } = artifact;
    return await verifyCanonical(`${ARTIFACT_DOMAIN.slice(0, -1)}:${artifact.domain}`, unsigned as unknown as SecureJson, artifact.signature, artifact.signer.key_id);
  } catch { return false; }
}

export async function createEncryptionIdentity(exportablePrivateKey = false): Promise<EncryptionIdentity> {
  // Public points remain exportable for distribution; the private key is
  // non-extractable by default and can be persisted as a CryptoKey by browsers.
  const pair = await hpkeSuite.GenerateKeyPair(exportablePrivateKey) as unknown as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey) as JsonWebKey;
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) fail('CRYPTO_ENCRYPTION_KEY_INVALID');
  const publicKeyJwk: SecureEncryptionKey = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, keyId: b64url(await sha256(encoder.encode(canonical(publicKeyJwk)))), publicKeySpki: b64url(spki), publicKeyJwk };
}

export async function generateRecipientKeypair(exportablePrivateKey = false): Promise<EncryptionIdentity> { return createEncryptionIdentity(exportablePrivateKey); }
export async function importRecipientPublicKey(jwk: SecureEncryptionKey): Promise<CryptoKey> {
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') fail('CRYPTO_ENCRYPTION_KEY_INVALID');
  // Public keys are intentionally exportable; HPKE needs the uncompressed point
  // when it encapsulates. This key contains no secret material.
  return await crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
}
export async function exportRecipientPublicKey(publicKey: CryptoKey): Promise<SecureEncryptionKey> {
  const jwk = await crypto.subtle.exportKey('jwk', publicKey) as JsonWebKey;
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) fail('CRYPTO_ENCRYPTION_KEY_INVALID');
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
}
export async function importRecipientPrivateKey(serialized: Uint8Array): Promise<CryptoKey> {
  return await hpkeSuite.DeserializePrivateKey(serialized) as unknown as CryptoKey;
}
export async function exportRecipientPrivateKey(privateKey: CryptoKey): Promise<Uint8Array> {
  if (!privateKey.extractable) fail('CRYPTO_PRIVATE_KEY_NONEXTRACTABLE');
  return await hpkeSuite.SerializePrivateKey(privateKey);
}

export async function certifyEncryptionKey(identity: SigningIdentity, encryption: EncryptionIdentity, createdAt: number, expiresAt: number | null = null): Promise<CertifiedEncryptionKey> {
  if (!Number.isSafeInteger(createdAt) || createdAt < 0 || (expiresAt !== null && (!Number.isSafeInteger(expiresAt) || expiresAt <= createdAt))) fail('CRYPTO_TIME_INVALID');
  const publicKey = encryption.publicKeyJwk;
  const fingerprint = b64url(await sha256(encoder.encode(canonical(publicKey))));
  if (fingerprint !== encryption.keyId) fail('CRYPTO_ENCRYPTION_KEY_MISMATCH');
  const payload = { v: 1 as const, actor_id: identity.actorId, signing_key: identity.keyId, encryption_key: publicKey, encryption_key_id: encryption.keyId, issued_at: createdAt, expires_at: expiresAt ?? createdAt + 366 * 86_400_000 };
  return { payload, signature: await signCanonical('peerwork.secure.key-certificate.v1', payload, identity.privateKey) };
}

export async function verifyEncryptionKeyCertificate(certificate: CertifiedEncryptionKey, expected?: { actorId?: string; signingKeyId?: string; now?: number }): Promise<CryptoKey | null> {
  try {
    const p = certificate?.payload;
    if (!p || p.v !== 1 || !Number.isSafeInteger(p.issued_at) || p.issued_at < 0 || !Number.isSafeInteger(p.expires_at) || p.expires_at <= p.issued_at ||
        (expected?.actorId !== undefined && p.actor_id !== expected.actorId) || (expected?.signingKeyId !== undefined && p.signing_key !== expected.signingKeyId) ||
        (expected?.now !== undefined && (p.issued_at > expected.now || expected.now >= p.expires_at))) return null;
    if (await actorId(p.signing_key) !== p.actor_id || b64url(await sha256(encoder.encode(canonical(p.encryption_key)))) !== p.encryption_key_id) return null;
    if (!await verifyCanonical('peerwork.secure.key-certificate.v1', p as unknown as SecureJson, certificate.signature, p.signing_key)) return null;
    return await importRecipientPublicKey(p.encryption_key);
  } catch { return null; }
}

export async function sealContentBytes(key: CryptoKey, plaintext: Uint8Array, context: unknown): Promise<SealedContent> {
  if (!(plaintext instanceof Uint8Array) || plaintext.byteLength > MAX_CIPHERTEXT_BYTES) fail('CRYPTO_CONTENT_TOO_LARGE');
  if (key.type !== 'secret' || !key.usages.includes('encrypt') || key.algorithm.name !== 'AES-GCM' || (key.algorithm as AesKeyAlgorithm).length !== 256) fail('CRYPTO_CONTENT_KEY_INVALID');
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const aad = encoder.encode(canonical({ domain: CONTENT_DOMAIN, context }));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce as Uint8Array<ArrayBuffer>, additionalData: aad as Uint8Array<ArrayBuffer>, tagLength: 128 }, key, plaintext as Uint8Array<ArrayBuffer>));
  const chunks: string[] = [];
  for (let offset = 0; offset < ciphertext.length; offset += CHUNK_BYTES) chunks.push(b64url(ciphertext.subarray(offset, offset + CHUNK_BYTES)));
  if (chunks.length === 0) chunks.push('');
  return { v: 1, alg: 'A256GCM', nonce: b64url(nonce), chunks };
}

export async function openContentBytes(key: CryptoKey, sealed: SealedContent, context: unknown): Promise<Uint8Array> {
  if (!sealed || sealed.v !== 1 || sealed.alg !== 'A256GCM' || !Array.isArray(sealed.chunks) || sealed.chunks.length === 0 || sealed.chunks.length > Math.ceil((MAX_CIPHERTEXT_BYTES + 16) / CHUNK_BYTES)) fail('CRYPTO_CIPHERTEXT_INVALID');
  if (key.type !== 'secret' || !key.usages.includes('decrypt') || key.algorithm.name !== 'AES-GCM' || (key.algorithm as AesKeyAlgorithm).length !== 256) fail('CRYPTO_CONTENT_KEY_INVALID');
  const nonce = unb64url(sealed.nonce);
  if (nonce.length !== 12) fail('CRYPTO_CIPHERTEXT_INVALID');
  const pieces = sealed.chunks.map(chunk => {
    if (typeof chunk !== 'string' || chunk.length > 8192) fail('CRYPTO_CIPHERTEXT_INVALID');
    return unb64url(chunk);
  });
  const ciphertext = concat(...pieces);
  if (ciphertext.length < 16 || ciphertext.length > MAX_CIPHERTEXT_BYTES + 16) fail('CRYPTO_CIPHERTEXT_INVALID');
  const aad = encoder.encode(canonical({ domain: CONTENT_DOMAIN, context }));
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce as Uint8Array<ArrayBuffer>, additionalData: aad as Uint8Array<ArrayBuffer>, tagLength: 128 }, key, ciphertext as Uint8Array<ArrayBuffer>));
  } catch { return fail('CRYPTO_AUTHENTICATION_FAILED'); }
}

export async function sealContent(key: CryptoKey, plaintext: SecureJson | Uint8Array, context: SecureJson): Promise<SecureCiphertext> {
  return await sealContentBytes(key, plaintext instanceof Uint8Array ? plaintext : encodeCanonicalJson(plaintext), context);
}
export async function openContent(key: CryptoKey, sealed: SecureCiphertext, context: SecureJson): Promise<SecureJson> {
  return decodeJson(await openContentBytes(key, sealed, context)) as SecureJson;
}
export const unsealContent = openContentBytes;

export const generateContentKey = createContentKey;

export async function hpkeSeal(recipientPublicJwk: SecureEncryptionKey, plaintext: SecureJson, context: SecureJson): Promise<SecureKeyBox> {
  const key = await importRecipientPublicKey(recipientPublicJwk);
  const aad = encoder.encode(canonical({ domain: 'peerwork.secure.key-box.v1', context }));
  const result = await hpkeSuite.Seal(key, encodeCanonicalJson(plaintext), { aad, info: encoder.encode('peerwork.secure.key-box.v1') });
  const chunks: string[] = [];
  for (let offset = 0; offset < result.ciphertext.length; offset += CHUNK_BYTES) chunks.push(b64url(result.ciphertext.subarray(offset, offset + CHUNK_BYTES)));
  if (!chunks.length) chunks.push('');
  return { v: 1, suite: KEYBOX_SUITE, enc: b64url(result.encapsulatedSecret), chunks };
}

export async function hpkeOpen(recipientPrivateKey: CryptoKey | CryptoKeyPair, envelope: SecureKeyBox, context: SecureJson): Promise<SecureJson> {
  if (!envelope || envelope.v !== 1 || envelope.suite !== KEYBOX_SUITE || !Array.isArray(envelope.chunks) || envelope.chunks.length === 0 || envelope.chunks.length > 128) fail('CRYPTO_KEY_BOX_INVALID');
  const enc = unb64url(envelope.enc);
  if (enc.length !== hpkeSuite.KEM.Nenc) fail('CRYPTO_KEY_BOX_INVALID');
  const ciphertext = concat(...envelope.chunks.map(chunk => {
    if (typeof chunk !== 'string' || chunk.length > 8192) fail('CRYPTO_KEY_BOX_INVALID');
    return unb64url(chunk);
  }));
  if (ciphertext.length < hpkeSuite.AEAD.Nt || ciphertext.length > MAX_CIPHERTEXT_BYTES) fail('CRYPTO_KEY_BOX_INVALID');
  const aad = encoder.encode(canonical({ domain: 'peerwork.secure.key-box.v1', context }));
  try {
    const plaintext = await hpkeSuite.Open(recipientPrivateKey, enc as Uint8Array<ArrayBuffer>, ciphertext as Uint8Array<ArrayBuffer>, { aad, info: encoder.encode('peerwork.secure.key-box.v1') });
    return decodeJson(plaintext) as SecureJson;
  } catch { return fail('CRYPTO_AUTHENTICATION_FAILED'); }
}

export async function createContentKey(): Promise<CryptoKey> {
  return await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/** Canonical JSON text, with the same validation used for signed bytes. */
export function canonicalJsonText(value: unknown): string { return canonical(value); }
export function encodeCanonicalJson(value: unknown): Uint8Array { return encoder.encode(canonical(value)); }
export function decodeJson(bytesValue: Uint8Array): unknown { return JSON.parse(decoder.decode(bytesValue)); }
export function encodeBase64Url(value: Uint8Array): string { return b64url(value); }
export function decodeBase64Url(value: string): Uint8Array { return unb64url(value); }
import * as HPKE from 'hpke';
import type { SecureCiphertext, SecureEncryptionKey, SecureJson, SecureKeyBox, SecureKeyCertificate } from './workspace-secure-contract.js';
