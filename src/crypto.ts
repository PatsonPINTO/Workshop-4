import { webcrypto } from "crypto";

// #############
// ### Utils ###
// #############

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ################
// ### RSA keys ###
// ################

type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};

export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  const keyPair = await webcrypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  };
}

export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  const exported = await webcrypto.subtle.exportKey("spki", key);
  return arrayBufferToBase64(exported);
}

export async function exportPrvKey(key: webcrypto.CryptoKey | null): Promise<string | null> {
  if (!key) return null;
  const exported = await webcrypto.subtle.exportKey("pkcs8", key);
  return arrayBufferToBase64(exported);
}

export async function importPubKey(strKey: string): Promise<webcrypto.CryptoKey> {
  const binaryDer = base64ToArrayBuffer(strKey);
  return await webcrypto.subtle.importKey(
    "spki",
    binaryDer,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  );
}

export async function importPrvKey(strKey: string): Promise<webcrypto.CryptoKey> {
  const binaryDer = base64ToArrayBuffer(strKey);
  return await webcrypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt"]
  );
}

export async function rsaEncrypt(b64Data: string, strPublicKey: string): Promise<string> {
  const publicKey = await importPubKey(strPublicKey);
  const dataBuffer = base64ToArrayBuffer(b64Data);
  const encryptedBuffer = await webcrypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    dataBuffer
  );
  return arrayBufferToBase64(encryptedBuffer);
}

// rsaDecrypt renvoie désormais le résultat en Base64
export async function rsaDecrypt(data: string, privateKey: webcrypto.CryptoKey): Promise<string> {
  const encryptedBuffer = base64ToArrayBuffer(data);
  const decryptedBuffer = await webcrypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    encryptedBuffer
  );
  return Buffer.from(new Uint8Array(decryptedBuffer)).toString("base64");
}

// ######################
// ### Symmetric keys ###
// ######################

export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  return await webcrypto.subtle.generateKey(
    { name: "AES-CBC", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  const exported = await webcrypto.subtle.exportKey("raw", key);
  return arrayBufferToBase64(exported);
}

export async function importSymKey(strKey: string): Promise<webcrypto.CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(strKey);
  return await webcrypto.subtle.importKey(
    "raw",
    keyBuffer,
    { name: "AES-CBC" },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function symEncrypt(key: webcrypto.CryptoKey, data: string): Promise<string> {
  const iv = new Uint8Array(16);
  webcrypto.getRandomValues(iv);
  const encodedData = new TextEncoder().encode(data);
  const encryptedBuffer = await webcrypto.subtle.encrypt(
    { name: "AES-CBC", iv },
    key,
    encodedData
  );
  const combined = new Uint8Array(iv.length + encryptedBuffer.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encryptedBuffer), iv.length);
  return Buffer.from(combined).toString("base64");
}

export async function symDecrypt(strKey: string, encryptedData: string): Promise<string> {
  const key = await importSymKey(strKey);
  const combined = Uint8Array.from(Buffer.from(encryptedData, "base64"));
  const iv = combined.slice(0, 16);
  const ciphertext = combined.slice(16);
  const decryptedBuffer = await webcrypto.subtle.decrypt(
    { name: "AES-CBC", iv },
    key,
    ciphertext
  );
  return new TextDecoder().decode(new Uint8Array(decryptedBuffer));
}
