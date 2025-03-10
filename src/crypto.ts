import { webcrypto } from "crypto";

// Convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
    return Buffer.from(buffer).toString("base64");
}

// Convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
    const buff = Buffer.from(base64, "base64");
    return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// Generate RSA key pair
export async function generateRsaKeyPair(): Promise<{ publicKey: webcrypto.CryptoKey; privateKey: webcrypto.CryptoKey }> {
    const keyPair = await webcrypto.subtle.generateKey(
        { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
        true,
        ["encrypt", "decrypt"]
    );
    return keyPair;
}

// Export public key to Base64
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
    const spki = await webcrypto.subtle.exportKey("spki", key);
    return arrayBufferToBase64(spki);
}

// Export private key to Base64
export async function exportPrvKey(key: webcrypto.CryptoKey | null): Promise<string | null> {
    if (!key) return null;
    const pkcs8 = await webcrypto.subtle.exportKey("pkcs8", key);
    return arrayBufferToBase64(pkcs8);
}

// Import public key from Base64
export async function importPubKey(strKey: string): Promise<webcrypto.CryptoKey> {
    const binaryDer = base64ToArrayBuffer(strKey);
    return await webcrypto.subtle.importKey("spki", binaryDer, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
}

// Import private key from Base64
export async function importPrvKey(strKey: string): Promise<webcrypto.CryptoKey> {
    const binaryDer = base64ToArrayBuffer(strKey);
    return await webcrypto.subtle.importKey("pkcs8", binaryDer, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);
}

// Encrypt data with RSA public key
export async function rsaEncrypt(b64Data: string, strPublicKey: string): Promise<string> {
    const publicKey = await importPubKey(strPublicKey);
    const dataBuffer = base64ToArrayBuffer(b64Data);
    const encryptedBuffer = await webcrypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, dataBuffer);
    return arrayBufferToBase64(encryptedBuffer);
}

// Decrypt data with RSA private key
export async function rsaDecrypt(data: string, privateKey: webcrypto.CryptoKey): Promise<string> {
    const encryptedBuffer = base64ToArrayBuffer(data);
    const decryptedBuffer = await webcrypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, encryptedBuffer);
    return arrayBufferToBase64(decryptedBuffer);
}

// Generate random symmetric key
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
    return await webcrypto.subtle.generateKey({ name: "AES-CBC", length: 256 }, true, ["encrypt", "decrypt"]);
}

// Export symmetric key to Base64
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
    const raw = await webcrypto.subtle.exportKey("raw", key);
    return arrayBufferToBase64(raw);
}

// Import symmetric key from Base64
export async function importSymKey(strKey: string): Promise<webcrypto.CryptoKey> {
    const raw = base64ToArrayBuffer(strKey);
    return await webcrypto.subtle.importKey("raw", raw, { name: "AES-CBC" }, true, ["encrypt", "decrypt"]);
}

// Encrypt data with symmetric key
export async function symEncrypt(key: webcrypto.CryptoKey, data: string): Promise<string> {
    const iv = webcrypto.getRandomValues(new Uint8Array(16));
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(data);
    const encryptedBuffer = await webcrypto.subtle.encrypt({ name: "AES-CBC", iv }, key, encodedData);
    const ivBase64 = arrayBufferToBase64(iv.buffer);
    const cipherBase64 = arrayBufferToBase64(encryptedBuffer);
    return ivBase64 + ":" + cipherBase64;
}

// Decrypt data with symmetric key
export async function symDecrypt(strKey: string, encryptedData: string): Promise<string> {
    const key = await importSymKey(strKey);
    const [ivBase64, cipherBase64] = encryptedData.split(":");
    const ivArray = new Uint8Array(base64ToArrayBuffer(ivBase64));
    const cipherArrayBuffer = base64ToArrayBuffer(cipherBase64);
    const decryptedBuffer = await webcrypto.subtle.decrypt({ name: "AES-CBC", iv: ivArray }, key, cipherArrayBuffer);
    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
}
