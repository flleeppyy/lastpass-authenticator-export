import Crypto from "webcrypto-liner";

const subtleCrypto = Crypto.nativeSubtle;
export async function encrypt(value: Buffer, key: Buffer): Promise<{ iv: Buffer; value: Buffer }> {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const importedKey = await subtleCrypto.importKey(
    "raw",
    key,
    "AES-CBC",
    false,
    ["encrypt", "decrypt"]
  );
  const encrypted = await subtleCrypto.encrypt(
    {
      name: "AES-CBC",
      iv: iv,
    },
    importedKey,
    value
  );
  return {
    iv: Buffer.from(iv),
    value: Buffer.from(encrypted),
  };
}

export async function decrypt(
  encrypted: {
    iv: Buffer;
    value: Buffer;
  },
  key: Buffer
): Promise<Buffer> {
  const importedKey = await crypto.subtle.importKey(
    "raw",
    key,
    "AES-CBC",
    false,
    ["encrypt", "decrypt"]
  );
  const decrypted = await subtleCrypto.decrypt(
    {
      name: "AES-CBC",
      iv: encrypted.iv,
    },
    importedKey,
    encrypted.value
  );
  return Buffer.from(decrypted);
}
