import crypto from "webcrypto-liner";
export async function pbkdf2(
  password: Buffer,
  salt: Buffer,
  iterations: number
): Promise<Buffer> {
  const importedKey = await crypto.nativeSubtle.importKey(
    "raw",
    password,
    "PBKDF2",
    false,
    ["deriveBits", "deriveKey"]
  );
  const derivedKey = await crypto.nativeSubtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256",
    },
    importedKey,
    { name: "AES-CBC", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  return Buffer.from(
    await crypto.nativeSubtle.exportKey("raw", derivedKey)
  );
}
