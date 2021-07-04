import { pbkdf2 } from "../../encryption/pbkdf-2";

/**
 * Generates the login hash from the vault encryption key and master password
 * @param key
 * @param password
 */
export async function pbkdf2Hash(
  key: Buffer,
  password: string
): Promise<string> {
  const loginHash = await pbkdf2(key, Buffer.from(password, "utf-8"), 1);
  return loginHash.toString("hex");
}
