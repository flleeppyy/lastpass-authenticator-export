import { pbkdf2 } from "../../encryption/pbkdf-2";

/**
 * Generates both the vault encryption key
 * @param username
 * @param password
 * @param iterations
 */
export function pbkdf2Key(
  username: string,
  password: string,
  iterations: number
): Promise<Buffer> {
  return pbkdf2(
    Buffer.from(password, "utf-8"),
    Buffer.from(username, "utf-8"),
    iterations
  );
}
