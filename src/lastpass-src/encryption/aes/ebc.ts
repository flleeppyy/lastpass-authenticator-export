import aesjs from "aes-js";

export function encrypt(value: string, key: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    try {
      const aesEcb = new aesjs.ModeOfOperation.ecb(key);
      const bytes = Buffer.from(value, "utf8");
      const encrypted = aesEcb.encrypt(aesjs.padding.pkcs7.pad(bytes));
      resolve(Buffer.from(encrypted));
    } catch (e) {
      reject(e);
    }
  });
}

export function decrypt(encrypted: Buffer, key: Buffer): Promise<string> {
  return new Promise((resolve, reject) => {
    try {
      const aesEcb = new aesjs.ModeOfOperation.ecb(key);
      const decrypted = aesjs.padding.pkcs7.strip(aesEcb.decrypt(encrypted));
      resolve(Buffer.from(decrypted).toString("utf8"));
    } catch (e) {
      reject(e);
    }
  });
}
