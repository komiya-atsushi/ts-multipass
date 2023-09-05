import {createCipheriv, createHash, randomBytes, createHmac} from 'crypto';

export interface CustomerDataEssentials {
  email: string;
}

interface CustomerDataWithTimestamp extends CustomerDataEssentials {
  created_at: string;
}

export class Multipass<
  T extends CustomerDataEssentials = CustomerDataEssentials,
> {
  private readonly encryptionKey: Buffer;
  private readonly signatureKey: Buffer;

  constructor(multipassSecret: string) {
    const hash = createHash('sha256');
    const keyMaterial = hash.update(multipassSecret).digest();
    this.encryptionKey = keyMaterial.subarray(0, 16);
    this.signatureKey = keyMaterial.subarray(16, 32);
  }

  generateToken(data: T, now?: Date): string {
    const withTimestamp: CustomerDataWithTimestamp = {
      created_at: (now ?? new Date()).toISOString(),
      ...data,
    };
    const cipherText = this.encrypt(JSON.stringify(withTimestamp));

    return Buffer.concat([cipherText, this.sign(cipherText)]).toString(
      'base64url'
    );
  }

  private encrypt(plainText: string): Buffer {
    const iv = randomBytes(16);
    const cipher = createCipheriv('aes-128-cbc', this.encryptionKey, iv);

    return Buffer.concat([
      iv,
      cipher.update(plainText, 'utf-8'),
      cipher.final(),
    ]);
  }

  private sign(data: Buffer): Buffer {
    return createHmac('sha256', this.signatureKey).update(data).digest();
  }
}
