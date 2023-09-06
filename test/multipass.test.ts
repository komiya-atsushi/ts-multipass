import {CustomerDataEssentials, Multipass} from '../src';
import {createDecipheriv, createHash, createHmac} from 'crypto';

describe('Multipass#generateToken()', () => {
  const secretKey = 'secret key';

  function splitIntoBuffers(token: string): {
    iv: Buffer;
    cipherText: Buffer;
    signature: Buffer;
  } {
    const buffer = Buffer.from(token, 'base64url');
    const ivAndCipherTextLength = buffer.length - 32;
    return {
      iv: buffer.subarray(0, 16),
      cipherText: buffer.subarray(16, ivAndCipherTextLength),
      signature: buffer.subarray(ivAndCipherTextLength),
    };
  }

  function generateKeys(secret: string): {
    encryptionKey: Buffer;
    signatureKey: Buffer;
  } {
    const secretKeyDigest = createHash('sha256').update(secret).digest();
    return {
      encryptionKey: secretKeyDigest.subarray(0, 16),
      signatureKey: secretKeyDigest.subarray(16, 32),
    };
  }

  function decrypt(
    cipherText: Buffer,
    encryptionKey: Buffer,
    iv: Buffer
  ): string {
    const decipher = createDecipheriv('aes-128-cbc', encryptionKey, iv);
    return Buffer.concat([
      decipher.update(cipherText),
      decipher.final(),
    ]).toString('utf-8');
  }

  test('with CustomerDataEssentials', () => {
    const multipass = new Multipass(secretKey);
    const begin = Date.now();
    const token = multipass.generateToken({email: 'foo@example.com'});
    const end = Date.now();

    const {iv, cipherText, signature} = splitIntoBuffers(token);
    const {encryptionKey, signatureKey} = generateKeys(secretKey);
    const plainText = decrypt(cipherText, encryptionKey, iv);

    expect(signature).toStrictEqual(
      createHmac('sha256', signatureKey)
        .update(Buffer.concat([iv, cipherText]))
        .digest()
    );

    const obj = JSON.parse(plainText);

    expect(obj).toStrictEqual({
      email: 'foo@example.com',
      created_at: expect.stringMatching(
        /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z/
      ),
    });

    const createdAt = Date.parse(obj['created_at']);
    expect(createdAt).toBeGreaterThanOrEqual(begin);
    expect(createdAt).toBeLessThanOrEqual(end);
  });

  test('with now', () => {
    const multipass = new Multipass(secretKey);
    const now = '2023-09-01T00:00:00.000Z';
    const token = multipass.generateToken(
      {email: 'foo@example.com'},
      new Date(now)
    );

    const {iv, cipherText, signature} = splitIntoBuffers(token);
    const {encryptionKey, signatureKey} = generateKeys(secretKey);
    const plainText = decrypt(cipherText, encryptionKey, iv);

    expect(signature).toStrictEqual(
      createHmac('sha256', signatureKey)
        .update(Buffer.concat([iv, cipherText]))
        .digest()
    );

    const obj = JSON.parse(plainText);

    expect(obj).toStrictEqual({
      email: 'foo@example.com',
      created_at: '2023-09-01T00:00:00.000Z',
    });
  });

  test('with CustomCustomerData', () => {
    interface CustomCustomerData extends CustomerDataEssentials {
      return_to: string;
    }

    const multipass = new Multipass<CustomCustomerData>(secretKey);
    const token = multipass.generateToken({
      email: 'foo@example.com',
      return_to: 'https://www.example.com/',
    });

    const {iv, cipherText, signature} = splitIntoBuffers(token);
    const {encryptionKey, signatureKey} = generateKeys(secretKey);
    const plainText = decrypt(cipherText, encryptionKey, iv);

    expect(signature).toStrictEqual(
      createHmac('sha256', signatureKey)
        .update(Buffer.concat([iv, cipherText]))
        .digest()
    );

    const obj = JSON.parse(plainText);

    expect(obj).toStrictEqual({
      email: 'foo@example.com',
      return_to: 'https://www.example.com/',
      created_at: expect.stringMatching(
        /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z/
      ),
    });
  });
});
