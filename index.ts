/**
 * PORTED FROM https://stackoverflow.com/a/53573115
 */

import crypto from "crypto";

export class MerrymakeCrypto {
  constructor(
    private readonly ALGORITHM: {
      BLOCK_CIPHER: crypto.CipherGCMTypes;
      AUTH_TAG_BYTE_LEN: number;
      IV_BYTE_LEN: number;
      KEY_BYTE_LEN: number;
      SALT_BYTE_LEN: number;
    } = {
      /**
       * GCM is an authenticated encryption mode that
       * not only provides confidentiality but also
       * provides integrity in a secured way
       * */
      BLOCK_CIPHER: "aes-256-gcm",

      /**
       * 128 bit auth tag is recommended for GCM
       */
      AUTH_TAG_BYTE_LEN: 16,

      /**
       * NIST recommends 96 bits or 12 bytes IV for GCM
       * to promote interoperability, efficiency, and
       * simplicity of design
       */
      IV_BYTE_LEN: 12,

      /**
       * Note: 256 (in algorithm name) is key size.
       * Block size for AES is always 128
       */
      KEY_BYTE_LEN: 32,

      /**
       * To prevent rainbow table attacks
       * */
      SALT_BYTE_LEN: 16,
    }
  ) {}

  getIV() {
    return crypto.randomBytes(this.ALGORITHM.IV_BYTE_LEN);
  }
  getRandomKey() {
    return crypto.randomBytes(this.ALGORITHM.KEY_BYTE_LEN);
  }

  /**
   * To prevent rainbow table attacks
   * */
  getSalt() {
    return crypto.randomBytes(this.ALGORITHM.SALT_BYTE_LEN);
  }

  /**
   *
   * @param {Buffer} password - The password to be used for generating key
   *
   * To be used when key needs to be generated based on password.
   * The caller of this function has the responsibility to clear
   * the Buffer after the key generation to prevent the password
   * from lingering in the memory
   */
  getKeyFromPassword(password: Buffer, salt: Buffer) {
    return crypto.scryptSync(password, salt, this.ALGORITHM.KEY_BYTE_LEN);
  }

  /**
   *
   * @param {Buffer} messageText - The clear text message to be encrypted
   * @param {Buffer} key - The key to be used for encryption
   *
   * The caller of this function has the responsibility to clear
   * the Buffer after the encryption to prevent the message text
   * and the key from lingering in the memory
   */
  encrypt(messageText: Buffer, key: Buffer) {
    const iv = this.getIV();
    const cipher = crypto.createCipheriv(this.ALGORITHM.BLOCK_CIPHER, key, iv, {
      authTagLength: this.ALGORITHM.AUTH_TAG_BYTE_LEN,
    });
    let encryptedMessage = cipher.update(messageText);
    encryptedMessage = Buffer.concat([encryptedMessage, cipher.final()]);
    return Buffer.concat([iv, encryptedMessage, cipher.getAuthTag()]);
  }

  /**
   *
   * @param {Buffer} cipherText - Cipher text
   * @param {Buffer} key - The key to be used for decryption
   *
   * The caller of this function has the responsibility to clear
   * the Buffer after the decryption to prevent the message text
   * and the key from lingering in the memory
   */
  decrypt(cipherText: Buffer, key: Buffer) {
    const authTag = cipherText.subarray(-this.ALGORITHM.AUTH_TAG_BYTE_LEN);
    const iv = cipherText.subarray(0, this.ALGORITHM.IV_BYTE_LEN);
    const encryptedMessage = cipherText.subarray(
      this.ALGORITHM.IV_BYTE_LEN,
      -this.ALGORITHM.AUTH_TAG_BYTE_LEN
    );
    const decipher = crypto.createDecipheriv(
      this.ALGORITHM.BLOCK_CIPHER,
      key,
      iv,
      {
        authTagLength: this.ALGORITHM.AUTH_TAG_BYTE_LEN,
      }
    );
    decipher.setAuthTag(authTag);
    let messageText = decipher.update(encryptedMessage);
    messageText = Buffer.concat([messageText, decipher.final()]);
    return messageText;
  }
}
