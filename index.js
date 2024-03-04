"use strict";
/**
 * PORTED FROM https://stackoverflow.com/a/53573115
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MerrymakeCrypto = void 0;
const crypto_1 = __importDefault(require("crypto"));
class MerrymakeCrypto {
    constructor(ALGORITHM = {
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
    }) {
        this.ALGORITHM = ALGORITHM;
    }
    getIV() {
        return crypto_1.default.randomBytes(this.ALGORITHM.IV_BYTE_LEN);
    }
    getRandomKey() {
        return crypto_1.default.randomBytes(this.ALGORITHM.KEY_BYTE_LEN);
    }
    /**
     * To prevent rainbow table attacks
     * */
    getSalt() {
        return crypto_1.default.randomBytes(this.ALGORITHM.SALT_BYTE_LEN);
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
    getKeyFromPassword(password, salt) {
        return crypto_1.default.scryptSync(password, salt, this.ALGORITHM.KEY_BYTE_LEN);
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
    encrypt(messageText, key) {
        const iv = this.getIV();
        const cipher = crypto_1.default.createCipheriv(this.ALGORITHM.BLOCK_CIPHER, key, iv, {
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
    decrypt(cipherText, key) {
        const authTag = cipherText.subarray(-this.ALGORITHM.AUTH_TAG_BYTE_LEN);
        const iv = cipherText.subarray(0, this.ALGORITHM.IV_BYTE_LEN);
        const encryptedMessage = cipherText.subarray(this.ALGORITHM.IV_BYTE_LEN, -this.ALGORITHM.AUTH_TAG_BYTE_LEN);
        const decipher = crypto_1.default.createDecipheriv(this.ALGORITHM.BLOCK_CIPHER, key, iv, {
            authTagLength: this.ALGORITHM.AUTH_TAG_BYTE_LEN,
        });
        decipher.setAuthTag(authTag);
        let messageText = decipher.update(encryptedMessage);
        messageText = Buffer.concat([messageText, decipher.final()]);
        return messageText;
    }
}
exports.MerrymakeCrypto = MerrymakeCrypto;
