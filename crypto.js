import { createCipheriv, createDecipheriv, randomBytes, createHash } from "node:crypto";
import { logger } from "./logger.js";
import { CONSTANTS } from "./utils.js";

/**
 * Enterprise WeChat Self-built Application Crypto Implementation.
 * Unlike the AI Bot mode, self-built apps include corpId in the encrypted payload
 * and must validate it during decryption.
 */
export class WecomCrypto {
  token;
  encodingAesKey;
  corpId;
  aesKey;
  iv;

  constructor(token, encodingAesKey, corpId) {
    if (!encodingAesKey || encodingAesKey.length !== CONSTANTS.AES_KEY_LENGTH) {
      throw new Error(`EncodingAESKey invalid: length must be ${CONSTANTS.AES_KEY_LENGTH}`);
    }
    if (!token) {
      throw new Error("Token is required");
    }
    if (!corpId) {
      throw new Error("CorpId is required for self-built application mode");
    }
    this.token = token;
    this.encodingAesKey = encodingAesKey;
    this.corpId = corpId;
    this.aesKey = Buffer.from(encodingAesKey + "=", "base64");
    this.iv = this.aesKey.subarray(0, 16);
    logger.debug("WecomCrypto initialized (self-built app mode)");
  }

  getSignature(timestamp, nonce, encrypt) {
    const shasum = createHash("sha1");
    const sorted = [this.token, timestamp, nonce, encrypt]
      .map((value) => String(value))
      .toSorted();
    shasum.update(sorted.join(""));
    return shasum.digest("hex");
  }

  decrypt(text) {
    let decipher;
    try {
      decipher = createDecipheriv("aes-256-cbc", this.aesKey, this.iv);
      decipher.setAutoPadding(false);
    } catch (e) {
      throw new Error(`Decrypt init failed: ${String(e)}`, { cause: e });
    }

    let deciphered = Buffer.concat([decipher.update(text, "base64"), decipher.final()]);
    deciphered = this.decodePkcs7(deciphered);

    // Format: 16 random bytes | 4 bytes msg_len | msg_content | corpid
    const content = deciphered.subarray(16);
    const lenList = content.subarray(0, 4);
    const xmlLen = lenList.readUInt32BE(0);
    const xmlContent = content.subarray(4, 4 + xmlLen).toString("utf-8");
    const corpIdFromMsg = content.subarray(4 + xmlLen).toString("utf-8");

    if (corpIdFromMsg !== this.corpId) {
      throw new Error(
        `CorpId mismatch: expected "${this.corpId}", got "${corpIdFromMsg}"`,
      );
    }

    return { message: xmlContent };
  }

  encrypt(text) {
    const random16 = randomBytes(16);
    const msgBuffer = Buffer.from(text);
    const corpIdBuffer = Buffer.from(this.corpId);
    const lenBuffer = Buffer.alloc(4);
    lenBuffer.writeUInt32BE(msgBuffer.length, 0);

    const rawMsg = Buffer.concat([random16, lenBuffer, msgBuffer, corpIdBuffer]);
    const encoded = this.encodePkcs7(rawMsg);

    const cipher = createCipheriv("aes-256-cbc", this.aesKey, this.iv);
    cipher.setAutoPadding(false);
    const ciphered = Buffer.concat([cipher.update(encoded), cipher.final()]);
    return ciphered.toString("base64");
  }

  encodePkcs7(buff) {
    const blockSize = CONSTANTS.AES_BLOCK_SIZE;
    const amountToPad = blockSize - (buff.length % blockSize);
    const pad = Buffer.alloc(amountToPad, amountToPad);
    return Buffer.concat([buff, pad]);
  }

  decodePkcs7(buff) {
    const pad = buff[buff.length - 1];
    if (pad < 1 || pad > CONSTANTS.AES_BLOCK_SIZE) {
      throw new Error(`Invalid PKCS7 padding: ${pad}`);
    }
    for (let i = buff.length - pad; i < buff.length; i++) {
      if (buff[i] !== pad) {
        throw new Error("Invalid PKCS7 padding: inconsistent padding bytes");
      }
    }
    return buff.subarray(0, buff.length - pad);
  }
}
