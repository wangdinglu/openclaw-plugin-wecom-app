import { WecomCrypto } from "./crypto.js";
import { logger } from "./logger.js";
import { MessageDeduplicator } from "./utils.js";

/**
 * WeCom Self-built Application Webhook Handler.
 *
 * Key differences from the AI Bot (智能机器人) plugin:
 * - Incoming messages are XML (not JSON)
 * - The encrypted envelope is XML: <xml><Encrypt>...</Encrypt></xml>
 * - Decrypted payload is also XML with standard WeCom fields
 * - Responses are "success" (async reply via API), not stream JSON
 */
export class WecomAppWebhook {
  config;
  crypto;
  deduplicator = new MessageDeduplicator();

  static DUPLICATE = Symbol.for("wecom-app.duplicate");

  constructor(config) {
    this.config = config;
    this.crypto = new WecomCrypto(config.token, config.encodingAesKey, config.corpId);
    logger.debug("WecomAppWebhook initialized (self-built app mode)");
  }

  // =========================================================================
  // URL Verification (GET request) — same mechanism as AI Bot
  // =========================================================================
  handleVerify(query) {
    const signature = query.msg_signature;
    const timestamp = query.timestamp;
    const nonce = query.nonce;
    const echostr = query.echostr;

    if (!signature || !timestamp || !nonce || !echostr) {
      logger.warn("Missing parameters in verify request", { query });
      return null;
    }

    logger.debug("Handling verify request", { timestamp, nonce });

    const calcSignature = this.crypto.getSignature(timestamp, nonce, echostr);
    if (calcSignature !== signature) {
      logger.error("Signature mismatch in verify", {
        expected: signature,
        calculated: calcSignature,
      });
      return null;
    }

    try {
      const result = this.crypto.decrypt(echostr);
      logger.info("URL verification successful");
      return result.message;
    } catch (e) {
      logger.error("Decrypt failed in verify", {
        error: e instanceof Error ? e.message : String(e),
      });
      return null;
    }
  }

  // =========================================================================
  // Message Handling (POST request)
  // Self-built app uses XML format (outer envelope and inner message)
  // =========================================================================
  async handleMessage(query, body) {
    const signature = query.msg_signature;
    const timestamp = query.timestamp;
    const nonce = query.nonce;

    if (!signature || !timestamp || !nonce) {
      logger.warn("Missing parameters in message request", { query });
      return null;
    }

    // 1. Extract encrypted content from XML envelope
    const encrypt = extractXmlField(body, "Encrypt");
    if (!encrypt) {
      logger.error("No Encrypt field in XML body");
      return null;
    }

    // 2. Verify signature
    const calcSignature = this.crypto.getSignature(timestamp, nonce, encrypt);
    if (calcSignature !== signature) {
      logger.error("Signature mismatch in message", {
        expected: signature,
        calculated: calcSignature,
      });
      return null;
    }

    // 3. Decrypt
    let decryptedXml;
    try {
      const result = this.crypto.decrypt(encrypt);
      decryptedXml = result.message;
      logger.debug("Decrypted content", { content: decryptedXml.substring(0, 300) });
    } catch (e) {
      logger.error("Message decrypt failed", {
        error: e instanceof Error ? e.message : String(e),
      });
      return null;
    }

    // 4. Parse XML message fields
    const msgType = extractXmlField(decryptedXml, "MsgType");
    if (!msgType) {
      logger.warn("No MsgType in decrypted message");
      return null;
    }

    if (msgType === "text") {
      const content = extractXmlField(decryptedXml, "Content") || "";
      const msgId = extractXmlField(decryptedXml, "MsgId") || `msg_${Date.now()}`;
      const fromUser = extractXmlField(decryptedXml, "FromUserName") || "";
      const agentId = extractXmlField(decryptedXml, "AgentID") || "";
      const createTime = extractXmlField(decryptedXml, "CreateTime") || "";

      if (this.deduplicator.isDuplicate(msgId)) {
        logger.debug("Duplicate message ignored", { msgId });
        return WecomAppWebhook.DUPLICATE;
      }

      logger.info("Received text message", {
        fromUser,
        agentId,
        content: content.substring(0, 50),
      });

      return {
        message: {
          msgId,
          msgType: "text",
          content,
          fromUser,
          agentId,
          createTime,
          chatType: "single",
          chatId: "",
        },
      };
    } else if (msgType === "image") {
      const picUrl = extractXmlField(decryptedXml, "PicUrl") || "";
      const mediaId = extractXmlField(decryptedXml, "MediaId") || "";
      const msgId = extractXmlField(decryptedXml, "MsgId") || `msg_${Date.now()}`;
      const fromUser = extractXmlField(decryptedXml, "FromUserName") || "";

      if (this.deduplicator.isDuplicate(msgId)) {
        logger.debug("Duplicate image message ignored", { msgId });
        return WecomAppWebhook.DUPLICATE;
      }

      logger.info("Received image message", { fromUser, picUrl: picUrl.substring(0, 80), mediaId });

      return {
        message: {
          msgId,
          msgType: "image",
          picUrl,
          mediaId,
          fromUser,
          chatType: "single",
          chatId: "",
        },
      };
    } else if (msgType === "voice") {
      const recognition = extractXmlField(decryptedXml, "Recognition") || "";
      const msgId = extractXmlField(decryptedXml, "MsgId") || `msg_${Date.now()}`;
      const fromUser = extractXmlField(decryptedXml, "FromUserName") || "";

      if (this.deduplicator.isDuplicate(msgId)) {
        logger.debug("Duplicate voice message ignored", { msgId });
        return WecomAppWebhook.DUPLICATE;
      }

      if (!recognition.trim()) {
        logger.warn("Voice message without recognition", { msgId });
        return null;
      }

      logger.info("Received voice message (transcribed)", {
        fromUser,
        preview: recognition.substring(0, 50),
      });

      return {
        message: {
          msgId,
          msgType: "text",
          content: recognition,
          fromUser,
          chatType: "single",
          chatId: "",
        },
      };
    } else if (msgType === "location") {
      const lat = extractXmlField(decryptedXml, "Location_X") || "";
      const lng = extractXmlField(decryptedXml, "Location_Y") || "";
      const label = extractXmlField(decryptedXml, "Label") || "";
      const msgId = extractXmlField(decryptedXml, "MsgId") || `msg_${Date.now()}`;
      const fromUser = extractXmlField(decryptedXml, "FromUserName") || "";

      if (this.deduplicator.isDuplicate(msgId)) {
        return WecomAppWebhook.DUPLICATE;
      }

      const content = label
        ? `[位置] ${label} (${lat}, ${lng})`
        : `[位置] ${lat}, ${lng}`;

      return {
        message: {
          msgId,
          msgType: "text",
          content,
          fromUser,
          chatType: "single",
          chatId: "",
        },
      };
    } else if (msgType === "link") {
      const title = extractXmlField(decryptedXml, "Title") || "";
      const description = extractXmlField(decryptedXml, "Description") || "";
      const url = extractXmlField(decryptedXml, "Url") || "";
      const msgId = extractXmlField(decryptedXml, "MsgId") || `msg_${Date.now()}`;
      const fromUser = extractXmlField(decryptedXml, "FromUserName") || "";

      if (this.deduplicator.isDuplicate(msgId)) {
        return WecomAppWebhook.DUPLICATE;
      }

      const parts = [];
      if (title) parts.push(`[链接] ${title}`);
      if (description) parts.push(description);
      if (url) parts.push(url);
      const content = parts.join("\n") || "[链接]";

      return {
        message: {
          msgId,
          msgType: "text",
          content,
          fromUser,
          chatType: "single",
          chatId: "",
        },
      };
    } else if (msgType === "event") {
      const event = extractXmlField(decryptedXml, "Event") || "";
      const eventKey = extractXmlField(decryptedXml, "EventKey") || "";
      const fromUser = extractXmlField(decryptedXml, "FromUserName") || "";
      logger.info("Received event", { event, eventKey, fromUser });
      return { event: { type: event, key: eventKey, fromUser } };
    } else {
      logger.warn("Unsupported message type", { msgType });
      return null;
    }
  }
}

/**
 * Extract a field value from XML using regex.
 * Handles both CDATA and plain text values.
 */
function extractXmlField(xml, field) {
  // Try CDATA first: <Field><![CDATA[value]]></Field>
  const cdataRe = new RegExp(`<${field}><!\\[CDATA\\[([\\s\\S]*?)\\]\\]></${field}>`, "i");
  const cdataMatch = xml.match(cdataRe);
  if (cdataMatch) {
    return cdataMatch[1];
  }

  // Fall back to plain text: <Field>value</Field>
  const plainRe = new RegExp(`<${field}>([\\s\\S]*?)</${field}>`, "i");
  const plainMatch = xml.match(plainRe);
  if (plainMatch) {
    return plainMatch[1].trim();
  }

  return null;
}
