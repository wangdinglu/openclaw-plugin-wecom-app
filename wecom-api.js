import { logger } from "./logger.js";
import { CONSTANTS } from "./utils.js";

const WECOM_API_BASE = "https://qyapi.weixin.qq.com/cgi-bin";

/**
 * WeCom API client for self-built applications.
 * Handles access_token lifecycle and message sending via the standard API.
 */
export class WecomApiClient {
  corpId;
  corpSecret;
  agentId;

  _accessToken = null;
  _tokenExpiresAt = 0;
  _tokenRefreshPromise = null;

  constructor({ corpId, corpSecret, agentId }) {
    if (!corpId) throw new Error("corpId is required");
    if (!corpSecret) throw new Error("corpSecret is required");
    if (!agentId && agentId !== 0) throw new Error("agentId is required");
    this.corpId = corpId;
    this.corpSecret = corpSecret;
    this.agentId = agentId;
    logger.info("WecomApiClient initialized", { corpId, agentId });
  }

  /**
   * Get a valid access_token, refreshing if expired.
   * Deduplicates concurrent refresh requests.
   */
  async getAccessToken() {
    if (this._accessToken && Date.now() < this._tokenExpiresAt) {
      return this._accessToken;
    }

    if (this._tokenRefreshPromise) {
      return this._tokenRefreshPromise;
    }

    this._tokenRefreshPromise = this._refreshToken();
    try {
      const token = await this._tokenRefreshPromise;
      return token;
    } finally {
      this._tokenRefreshPromise = null;
    }
  }

  async _refreshToken() {
    const url = `${WECOM_API_BASE}/gettoken?corpid=${encodeURIComponent(this.corpId)}&corpsecret=${encodeURIComponent(this.corpSecret)}`;
    logger.debug("Refreshing access_token");

    const resp = await fetch(url);
    if (!resp.ok) {
      throw new Error(`Failed to get access_token: HTTP ${resp.status}`);
    }
    const data = await resp.json();
    if (data.errcode !== 0) {
      throw new Error(`WeCom API error: ${data.errcode} ${data.errmsg}`);
    }

    this._accessToken = data.access_token;
    // Expire 5 minutes early to avoid edge-case failures.
    this._tokenExpiresAt = Date.now() + (data.expires_in - 300) * 1000;
    logger.info("access_token refreshed", {
      expiresIn: data.expires_in,
      effectiveExpiresIn: data.expires_in - 300,
    });
    return this._accessToken;
  }

  /**
   * Send a text message to a user via the standard message API.
   * Automatically chunks messages that exceed the 2048-char limit.
   */
  async sendText(toUser, text) {
    const chunks = chunkText(text, CONSTANTS.WECOM_TEXT_LIMIT);
    const results = [];
    for (const chunk of chunks) {
      const result = await this._sendMessage({
        touser: toUser,
        msgtype: "text",
        agentid: this.agentId,
        text: { content: chunk },
      });
      results.push(result);
    }
    return results;
  }

  /**
   * Send a markdown message (renders in WeCom app, plain text in WeChat plugin).
   */
  async sendMarkdown(toUser, markdown) {
    const chunks = chunkText(markdown, CONSTANTS.WECOM_TEXT_LIMIT);
    const results = [];
    for (const chunk of chunks) {
      const result = await this._sendMessage({
        touser: toUser,
        msgtype: "markdown",
        agentid: this.agentId,
        markdown: { content: chunk },
      });
      results.push(result);
    }
    return results;
  }

  async _sendMessage(body) {
    const token = await this.getAccessToken();
    const url = `${WECOM_API_BASE}/message/send?access_token=${encodeURIComponent(token)}`;
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      throw new Error(`WeCom send message failed: HTTP ${resp.status}`);
    }
    const data = await resp.json();
    if (data.errcode !== 0) {
      // Token expired — retry once with a fresh token.
      if (data.errcode === 40014 || data.errcode === 42001) {
        logger.warn("access_token invalid, refreshing and retrying", { errcode: data.errcode });
        this._accessToken = null;
        this._tokenExpiresAt = 0;
        const freshToken = await this.getAccessToken();
        const retryUrl = `${WECOM_API_BASE}/message/send?access_token=${encodeURIComponent(freshToken)}`;
        const retryResp = await fetch(retryUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        if (!retryResp.ok) {
          throw new Error(`WeCom send retry failed: HTTP ${retryResp.status}`);
        }
        const retryData = await retryResp.json();
        if (retryData.errcode !== 0) {
          throw new Error(`WeCom send retry error: ${retryData.errcode} ${retryData.errmsg}`);
        }
        logger.info("Message sent after token refresh", { touser: body.touser, msgtype: body.msgtype });
        return retryData;
      }
      throw new Error(`WeCom send error: ${data.errcode} ${data.errmsg}`);
    }
    logger.info("Message sent", { touser: body.touser, msgtype: body.msgtype });
    return data;
  }
}

/**
 * Split text into chunks that fit within the character limit.
 * Tries to break at paragraph or sentence boundaries.
 */
function chunkText(text, limit) {
  if (!text || text.length <= limit) {
    return [text];
  }

  const chunks = [];
  let remaining = text;

  while (remaining.length > limit) {
    let breakPoint = remaining.lastIndexOf("\n\n", limit);
    if (breakPoint <= 0) {
      breakPoint = remaining.lastIndexOf("\n", limit);
    }
    if (breakPoint <= 0) {
      breakPoint = remaining.lastIndexOf("。", limit);
    }
    if (breakPoint <= 0) {
      breakPoint = remaining.lastIndexOf(". ", limit);
    }
    if (breakPoint <= 0) {
      breakPoint = limit;
    } else {
      breakPoint += 1;
    }

    chunks.push(remaining.substring(0, breakPoint));
    remaining = remaining.substring(breakPoint).trimStart();
  }

  if (remaining.length > 0) {
    chunks.push(remaining);
  }
  return chunks;
}
