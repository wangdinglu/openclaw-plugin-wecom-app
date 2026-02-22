import {
  generateAgentId,
  getDynamicAgentConfig,
  shouldUseDynamicAgent,
  shouldTriggerGroupResponse,
  extractGroupMessageContent,
} from "./dynamic-agent.js";
import { logger } from "./logger.js";
import { WecomApiClient } from "./wecom-api.js";
import { WecomAppWebhook } from "./webhook.js";

const DEFAULT_ACCOUNT_ID = "default";
const CHANNEL_ID = "wecom-app";

// =============================================================================
// Command allowlist
// =============================================================================

const DEFAULT_COMMAND_ALLOWLIST = ["/new", "/compact", "/help", "/status"];

const DEFAULT_COMMAND_BLOCK_MESSAGE = `⚠️ 该命令不可用。

支持的命令：
• **/new** - 新建会话
• **/compact** - 压缩会话（保留上下文摘要）
• **/help** - 查看帮助
• **/status** - 查看状态`;

function getCommandConfig(config) {
  const ch = config?.channels?.[CHANNEL_ID] || {};
  const commands = ch.commands || {};
  return {
    allowlist: commands.allowlist || DEFAULT_COMMAND_ALLOWLIST,
    blockMessage: commands.blockMessage || DEFAULT_COMMAND_BLOCK_MESSAGE,
    enabled: commands.enabled !== false,
  };
}

function checkCommandAllowlist(message, config) {
  const trimmed = message.trim();
  if (!trimmed.startsWith("/")) {
    return { isCommand: false, allowed: true, command: null };
  }
  const command = trimmed.split(/\s+/)[0].toLowerCase();
  const cmdConfig = getCommandConfig(config);
  if (!cmdConfig.enabled) {
    return { isCommand: true, allowed: true, command };
  }
  const allowed = cmdConfig.allowlist.some((cmd) => cmd.toLowerCase() === command);
  return { isCommand: true, allowed, command };
}

// =============================================================================
// Admin users
// =============================================================================

function getAdminUsers(config) {
  const raw = config?.channels?.[CHANNEL_ID]?.adminUsers;
  if (!Array.isArray(raw)) {
    return [];
  }
  return raw.map((u) => String(u ?? "").trim().toLowerCase()).filter(Boolean);
}

function isAdmin(userId, config) {
  if (!userId) return false;
  const admins = getAdminUsers(config);
  return admins.length > 0 && admins.includes(String(userId).trim().toLowerCase());
}

// =============================================================================
// Runtime state
// =============================================================================

let _runtime = null;
let _openclawConfig = null;
let _apiClient = null;
const ensuredDynamicAgentIds = new Set();
let ensureDynamicAgentWriteQueue = Promise.resolve();

const DEBOUNCE_MS = 2000;
const messageBuffers = new Map();
const dispatchLocks = new Map();

function setRuntime(runtime) {
  _runtime = runtime;
}

function getRuntime() {
  if (!_runtime) {
    throw new Error("[wecom-app] Runtime not initialized");
  }
  return _runtime;
}

function getApiClient() {
  if (!_apiClient) {
    throw new Error("[wecom-app] API client not initialized");
  }
  return _apiClient;
}

// =============================================================================
// Dynamic agent helpers
// =============================================================================

function upsertAgentIdOnlyEntry(cfg, agentId) {
  const normalizedId = String(agentId || "").trim().toLowerCase();
  if (!normalizedId) return false;

  if (!cfg.agents || typeof cfg.agents !== "object") {
    cfg.agents = {};
  }

  const currentList = Array.isArray(cfg.agents.list) ? cfg.agents.list : [];
  const existingIds = new Set(
    currentList
      .map((entry) => (entry && typeof entry.id === "string" ? entry.id.trim().toLowerCase() : ""))
      .filter(Boolean),
  );

  let changed = false;
  const nextList = [...currentList];

  if (nextList.length === 0) {
    nextList.push({ id: "main" });
    existingIds.add("main");
    changed = true;
  }

  if (!existingIds.has(normalizedId)) {
    nextList.push({ id: normalizedId });
    changed = true;
  }

  if (changed) {
    cfg.agents.list = nextList;
  }
  return changed;
}

async function ensureDynamicAgentListed(agentId) {
  const normalizedId = String(agentId || "").trim().toLowerCase();
  if (!normalizedId || ensuredDynamicAgentIds.has(normalizedId)) return;

  const runtime = getRuntime();
  const configRuntime = runtime?.config;
  if (!configRuntime?.loadConfig || !configRuntime?.writeConfigFile) return;

  ensureDynamicAgentWriteQueue = ensureDynamicAgentWriteQueue
    .then(async () => {
      if (ensuredDynamicAgentIds.has(normalizedId)) return;

      const latestConfig = configRuntime.loadConfig();
      if (!latestConfig || typeof latestConfig !== "object") return;

      const changed = upsertAgentIdOnlyEntry(latestConfig, normalizedId);
      if (changed) {
        await configRuntime.writeConfigFile(latestConfig);
        logger.info("Dynamic agent added to agents.list", { agentId: normalizedId });
      }

      if (_openclawConfig && typeof _openclawConfig === "object") {
        upsertAgentIdOnlyEntry(_openclawConfig, normalizedId);
      }

      ensuredDynamicAgentIds.add(normalizedId);
    })
    .catch((err) => {
      logger.warn("Failed to sync dynamic agent", {
        agentId: normalizedId,
        error: err?.message || String(err),
      });
    });

  await ensureDynamicAgentWriteQueue;
}

// =============================================================================
// Webhook target registry
// =============================================================================

const webhookTargets = new Map();

function normalizeWebhookPath(raw) {
  const trimmed = (raw || "").trim();
  if (!trimmed) return "/";
  const withSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  if (withSlash.length > 1 && withSlash.endsWith("/")) {
    return withSlash.slice(0, -1);
  }
  return withSlash;
}

function registerWebhookTarget(target) {
  const key = normalizeWebhookPath(target.path);
  const entry = { ...target, path: key };
  const existing = webhookTargets.get(key) ?? [];
  webhookTargets.set(key, [...existing, entry]);
  return () => {
    const updated = (webhookTargets.get(key) ?? []).filter((e) => e !== entry);
    if (updated.length > 0) {
      webhookTargets.set(key, updated);
    } else {
      webhookTargets.delete(key);
    }
  };
}

// =============================================================================
// AllowFrom / CommandAuthorized helpers
// =============================================================================

function resolveAllowFrom(cfg, accountId) {
  const ch = cfg?.channels?.[CHANNEL_ID];
  if (!ch) return [];
  const allowFromRaw = ch.dm?.allowFrom ?? ch.allowFrom ?? [];
  if (!Array.isArray(allowFromRaw)) return [];
  return allowFromRaw
    .map((raw) => {
      const trimmed = String(raw ?? "").trim();
      if (!trimmed) return null;
      if (trimmed === "*") return "*";
      return trimmed.replace(/^(wecom-app|wecom|wework):/i, "").replace(/^user:/i, "").toLowerCase();
    })
    .filter(Boolean);
}

function resolveCommandAuthorized({ cfg, accountId, senderId }) {
  const sender = String(senderId ?? "").trim().toLowerCase();
  if (!sender) return false;
  const allowFrom = resolveAllowFrom(cfg, accountId);
  if (allowFrom.includes("*") || allowFrom.length === 0) return true;
  return allowFrom.includes(sender);
}

// =============================================================================
// Outbound target resolution
// For normal replies, `to` is "wecom-app:<userid>".
// For cron/system announcements, `to` might be a conversation ID or empty.
// Falls back to defaultNotifyUser from config.
// =============================================================================

function resolveOutboundTarget(to, cfg) {
  if (!to) {
    return getDefaultNotifyUser(cfg);
  }

  // Strip channel prefix: "wecom-app:WangDingLu01" → "WangDingLu01"
  let userId = to.replace(new RegExp(`^${CHANNEL_ID}:`), "");

  // Strip additional prefixes that OpenClaw might add
  userId = userId.replace(/^(group:|dm:)/, "");

  // If userId looks like a valid WeCom userid (alphanumeric, not a UUID/hash), use it.
  if (userId && /^[a-zA-Z0-9_-]+$/.test(userId) && userId.length <= 64) {
    return userId;
  }

  // Fallback to configured default user for system/cron messages.
  return getDefaultNotifyUser(cfg);
}

function getDefaultNotifyUser(cfg) {
  const ch = cfg?.channels?.[CHANNEL_ID];
  if (ch?.defaultNotifyUser) {
    return ch.defaultNotifyUser;
  }
  // Fall back to first admin user if available.
  const admins = ch?.adminUsers;
  if (Array.isArray(admins) && admins.length > 0) {
    return admins[0];
  }
  return null;
}

// =============================================================================
// HTTP Handler — handles GET verification and POST messages
// =============================================================================

async function wecomAppHttpHandler(req, res) {
  const url = new URL(req.url || "", "http://localhost");
  const path = normalizeWebhookPath(url.pathname);
  const targets = webhookTargets.get(path);

  if (!targets || targets.length === 0) {
    return false;
  }

  const query = Object.fromEntries(url.searchParams);
  logger.debug("HTTP request", { method: req.method, path });

  // GET: URL Verification
  if (req.method === "GET") {
    const target = targets[0];
    if (!target) {
      res.writeHead(503, { "Content-Type": "text/plain" });
      res.end("No webhook target configured");
      return true;
    }

    const webhook = new WecomAppWebhook({
      token: target.account.token,
      encodingAesKey: target.account.encodingAesKey,
      corpId: target.account.corpId,
    });

    const echo = webhook.handleVerify(query);
    if (echo) {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(echo);
      logger.info("URL verification successful");
      return true;
    }

    res.writeHead(403, { "Content-Type": "text/plain" });
    res.end("Verification failed");
    logger.warn("URL verification failed");
    return true;
  }

  // POST: Message handling
  if (req.method === "POST") {
    const target = targets[0];
    if (!target) {
      res.writeHead(503, { "Content-Type": "text/plain" });
      res.end("No webhook target configured");
      return true;
    }

    // Read request body
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(chunk);
    }
    const body = Buffer.concat(chunks).toString("utf-8");
    logger.debug("Message received", { bodyLength: body.length });

    const webhook = new WecomAppWebhook({
      token: target.account.token,
      encodingAesKey: target.account.encodingAesKey,
      corpId: target.account.corpId,
    });

    const result = await webhook.handleMessage(query, body);

    // Immediately respond to WeCom to prevent timeout.
    // All replies are sent asynchronously via the message API.
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("success");

    if (result === WecomAppWebhook.DUPLICATE) {
      return true;
    }
    if (!result) {
      return true;
    }

    // Handle regular messages
    if (result.message) {
      const msg = result.message;
      const content = (msg.content || "").trim();
      const isCommand = content.startsWith("/");
      const streamKey = msg.chatId || msg.fromUser;

      logger.info("Processing inbound message", {
        from: msg.fromUser,
        isCommand,
        content: content.substring(0, 50),
      });

      // Commands bypass debounce.
      if (isCommand) {
        processInboundMessage({
          message: msg,
          account: target.account,
          config: target.config,
        }).catch((err) => {
          logger.error("Message processing failed", { error: err.message });
          sendErrorReply(msg.fromUser, "处理消息时出错，请稍后再试。");
        });
        return true;
      }

      // Debounce non-command messages.
      const existing = messageBuffers.get(streamKey);
      if (existing) {
        existing.messages.push(msg);
        clearTimeout(existing.timer);
        existing.timer = setTimeout(() => flushMessageBuffer(streamKey, target), DEBOUNCE_MS);
        logger.info("Message buffered for merge", { streamKey, buffered: existing.messages.length });
      } else {
        const buffer = {
          messages: [msg],
          target,
          timer: setTimeout(() => flushMessageBuffer(streamKey, target), DEBOUNCE_MS),
        };
        messageBuffers.set(streamKey, buffer);
        logger.info("Message buffered (first)", { streamKey });
      }

      return true;
    }

    // Handle events
    if (result.event) {
      logger.info("Event received", { event: result.event });
      return true;
    }

    return true;
  }

  res.writeHead(405, { "Content-Type": "text/plain" });
  res.end("Method Not Allowed");
  return true;
}

// =============================================================================
// Message debounce + flush
// =============================================================================

function flushMessageBuffer(streamKey, target) {
  const buffer = messageBuffers.get(streamKey);
  if (!buffer) return;
  messageBuffers.delete(streamKey);

  const { messages } = buffer;
  const primaryMsg = messages[0];

  if (messages.length > 1) {
    const mergedContent = messages.map((m) => m.content || "").filter(Boolean).join("\n");
    primaryMsg.content = mergedContent;
    logger.info("Flushing merged messages", {
      streamKey,
      count: messages.length,
      preview: mergedContent.substring(0, 60),
    });
  } else {
    logger.info("Flushing single message", { streamKey });
  }

  processInboundMessage({
    message: primaryMsg,
    account: target.account,
    config: target.config,
  }).catch((err) => {
    logger.error("Message processing failed", { error: err.message });
    sendErrorReply(primaryMsg.fromUser, "处理消息时出错，请稍后再试。");
  });
}

// =============================================================================
// Inbound message processing → AI dispatch
// =============================================================================

async function processInboundMessage({ message, account, config }) {
  const runtime = getRuntime();
  const core = runtime.channel;

  const senderId = message.fromUser;
  const rawContent = message.content || "";
  const chatType = message.chatType || "single";
  const chatId = message.chatId || "";
  const isGroupChat = chatType === "group" && chatId;

  const peerId = isGroupChat ? chatId : senderId;
  const peerKind = isGroupChat ? "group" : "dm";
  const conversationId = isGroupChat
    ? `${CHANNEL_ID}:group:${chatId}`
    : `${CHANNEL_ID}:${senderId}`;
  const streamKey = isGroupChat ? chatId : senderId;

  // Group mention gating
  let rawBody = rawContent;
  if (isGroupChat) {
    if (!shouldTriggerGroupResponse(rawContent, config)) {
      logger.debug("Group message ignored (no mention)", { chatId, senderId });
      return;
    }
    rawBody = extractGroupMessageContent(rawContent, config);
  }

  // Skip empty messages
  if (!rawBody.trim()) {
    logger.debug("Empty message, skipping");
    return;
  }

  // Command allowlist enforcement
  const senderIsAdmin = isAdmin(senderId, config);
  const commandCheck = checkCommandAllowlist(rawBody, config);

  if (commandCheck.isCommand && !commandCheck.allowed && !senderIsAdmin) {
    const cmdConfig = getCommandConfig(config);
    logger.warn("Blocked command", { command: commandCheck.command, from: senderId });
    await sendErrorReply(senderId, cmdConfig.blockMessage);
    return;
  }

  logger.info("Processing message for AI", {
    from: senderId,
    chatType: peerKind,
    peerId,
    content: rawBody.substring(0, 50),
    isCommand: commandCheck.isCommand,
  });

  // Dynamic agent routing
  const dynamicConfig = getDynamicAgentConfig(config);
  const targetAgentId =
    !senderIsAdmin && dynamicConfig.enabled && shouldUseDynamicAgent({ chatType: peerKind, config })
      ? generateAgentId(peerKind, peerId)
      : null;

  if (targetAgentId) {
    await ensureDynamicAgentListed(targetAgentId);
    logger.debug("Using dynamic agent", { agentId: targetAgentId });
  }

  // Resolve route
  const route = core.routing.resolveAgentRoute({
    cfg: config,
    channel: CHANNEL_ID,
    accountId: account.accountId,
    peer: { kind: peerKind, id: peerId },
  });

  if (targetAgentId) {
    route.agentId = targetAgentId;
    route.sessionKey = `agent:${targetAgentId}:${peerKind}:${peerId}`;
  }

  // Build inbound context
  const commandAuthorized = resolveCommandAuthorized({
    cfg: config,
    accountId: account.accountId,
    senderId,
  });

  const storePath = core.session.resolveStorePath(config.session?.store, {
    agentId: route.agentId,
  });
  const envelopeOptions = core.reply.resolveEnvelopeFormatOptions(config);
  const previousTimestamp = core.session.readSessionUpdatedAt({
    storePath,
    sessionKey: route.sessionKey,
  });

  const senderLabel = isGroupChat ? `[${senderId}]` : senderId;
  const body = core.reply.formatAgentEnvelope({
    channel: isGroupChat ? "Enterprise WeChat Group" : "Enterprise WeChat",
    from: senderLabel,
    timestamp: Date.now(),
    previousTimestamp,
    envelope: envelopeOptions,
    body: rawBody,
  });

  const ctxBase = {
    Body: body,
    RawBody: rawBody,
    CommandBody: rawBody,
    From: `${CHANNEL_ID}:${senderId}`,
    To: conversationId,
    SessionKey: route.sessionKey,
    AccountId: route.accountId,
    ChatType: isGroupChat ? "group" : "direct",
    ConversationLabel: isGroupChat ? `Group ${chatId}` : senderId,
    SenderName: senderId,
    SenderId: senderId,
    GroupId: isGroupChat ? chatId : undefined,
    Provider: CHANNEL_ID,
    Surface: CHANNEL_ID,
    OriginatingChannel: CHANNEL_ID,
    OriginatingTo: conversationId,
    CommandAuthorized: commandAuthorized,
  };

  const ctxPayload = core.reply.finalizeInboundContext(ctxBase);

  // Record session meta
  void core.session
    .recordSessionMetaFromInbound({
      storePath,
      sessionKey: ctxPayload.SessionKey ?? route.sessionKey,
      ctx: ctxPayload,
    })
    .catch((err) => {
      logger.error("Failed updating session meta", { error: err.message });
    });

  // Serialize dispatches per user/group.
  const prevLock = dispatchLocks.get(streamKey) ?? Promise.resolve();
  const currentDispatch = prevLock.then(async () => {
    await core.reply.dispatchReplyWithBufferedBlockDispatcher({
      ctx: ctxPayload,
      cfg: config,
      dispatcherOptions: {
        deliver: async (payload, info) => {
          const text = payload.text || "";
          logger.info("Deliver called", {
            kind: info.kind,
            hasText: !!text.trim(),
            preview: text.substring(0, 50),
          });

          if (!text.trim()) return;

          try {
            await getApiClient().sendText(senderId, text);
          } catch (err) {
            logger.error("Failed to send reply", {
              to: senderId,
              error: err.message,
            });
          }
        },
        onError: async (err, info) => {
          logger.error("Reply dispatch failed", { error: err.message, kind: info.kind });
          await sendErrorReply(senderId, "处理消息时出错，请稍后再试。");
        },
      },
    });
  }).catch(async (err) => {
    logger.error("Dispatch chain error", { streamKey, error: err.message });
    await sendErrorReply(senderId, "处理消息时出错，请稍后再试。");
  });

  dispatchLocks.set(streamKey, currentDispatch);
  await currentDispatch;
  if (dispatchLocks.get(streamKey) === currentDispatch) {
    dispatchLocks.delete(streamKey);
  }
}

async function sendErrorReply(toUser, text) {
  try {
    await getApiClient().sendText(toUser, text);
  } catch (err) {
    logger.error("Failed to send error reply", { to: toUser, error: err.message });
  }
}

// =============================================================================
// Channel Plugin Definition
// =============================================================================

const wecomAppChannelPlugin = {
  id: CHANNEL_ID,
  meta: {
    id: CHANNEL_ID,
    label: "Enterprise WeChat App",
    selectionLabel: "Enterprise WeChat (Self-built App)",
    docsPath: "/channels/wecom-app",
    blurb: "Enterprise WeChat self-built application channel plugin.",
    aliases: ["wecom-app", "wework-app"],
  },
  capabilities: {
    chatTypes: ["direct", "group"],
    reactions: false,
    threads: false,
    media: false,
    nativeCommands: false,
    blockStreaming: true,
  },
  reload: { configPrefixes: [`channels.${CHANNEL_ID}`] },
  configSchema: {
    schema: {
      $schema: "http://json-schema.org/draft-07/schema#",
      type: "object",
      additionalProperties: false,
      properties: {
        enabled: {
          type: "boolean",
          description: "Enable WeCom App channel",
          default: true,
        },
        corpid: {
          type: "string",
          description: "Enterprise WeChat Corp ID",
        },
        corpsecret: {
          type: "string",
          description: "Self-built application Secret",
        },
        agentid: {
          type: "number",
          description: "Self-built application Agent ID",
        },
        token: {
          type: "string",
          description: "Callback Token from admin console",
        },
        encodingAesKey: {
          type: "string",
          description: "Message encryption key (43 characters)",
          minLength: 43,
          maxLength: 43,
        },
        webhookPath: {
          type: "string",
          description: "Custom webhook path (default: /webhooks/wecom-app)",
        },
        commands: {
          type: "object",
          additionalProperties: false,
          properties: {
            enabled: { type: "boolean", default: true },
            allowlist: {
              type: "array",
              items: { type: "string" },
              default: ["/new", "/status", "/help", "/compact"],
            },
          },
        },
        dynamicAgents: {
          type: "object",
          additionalProperties: false,
          properties: {
            enabled: { type: "boolean", default: true },
          },
        },
        dm: {
          type: "object",
          additionalProperties: false,
          properties: {
            createAgentOnFirstMessage: { type: "boolean", default: true },
          },
        },
        groupChat: {
          type: "object",
          additionalProperties: false,
          properties: {
            enabled: { type: "boolean", default: true },
            requireMention: { type: "boolean", default: true },
          },
        },
        adminUsers: {
          type: "array",
          items: { type: "string" },
          default: [],
        },
        defaultNotifyUser: {
          type: "string",
          description: "Default userid for cron/system notifications (falls back to first adminUser)",
        },
      },
    },
    uiHints: {
      corpsecret: { sensitive: true, label: "App Secret" },
      token: { sensitive: true, label: "Callback Token" },
      encodingAesKey: {
        sensitive: true,
        label: "Encoding AES Key",
        help: "43-character encryption key from WeCom admin console",
      },
    },
  },
  config: {
    listAccountIds: (cfg) => {
      const ch = cfg?.channels?.[CHANNEL_ID];
      if (!ch || !ch.enabled) return [];
      return [DEFAULT_ACCOUNT_ID];
    },
    resolveAccount: (cfg, accountId) => {
      const ch = cfg?.channels?.[CHANNEL_ID];
      if (!ch) return null;
      return {
        id: accountId || DEFAULT_ACCOUNT_ID,
        accountId: accountId || DEFAULT_ACCOUNT_ID,
        enabled: ch.enabled !== false,
        token: ch.token || "",
        encodingAesKey: ch.encodingAesKey || "",
        corpId: ch.corpid || "",
        corpSecret: ch.corpsecret || "",
        agentId: ch.agentid || 0,
        webhookPath: ch.webhookPath || "/webhooks/wecom-app",
        config: ch,
      };
    },
    defaultAccountId: (cfg) => {
      const ch = cfg?.channels?.[CHANNEL_ID];
      if (!ch || !ch.enabled) return null;
      return DEFAULT_ACCOUNT_ID;
    },
    setAccountEnabled: ({ cfg, accountId: _accountId, enabled }) => {
      if (!cfg.channels) cfg.channels = {};
      if (!cfg.channels[CHANNEL_ID]) cfg.channels[CHANNEL_ID] = {};
      cfg.channels[CHANNEL_ID].enabled = enabled;
      return cfg;
    },
    deleteAccount: ({ cfg, accountId: _accountId }) => {
      if (cfg.channels?.[CHANNEL_ID]) {
        delete cfg.channels[CHANNEL_ID];
      }
      return cfg;
    },
  },
  directory: {
    self: async () => null,
    listPeers: async () => [],
    listGroups: async () => [],
  },
  outbound: {
    deliveryMode: "direct",
    sendText: async ({ cfg, to, text, accountId: _accountId }) => {
      const userId = resolveOutboundTarget(to, cfg);
      if (!userId) {
        logger.warn("outbound.sendText: no valid target", { to });
        return { channel: CHANNEL_ID, messageId: `msg_skip_${Date.now()}` };
      }
      try {
        await getApiClient().sendText(userId, text);
      } catch (err) {
        logger.error("outbound.sendText failed", { to: userId, error: err.message });
      }
      return {
        channel: CHANNEL_ID,
        messageId: `msg_${Date.now()}`,
      };
    },
    sendMedia: async ({ cfg, to, text, mediaUrl, accountId: _accountId }) => {
      const userId = resolveOutboundTarget(to, cfg);
      if (!userId) {
        logger.warn("outbound.sendMedia: no valid target", { to });
        return { channel: CHANNEL_ID, messageId: `msg_skip_${Date.now()}` };
      }
      const content = text
        ? `${text}\n\n${mediaUrl}`
        : mediaUrl;
      try {
        await getApiClient().sendText(userId, content);
      } catch (err) {
        logger.error("outbound.sendMedia failed", { to: userId, error: err.message });
      }
      return {
        channel: CHANNEL_ID,
        messageId: `msg_${Date.now()}`,
      };
    },
  },
  gateway: {
    startAccount: async (ctx) => {
      const account = ctx.account;
      logger.info("Gateway starting", {
        accountId: account.accountId,
        webhookPath: account.webhookPath,
        corpId: account.corpId,
        agentId: account.agentId,
      });

      // Initialize the API client for outbound messages.
      _apiClient = new WecomApiClient({
        corpId: account.corpId,
        corpSecret: account.corpSecret,
        agentId: account.agentId,
      });

      const unregister = registerWebhookTarget({
        path: account.webhookPath || "/webhooks/wecom-app",
        account,
        config: ctx.cfg,
      });

      return {
        shutdown: async () => {
          logger.info("Gateway shutting down");
          for (const [, buf] of messageBuffers) {
            clearTimeout(buf.timer);
          }
          messageBuffers.clear();
          _apiClient = null;
          unregister();
        },
      };
    },
  },
};

// =============================================================================
// Plugin Registration
// =============================================================================

const plugin = {
  id: "wecom-app",
  name: "Enterprise WeChat App",
  description: "Enterprise WeChat self-built application channel plugin for OpenClaw",
  configSchema: { type: "object", additionalProperties: false, properties: {} },
  register(api) {
    logger.info("WeCom App plugin registering...");

    setRuntime(api.runtime);
    _openclawConfig = api.config;

    api.registerChannel({ plugin: wecomAppChannelPlugin });
    logger.info("WeCom App channel registered");

    api.registerHttpHandler(wecomAppHttpHandler);
    logger.info("WeCom App HTTP handler registered");
  },
};

export default plugin;
