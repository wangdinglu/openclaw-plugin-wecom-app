/**
 * Dynamic agent helpers for WeCom self-built application.
 *
 * Agent IDs use "wecom-app-" prefix to avoid collisions with the
 * AI Bot plugin ("wecom-dm-"/"wecom-group-").
 */

export function generateAgentId(chatType, peerId) {
  const sanitizedId = String(peerId)
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, "_");
  if (chatType === "group") {
    return `wecom-app-group-${sanitizedId}`;
  }
  return `wecom-app-dm-${sanitizedId}`;
}

export function getDynamicAgentConfig(config) {
  const ch = config?.channels?.["wecom-app"] || {};
  return {
    enabled: ch.dynamicAgents?.enabled !== false,
    dmCreateAgent: ch.dm?.createAgentOnFirstMessage !== false,
    groupEnabled: ch.groupChat?.enabled !== false,
    groupRequireMention: ch.groupChat?.requireMention !== false,
    groupMentionPatterns: ch.groupChat?.mentionPatterns || ["@"],
  };
}

export function shouldUseDynamicAgent({ chatType, config }) {
  const dynamicConfig = getDynamicAgentConfig(config);
  if (!dynamicConfig.enabled) {
    return false;
  }
  if (chatType === "group") {
    return dynamicConfig.groupEnabled;
  }
  return dynamicConfig.dmCreateAgent;
}

export function shouldTriggerGroupResponse(content, config) {
  const dynamicConfig = getDynamicAgentConfig(config);
  if (!dynamicConfig.groupEnabled) {
    return false;
  }
  if (!dynamicConfig.groupRequireMention) {
    return true;
  }
  const patterns = dynamicConfig.groupMentionPatterns;
  for (const pattern of patterns) {
    const escaped = escapeRegExp(pattern);
    const re = new RegExp(`(?:^|(?<=\\s|[^\\w]))${escaped}`, "u");
    if (re.test(content)) {
      return true;
    }
  }
  return false;
}

export function extractGroupMessageContent(content, config) {
  const dynamicConfig = getDynamicAgentConfig(config);
  let cleanContent = content;
  const patterns = dynamicConfig.groupMentionPatterns;
  for (const pattern of patterns) {
    const escapedPattern = escapeRegExp(pattern);
    const regex = new RegExp(`(?:^|(?<=\\s))${escapedPattern}\\S*\\s*`, "gu");
    cleanContent = cleanContent.replace(regex, "");
  }
  return cleanContent.trim();
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
