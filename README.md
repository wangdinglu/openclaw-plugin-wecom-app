# openclaw-plugin-wecom-app

企业微信**自建应用**频道插件，适用于 [OpenClaw](https://github.com/openclaw/openclaw)。

与 [openclaw-plugin-wecom](https://github.com/sunnoy/openclaw-plugin-wecom)（智能机器人）不同，本插件对接的是企业微信「自建应用」，通过标准消息 API 发送回复，**支持微信插件可见**，让微信用户也能与 AI 对话。

## 核心差异

| 对比项 | 智能机器人 (wecom) | 自建应用 (wecom-app) |
|--------|-------------------|---------------------|
| 消息接收格式 | JSON | XML |
| 回复方式 | 流式被动响应 | 异步调 API 主动回复 |
| 认证方式 | Token + EncodingAESKey | Token + EncodingAESKey + corpid + corpsecret |
| 微信插件可见 | 不可见 | **可见** |

## 安装

```bash
openclaw plugins install github:wangdinglu/openclaw-plugin-wecom-app
```

## 配置

编辑 `~/.openclaw/openclaw.json`：

```json
{
  "plugins": {
    "entries": {
      "wecom-app": { "enabled": true }
    }
  },
  "channels": {
    "wecom-app": {
      "enabled": true,
      "corpid": "你的企业ID",
      "corpsecret": "自建应用的Secret",
      "agentid": 1000002,
      "token": "回调配置的Token",
      "encodingAesKey": "回调配置的EncodingAESKey"
    }
  }
}
```

### 获取配置值

| 配置项 | 获取位置 |
|--------|---------|
| corpid | [管理后台](https://work.weixin.qq.com/) → 我的企业 → 企业ID |
| corpsecret | 管理后台 → 应用管理 → 你的应用 → Secret |
| agentid | 管理后台 → 应用管理 → 你的应用 → AgentId |
| token | 应用 → API接收消息 → 设置时自动生成 |
| encodingAesKey | 应用 → API接收消息 → 设置时自动生成 |

## 企业微信后台配置

1. 登录 [企业微信管理后台](https://work.weixin.qq.com/)
2. 进入 **应用管理** → 你的自建应用
3. 在「API接收消息」中设置：
   - **URL**: `https://your-domain.com/webhooks/wecom-app`
   - **Token**: 与配置中一致
   - **EncodingAESKey**: 与配置中一致
4. 保存（会自动验证 URL）

## 反向代理

如果使用 Nginx 反向代理，在配置中添加：

```nginx
location /webhooks/wecom-app {
    proxy_pass http://127.0.0.1:18789;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 120s;
}
```

## 可选配置

```json
{
  "channels": {
    "wecom-app": {
      "adminUsers": ["管理员userid"],
      "commands": {
        "enabled": true,
        "allowlist": ["/new", "/status", "/help", "/compact"]
      },
      "dynamicAgents": { "enabled": true },
      "groupChat": {
        "enabled": true,
        "requireMention": true
      }
    }
  }
}
```

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| adminUsers | 管理员用户 ID 列表（绕过指令白名单和动态路由） | `[]` |
| commands.allowlist | 允许的斜杠指令 | `["/new", "/status", "/help", "/compact"]` |
| dynamicAgents.enabled | 按用户/群隔离 Agent | `true` |
| groupChat.requireMention | 群聊必须 @提及才响应 | `true` |
| webhookPath | 自定义 webhook 路径 | `/webhooks/wecom-app` |

## 项目结构

```
openclaw-plugin-wecom-app/
├── index.js              # 插件入口 + 频道注册 + HTTP handler + 消息处理
├── webhook.js            # XML 消息解析 + 签名验证
├── crypto.js             # AES-256-CBC 加解密（含 corpid 校验）
├── wecom-api.js          # 企微 API 客户端（access_token + 发消息）
├── dynamic-agent.js      # 动态 Agent 路由
├── logger.js             # 日志模块
├── utils.js              # 工具函数
├── package.json
└── openclaw.plugin.json
```

## 许可证

ISC
