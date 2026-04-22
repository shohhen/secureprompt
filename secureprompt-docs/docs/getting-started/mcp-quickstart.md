---
sidebar_position: 2
---

# MCP Quickstart

Connect Claude Desktop to SecurePrompt via the Model Context Protocol.

## What the MCP server exposes

| Tool | Description |
|------|-------------|
| `redact` | Redact PII and secrets from text |
| `check_policy` | Check a prompt against indexed policy rules |
| `estimate_tokens` | Count tokens before sending to a provider |

## Configure Claude Desktop

Add SecurePrompt to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "secureprompt": {
      "command": "docker",
      "args": ["exec", "-i", "secureprompt-mcp", "sp-mcp"],
      "env": {
        "SP_API_KEY": "sp-your-key-here"
      }
    }
  }
}
```

Restart Claude Desktop — SecurePrompt tools appear in the tool picker.

## Via HTTP (for other MCP clients)

The MCP server also speaks HTTP at `http://localhost:8081`:

```bash
curl -X POST http://localhost:8081/mcp \
  -H "Content-Type: application/json" \
  -d '{"method":"tools/call","params":{"name":"redact","arguments":{"text":"My email is john@example.com"}}}'
```
