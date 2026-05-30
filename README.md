# OpenCode Safe Auto-Approve

An OpenCode plugin that hooks into `permission.asked` bus events to automatically approve low-risk bash commands while flagging dangerous operations for user confirmation.

## Installation

```bash
git clone https://github.com/cbruegg/opencode-safe-auto-approve.git ~/.config/opencode/plugins/safe-auto-approve
cd ~/.config/opencode/plugins/safe-auto-approve
npm install
```

Then register the plugin in your OpenCode config (e.g. `~/.config/opencode/opencode.json`).

## Configuration

Copy the example config and customize it:

```bash
cp safe-auto-approve.example.json ~/.config/opencode/plugins/safe-auto-approve.json
```

### Options

| Field | Type | Default | Description |
|---|---|---|---|
| `model` | string | `anthropic/claude-haiku-4-5` | Model used for classifier fallback (`provider/model` format) |
| `confidenceThreshold` | number | `0.8` | Minimum confidence (0–1) required for auto-approval |
| `timeoutMs` | number | `1500` | Max milliseconds for classifier request |
| `maxCommandLength` | number | `2000` | Commands longer than this are always sent to user |
| `logDecisions` | boolean | `true` | Log every decision to OpenCode logs |
| `cacheDecisions` | boolean | `true` | Cache deterministic and high-confidence decisions |
| `customInstructions` | string | `""` | Extra instructions appended to the classifier prompt |

## How It Works

The plugin runs a two-stage decision pipeline for every `permission.asked` event on `bash`/`shell` permissions:

1. **Deterministic Rules** — A hardcoded set of regex rules flags high-risk patterns (sudo, broad deletion, credential access, git pushes, deployments, etc.) and sends them straight to the user.

2. **Model Classifier Fallback** — Commands that pass the rule check are sent to the configured model with a structured classification prompt. If the model responds `AUTO_APPROVE` with confidence ≥ the threshold, the command is auto-approved.

If either stage fails (timeout, invalid response, no session), the plugin degrades gracefully and leaves the permission for the user to handle manually.

**Always sent to user:**
- `sudo`, `su`, `doas` (privilege escalation)
- `rm -rf` targeting root, home, system directories, or credential folders
- Reading credential files (`~/.ssh/id_rsa`, `~/.aws/credentials`, etc.)
- Git pushes and remote mutations
- Package publishing (`npm publish`, `cargo publish`)
- Kubernetes/Terraform/Pulumi mutations
- Docker system/volume/builder prune
- Downloaded code execution (`curl | sh`)
- Remote access (`ssh`, `scp`, `rsync`)
- Global package installs and auth mutations
- Suspicious data exfiltration
