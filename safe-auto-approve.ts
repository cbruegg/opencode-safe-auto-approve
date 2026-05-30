/**
 * OpenCode Safe Auto-Approve Plugin
 *
 * Hooks into permission.asked bus events to auto-approve low-risk bash commands.
 * Pipeline: deterministic ask rules → model classifier fallback → reply "once".
 * All failures degrade to ASK_USER (no reply sent).
 *
 * Configuration: create ~/.config/opencode/plugins/safe-auto-approve.json
 * {
 *   "model": "anthropic/claude-haiku-4-5",
 *   "confidenceThreshold": 0.8,
 *   "timeoutMs": 1500,
 *   "customInstructions": "Auto-approve local Docker commands, but ask before deleting volumes.",
 *   "showDecisionToasts": true,
 *   "showDecisionInline": true
 * }
 */

import type { Plugin } from "@opencode-ai/plugin"
import { createOpencodeClient as createOpencodeClientV2 } from "@opencode-ai/sdk/v2"

// ============================================================================
// Types & Config
// ============================================================================

type Decision = {
  kind: "AUTO_APPROVE" | "ASK_USER"
  source: "rule" | "model" | "error"
  confidence?: number
  reason: string
}

interface PluginConfig {
  model: string
  confidenceThreshold: number
  timeoutMs: number
  maxCommandLength: number
  logDecisions: boolean
  cacheDecisions: boolean
  customInstructions: string
  showDecisionToasts: boolean
  showDecisionInline: boolean
}

const DEFAULT_CONFIG: PluginConfig = {
  model: "anthropic/claude-haiku-4-5",
  confidenceThreshold: 0.8,
  timeoutMs: 1500,
  maxCommandLength: 2000,
  logDecisions: true,
  cacheDecisions: true,
  customInstructions: "",
  showDecisionToasts: true,
  showDecisionInline: true,
}

async function loadConfig(): Promise<PluginConfig> {
  const n = (v: unknown, d: number) => (typeof v === "number" ? v : d)
  const s = (v: unknown, d: string) => (typeof v === "string" ? v : d)
  const b = (v: unknown, d: boolean) => (typeof v === "boolean" ? v : d)

  let fileConfig: Record<string, unknown> = {}
  try {
    const fs = await import("node:fs")
    const path = await import("node:path")
    const configPath = path.join(
      process.env.HOME || process.env.USERPROFILE || "",
      ".config/opencode/plugins/safe-auto-approve.json",
    )
    if (fs.existsSync(configPath)) {
      const text = fs.readFileSync(configPath, "utf-8")
      fileConfig = JSON.parse(text)
    }
  } catch {
    // Ignore missing or invalid config file
  }

  return {
    model: s(fileConfig.model, DEFAULT_CONFIG.model),
    confidenceThreshold: n(fileConfig.confidenceThreshold, DEFAULT_CONFIG.confidenceThreshold),
    timeoutMs: n(fileConfig.timeoutMs, DEFAULT_CONFIG.timeoutMs),
    maxCommandLength: n(fileConfig.maxCommandLength, DEFAULT_CONFIG.maxCommandLength),
    logDecisions: b(fileConfig.logDecisions, DEFAULT_CONFIG.logDecisions),
    cacheDecisions: b(fileConfig.cacheDecisions, DEFAULT_CONFIG.cacheDecisions),
    customInstructions: s(fileConfig.customInstructions, DEFAULT_CONFIG.customInstructions),
    showDecisionToasts: b(fileConfig.showDecisionToasts, DEFAULT_CONFIG.showDecisionToasts),
    showDecisionInline: b(fileConfig.showDecisionInline, DEFAULT_CONFIG.showDecisionInline),
  }
}

// ============================================================================
// Cache
// ============================================================================

const decisionCache = new Map<string, Decision>()
const MAX_CACHE_SIZE = 500

function cacheKey(permission: string, command: string): string {
  return `${permission}::${command.trim().replace(/\s+/g, " ")}`
}

function getCached(key: string): Decision | undefined {
  return decisionCache.get(key)
}

function setCached(key: string, decision: Decision): void {
  if (!decisionCache.has(key) && decisionCache.size >= MAX_CACHE_SIZE) {
    decisionCache.delete(decisionCache.keys().next().value!)
  }
  decisionCache.set(key, decision)
}

function shouldCache(d: Decision): boolean {
  return !(d.source === "model" && d.kind === "ASK_USER")
}

// ============================================================================
// Deterministic Ask Rules
// ============================================================================

type Rule = { test: (cmd: string) => boolean; reason: string }

const ASK_RULES: Rule[] = [
  // Privilege escalation
  { test: (cmd) => /\bsudo\b/.test(cmd), reason: "Privilege escalation (sudo)" },
  { test: (cmd) => /\bsu\s+-/.test(cmd), reason: "Privilege escalation (su)" },
  { test: (cmd) => /\bdoas\b/.test(cmd), reason: "Privilege escalation (doas)" },

  // Broad filesystem deletion
  { test: (cmd) => /\brm\s+-[rf]*\s+(\/\s*$|\/\b)/.test(cmd), reason: "Broad filesystem deletion targeting root" },
  { test: (cmd) => /\brm\s+-[rf]*\s+~\b/.test(cmd), reason: "Home directory deletion" },
  { test: (cmd) => /\brm\s+-[rf]*\s+\$HOME\b/.test(cmd), reason: "Home directory deletion" },
  { test: (cmd) => /\brm\s+-[rf]*\s+(\.\.\/|\.{2,})+/.test(cmd), reason: "Deletion outside project (parent directory)" },
  { test: (cmd) => /\brm\s+-[rf]*\s+\/etc\b/.test(cmd), reason: "System directory deletion (/etc)" },
  { test: (cmd) => /\brm\s+-[rf]*\s+\/usr\b/.test(cmd), reason: "System directory deletion (/usr)" },
  { test: (cmd) => /\brm\s+-[rf]*\s+\/var\b/.test(cmd), reason: "System directory deletion (/var)" },
  { test: (cmd) => /\brm\s+-[rf]*\s+\/bin\b/.test(cmd), reason: "System directory deletion (/bin)" },
  { test: (cmd) => /\brm\s+-[rf]*\s+\/sbin\b/.test(cmd), reason: "System directory deletion (/sbin)" },
  { test: (cmd) => /\brm\s+-[rf]*\s+\/lib/.test(cmd), reason: "System directory deletion (/lib)" },
  { test: (cmd) => /\brm\s+-[rf]*\s+\/opt\b/.test(cmd), reason: "System directory deletion (/opt)" },
  { test: (cmd) => /\brm\s+-[rf]*\s+~\/\.(ssh|aws|gnupg|config|npmrc|netrc|bash_history|zsh_history)\b/.test(cmd), reason: "Credential/config directory deletion" },

  // Credential access
  {
    test: (cmd) =>
      /\b(cat|less|more|head|tail|sed|awk|grep|rg)\b.*~\/\.(ssh\/id_rsa|ssh\/id_ed25519|ssh\/id_ecdsa|aws\/credentials|config\/gh\/hosts|npmrc|netrc|bash_history|zsh_history)/.test(cmd),
    reason: "Credential file access",
  },
  {
    test: (cmd) =>
      /\b(cat|less|more|head|tail)\b.*\.(env(\.local|\.production|\.development)?)\b/.test(cmd),
    reason: "Environment file access",
  },
  { test: (cmd) => /^\s*(env|printenv|set)\s*$/.test(cmd), reason: "Environment variable dump" },

  // Git remote mutation
  { test: (cmd) => /\bgit\s+push\b/.test(cmd), reason: "Git push to remote" },
  { test: (cmd) => /\bgit\s+remote\s+(add|set-url|remove|rename)\b/.test(cmd), reason: "Git remote mutation" },

  // Publishing
  { test: (cmd) => /\b(npm|pnpm|yarn|cargo)\s+publish\b/.test(cmd), reason: "Package publishing" },

  // Deployment
  { test: (cmd) => /\bkubectl\s+(apply|delete|exec|run|create|patch)\b/.test(cmd), reason: "Kubernetes mutation" },
  { test: (cmd) => /\bterraform\s+(apply|destroy|plan\s+-destroy)\b/.test(cmd), reason: "Terraform infrastructure mutation" },
  { test: (cmd) => /\bpulumi\s+(up|destroy|refresh)\b/.test(cmd), reason: "Pulumi infrastructure mutation" },
  { test: (cmd) => /\b(vercel|fly|flyctl|railway)\s+(deploy|up)\b/.test(cmd), reason: "Deployment to remote" },

  // Docker broad cleanup
  { test: (cmd) => /\bdocker\s+system\s+prune\b/.test(cmd), reason: "Docker system-wide cleanup" },
  { test: (cmd) => /\bdocker\s+volume\s+prune\b/.test(cmd), reason: "Docker volume cleanup" },
  { test: (cmd) => /\bdocker\s+builder\s+prune\b/.test(cmd), reason: "Docker builder cleanup" },
  { test: (cmd) => /\bdocker\s+rm\s+-f\s+\$\(/.test(cmd), reason: "Docker bulk container removal" },
  { test: (cmd) => /\bdocker\s+rmi\s+-f\s+\$\(/.test(cmd), reason: "Docker bulk image removal" },

  // Downloaded code execution
  {
    test: (cmd) =>
      /\b(curl|wget)\b.*(\|\s*(sh|bash|zsh)|>\s*.*\.(sh|bash|zsh)|-[oO]\s+\S*\.(sh|bash|zsh))/.test(cmd),
    reason: "Downloaded code execution",
  },

  // Remote access
  { test: (cmd) => /^\s*ssh\b/.test(cmd), reason: "Remote SSH access" },
  { test: (cmd) => /^\s*scp\b/.test(cmd), reason: "Remote file copy (scp)" },
  { test: (cmd) => /^\s*rsync\b.*:/.test(cmd), reason: "Remote rsync" },

  // Global package installation / auth
  { test: (cmd) => /\b(npm|pnpm|yarn|bun)\s+install\s+-g\b/.test(cmd), reason: "Global package installation" },
  { test: (cmd) => /\bnpm\s+(login|token|logout)\b/.test(cmd), reason: "Package manager authentication" },
  { test: (cmd) => /\bnpm\s+config\s+set\b.*auth/i.test(cmd), reason: "Credential configuration" },

  // Exfiltration
  {
    test: (cmd) => /\bcurl\b.*-X\s+POST/.test(cmd) && /\b(env|\.env|ssh|token|secret|key)\b/.test(cmd),
    reason: "Potential data exfiltration",
  },
]

function matchAskRule(command: string): Decision | null {
  for (const rule of ASK_RULES) {
    if (rule.test(command)) {
      return { kind: "ASK_USER", source: "rule", reason: rule.reason }
    }
  }
  return null
}

// ============================================================================
// Model Classifier
// ============================================================================

const CLASSIFIER_PROMPT = `You classify OpenCode permission requests for auto-approval.

Return AUTO_APPROVE for ordinary developer commands that read, write, move, delete, build, test, install, run local tools, use shell operators, or mutate local Git state, as long as their effects are local, bounded, and recoverable.

Return ASK_USER for commands that use elevated privileges, affect broad system paths, publish/deploy, push to remotes, execute downloaded code, access credentials, upload data, modify remote systems, or have unclear high-impact effects.

When uncertain about a high-impact command, return ASK_USER. When uncertain about a normal local command, prefer AUTO_APPROVE.

Return JSON only:
{
  "decision": "AUTO_APPROVE" | "ASK_USER",
  "confidence": number between 0.0 and 1.0,
  "reason": string
}`

function buildClassifierPrompt(config: PluginConfig): string {
  const customInstructions = config.customInstructions.trim()
  if (!customInstructions) return CLASSIFIER_PROMPT

  return `${CLASSIFIER_PROMPT}

Additional user instructions:
${customInstructions}`
}

function parseModelId(model: string): { providerID: string; modelID: string } {
  const idx = model.indexOf("/")
  if (idx > 0 && idx < model.length - 1) {
    return { providerID: model.slice(0, idx), modelID: model.slice(idx + 1) }
  }
  return { providerID: "opencode", modelID: model }
}

function unwrapSdkData<T = any>(result: unknown): T {
  const obj = result as { data?: T; error?: unknown } | null
  if (obj && typeof obj === "object" && "error" in obj && obj.error) {
    throw new Error(typeof obj.error === "string" ? obj.error : JSON.stringify(obj.error))
  }
  if (obj && typeof obj === "object" && "data" in obj) return obj.data as T
  return result as T
}

async function classifyWithModel(
  client: any,
  sessionId: string,
  command: string,
  config: PluginConfig,
): Promise<Decision> {
  const modelId = parseModelId(config.model)

  const timeoutPromise = new Promise<never>((_, reject) => {
    setTimeout(() => reject(new Error("Classifier timeout")), config.timeoutMs)
  })

  const promptPromise = client.session.prompt({
    path: { id: sessionId },
    body: {
      model: modelId,
      system: buildClassifierPrompt(config),
      parts: [
        { type: "text", text: `Command:\n${command}` },
      ],
    },
  })

  let result: unknown
  try {
    result = unwrapSdkData(await Promise.race([promptPromise, timeoutPromise]))
  } catch (error) {
    return {
      kind: "ASK_USER",
      source: "error",
      reason: `Classifier failed: ${error instanceof Error ? error.message : String(error)}`,
    }
  }

  let text = ""
  const obj = result as Record<string, unknown> | undefined
  if (obj && Array.isArray(obj.parts)) {
    for (const part of obj.parts as Array<Record<string, unknown>>) {
      if (part.type === "text" && typeof part.text === "string") text += part.text
    }
  }

  let parsed: { decision?: unknown; confidence?: unknown; reason?: unknown } = {}
  try {
    const match = text.match(/\{[\s\S]*\}/)
    parsed = JSON.parse(match ? match[0] : text) as typeof parsed
  } catch {
    return { kind: "ASK_USER", source: "error", reason: "Classifier returned invalid JSON" }
  }

  const decision = parsed.decision
  const confidence = typeof parsed.confidence === "number" ? parsed.confidence : 0
  const reason = typeof parsed.reason === "string" ? parsed.reason : "No reason provided"

  if (decision !== "AUTO_APPROVE" && decision !== "ASK_USER") {
    return { kind: "ASK_USER", source: "error", reason: "Classifier returned invalid decision value" }
  }

  if (decision === "AUTO_APPROVE" && confidence >= config.confidenceThreshold) {
    return { kind: "AUTO_APPROVE", source: "model", confidence, reason }
  }

  return {
    kind: "ASK_USER",
    source: "model",
    confidence,
    reason:
      decision === "AUTO_APPROVE"
        ? `${reason} (confidence ${confidence.toFixed(2)} below threshold ${config.confidenceThreshold})`
        : reason,
  }
}

// ============================================================================
// Pending Decision Tracker (for tool.execute.after correlation)
// ============================================================================

interface PendingEntry {
  decision: Decision
  sessionID: string
  _ts: number
}

const pendingDecisions = new Map<string, PendingEntry>()
const MAX_PENDING_AGE_MS = 60_000 // 1 minute TTL to prevent memory leaks

function cleanupStalePending(): void {
  if (pendingDecisions.size === 0) return
  const now = Date.now()
  for (const [key, entry] of pendingDecisions) {
    if (now - entry._ts > MAX_PENDING_AGE_MS) {
      pendingDecisions.delete(key)
    }
  }
}

// ============================================================================
// Lazy Session Creation
// ============================================================================

function createLazySession(client: any): () => Promise<string | null> {
  let promise: Promise<string | null> | null = null

  return async () => {
    if (promise) return promise

    promise = (async () => {
      try {
        const sessionResult = await Promise.race([
          client.session.create({ body: { title: "Safe Auto-Approve Classifier" } }),
          new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error("Session creation timeout")), 10000),
          ),
        ])
        const session = unwrapSdkData(sessionResult)
        return (session as any)?.id ?? null
      } catch (e) {
        try {
          await client.app.log({
            body: {
              service: "safe-auto-approve",
              level: "warn",
              message: "Failed to create classifier session; model fallback disabled",
              extra: { error: String(e) },
            },
          })
        } catch {
          // Ignore logging errors
        }
        return null
      }
    })()

    return promise
  }
}

// ============================================================================
// Logging
// ============================================================================

function redactCommand(command: string): string {
  return command
    .replace(/[A-Z_]*TOKEN\s*=\s*[^\s]+/g, "TOKEN=***")
    .replace(/[A-Z_]*KEY\s*=\s*[^\s]+/g, "KEY=***")
    .replace(/[A-Z_]*SECRET\s*=\s*[^\s]+/g, "SECRET=***")
    .replace(/--token\s+[^\s]+/g, "--token ***")
    .replace(/--api-key\s+[^\s]+/g, "--api-key ***")
    .replace(/Authorization:\s*Bearer\s+[^\s]+/g, "Authorization: Bearer ***")
}

async function logDecision(
  client: any,
  permission: string,
  command: string,
  decision: Decision,
): Promise<void> {
  try {
    await client.app.log({
      body: {
        service: "safe-auto-approve",
        level: "info",
        message: `Permission ${decision.kind}`,
        extra: {
          permission,
          command: redactCommand(command),
          decision: decision.kind,
          source: decision.source,
          confidence: decision.confidence,
          reason: decision.reason,
        },
      },
    })
  } catch {
    // Logging should never break the plugin
  }
}

function truncateText(value: string, maxLength: number): string {
  if (value.length <= maxLength) return value
  return `${value.slice(0, Math.max(0, maxLength - 1))}…`
}

async function showDecisionToast(
  client: any,
  command: string,
  decision: Decision,
): Promise<void> {
  try {
    if (typeof client.tui?.showToast !== "function") return

    const autoApproved = decision.kind === "AUTO_APPROVE"
    const confidence = typeof decision.confidence === "number" ? ` (${Math.round(decision.confidence * 100)}%)` : ""
    const commandText = truncateText(redactCommand(command), 80)
    const reasonText = truncateText(decision.reason, 140)

    await client.tui.showToast({
      body: {
        title: autoApproved ? "Safe Auto-Approve: approved" : "Safe Auto-Approve: asking",
        message: `${commandText}\n${decision.source}${confidence}: ${reasonText}`,
        variant: autoApproved ? "success" : "warning",
        duration: autoApproved ? 6000 : 10000,
      },
    })
  } catch {
    // UI feedback should never affect permission handling
  }
}

// ============================================================================
// Decision Pipeline
// ============================================================================

function normalizeCommand(command: string): string {
  return command.trim().replace(/\s+/g, " ")
}

async function decide(
  command: string,
  client: any,
  config: PluginConfig,
  getSession: () => Promise<string | null>,
): Promise<Decision> {
  const normalized = normalizeCommand(command)

  if (normalized.length > config.maxCommandLength) {
    return { kind: "ASK_USER", source: "rule", reason: "Command exceeds maximum length" }
  }

  const key = cacheKey("bash", normalized)
  const cached = getCached(key)
  if (cached) return { ...cached, reason: `${cached.reason} (cached)` }

  // 1. Deterministic Ask Rules
  const askRule = matchAskRule(normalized)
  if (askRule) {
    if (config.cacheDecisions) setCached(key, askRule)
    return askRule
  }

  // 2. Model Classifier Fallback
  const sessionId = await getSession()
  if (!sessionId) {
    return { kind: "ASK_USER", source: "error", reason: "Classifier session not available" }
  }

  const modelDecision = await classifyWithModel(client, sessionId, normalized, config)

  if (config.cacheDecisions && shouldCache(modelDecision)) setCached(key, modelDecision)
  return modelDecision
}

// ============================================================================
// Permission Reply
// ============================================================================

async function replyOnce(client: any, sessionID: string, requestID: string): Promise<void> {
  try {
    // Try v2 API first
    const v2client = client as any
    if (typeof v2client.permission?.reply === "function") {
      unwrapSdkData(await v2client.permission.reply({
        requestID,
        reply: "once",
      }))
      return
    }

    // Fall back to v1 legacy API
    unwrapSdkData(await client.postSessionIdPermissionsPermissionId({
      path: { id: sessionID, permissionID: requestID },
      body: { response: "once" },
    }))
  } catch {
    // Permission may have already been handled manually
  }
}

async function replyOnceV2(client: any, requestID: string): Promise<void> {
  try {
    unwrapSdkData(await client.permission.reply({ requestID, reply: "once" }))
  } catch {
    // Permission may have already been handled manually
  }
}

// ============================================================================
// Plugin Export
// ============================================================================

export const SafeAutoApprovePlugin: Plugin = async ({ client, serverUrl, directory }) => {
  const config = await loadConfig()
  const getSession = createLazySession(client)
  const v2Client = createOpencodeClientV2({ baseUrl: serverUrl.toString(), directory })

  try {
    await client.app.log({
      body: {
        service: "safe-auto-approve",
        level: "info",
        message: "Plugin initialized",
        extra: { model: config.model, confidenceThreshold: config.confidenceThreshold, timeoutMs: config.timeoutMs },
      },
    })
  } catch {
    // Ignore logging errors
  }

  return {
    event: async ({ event }) => {
      const busEvent = event as any
      if (busEvent.type !== "permission.asked") return

      try {
        await client.app.log({
          body: {
            service: "safe-auto-approve",
            level: "info",
            message: "permission.asked event received",
            extra: { event: JSON.stringify(busEvent) },
          },
        })
      } catch {
        // Ignore logging errors
      }

      const props = busEvent.properties as {
        id: string
        sessionID: string
        permission: string
        patterns: string[]
        tool?: { messageID: string; callID: string }
      }

      // Only handle bash/shell permissions
      if (props.permission !== "bash" && props.permission !== "shell") return

      const command = props.patterns[0] || ""
      if (!command) return

      try {
        await client.app.log({
          body: {
            service: "safe-auto-approve",
            level: "info",
            message: "classifying permission request",
            extra: { permission: props.permission, command: redactCommand(command), requestID: props.id },
          },
        })
      } catch {
        // Ignore logging errors
      }

      const decision = await decide(command, client, config, getSession)

      // Correlate decision with the upcoming tool execution for inline chat annotation
      if (props.tool?.callID) {
        cleanupStalePending()
        pendingDecisions.set(props.tool.callID, { decision, sessionID: props.sessionID, _ts: Date.now() })
      }

      if (config.logDecisions) {
        await logDecision(client, props.permission, command, decision)
      }

      if (config.showDecisionToasts) {
        await showDecisionToast(client, command, decision)
      }

      if (decision.kind === "AUTO_APPROVE") {
        await replyOnceV2(v2Client, props.id)
        await replyOnce(client, props.sessionID, props.id)
      }
    },

    "tool.execute.after": async (input, output) => {
      if (!config.showDecisionInline) return

      // Only annotate bash/shell tool results
      if (input.tool !== "bash" && input.tool !== "shell") return

      // Check if we have a pending decision for this tool call
      const entry = pendingDecisions.get(input.callID)
      if (!entry) return

      pendingDecisions.delete(input.callID)
      const { decision, sessionID } = entry

      // Format decision message
      const approved = decision.kind === "AUTO_APPROVE"
      const confidence = decision.confidence != null
        ? ` (confidence: ${Math.round(decision.confidence * 100)}%)`
        : ""
      const header = approved
        ? "Safe Auto-Approve: approved"
        : "Safe Auto-Approve: asking"

      const message = `${header}\n` +
        `Command: ${redactCommand(input.args?.command ?? input.args?.[0] ?? "unknown")}\n` +
        `Source: ${decision.source}${confidence}\n` +
        `Reason: ${decision.reason}`

      // Inject a visible chat message after the tool result (noReply prevents LLM trigger)
      try {
        await v2Client.session.prompt({
          sessionID,
          parts: [{ type: "text", text: message }],
          noReply: true,
        })
      } catch {
        // Silently ignore — UI feedback is best-effort
      }
    },
  }
}

export default SafeAutoApprovePlugin
export const server = SafeAutoApprovePlugin
