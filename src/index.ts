/**
 * ground-rules: compile natural-language intent into validated, enforceable agent policy.
 *
 * The output shape is compatible with callgate's definePolicy: a versioned,
 * deny-by-default rule list over tool calls. ground-rules never depends on
 * callgate; any gate that speaks this shape can enforce the compiled policy.
 */

export type Decision =
  | "allow"
  | "deny"
  | "require_approval"
  | "redact"
  | "defer"
  | "escalate"
  | "simulate";

export interface RuleWhere {
  tool?: string;
  reversibility?: string;
  risk?: { gte: number };
  labels?: Record<string, string>;
}

export interface PolicyRule {
  on: "tool.call";
  where: RuleWhere;
  decide: Decision;
  to?: string;
}

export interface CompiledPolicy {
  version: string;
  default: "deny";
  rules: PolicyRule[];
  /** Non-fatal notes from the deterministic compiler (broad matchers, skipped clauses). */
  warnings?: string[];
}

export interface ValidationReport {
  conflicts: Array<{ rules: [number, number]; reason: string }>;
  unreachable: Array<{ rule: number; reason: string }>;
  warnings: string[];
}

const DECISIONS: Decision[] = [
  "allow",
  "deny",
  "require_approval",
  "redact",
  "defer",
  "escalate",
  "simulate",
];

/** Verb (and common inflections) to tool-name glob. First match in a clause wins. */
const VERB_TO_PATTERN: Record<string, string> = {
  read: "read_*",
  fetch: "read_*",
  get: "read_*",
  list: "read_*",
  search: "read_*",
  query: "read_*",
  delete: "delete_*",
  drop: "delete_*",
  destroy: "delete_*",
  remove: "delete_*",
  erase: "delete_*",
  wipe: "delete_*",
  modify: "update_*",
  change: "update_*",
  update: "update_*",
  write: "update_*",
  edit: "update_*",
  touch: "update_*",
  alter: "update_*",
  publish: "publish_*",
  post: "publish_*",
  deploy: "publish_*",
  release: "publish_*",
  send: "send_*",
  email: "send_*",
  notify: "send_*",
  message: "send_*",
  refund: "refund_*",
  charge: "charge_*",
  pay: "pay_*",
  purchase: "purchase_*",
  buy: "buy_*",
  transfer: "transfer_*",
};

function lookupVerb(token: string): string | null {
  const candidates = [token];
  if (token.endsWith("s")) candidates.push(token.slice(0, -1));
  if (token.endsWith("ing")) {
    candidates.push(token.slice(0, -3));
    candidates.push(token.slice(0, -3) + "e");
  }
  for (const c of candidates) {
    const pattern = VERB_TO_PATTERN[c];
    if (pattern) return pattern;
  }
  return null;
}

function findToolPattern(clause: string): { pattern: string; matched: boolean } {
  const tokens = clause.toLowerCase().match(/[a-z]+/g) ?? [];
  for (const token of tokens) {
    const pattern = lookupVerb(token);
    if (pattern) return { pattern, matched: true };
  }
  return { pattern: "*", matched: false };
}

function parseAmountUsd(clause: string): number | null {
  const m = clause.match(/\$\s*([\d,]+(?:\.\d+)?)/);
  if (!m) return null;
  return parseFloat(m[1].replace(/,/g, ""));
}

function baseLabels(clause: string): Record<string, string> {
  const labels: Record<string, string> = {};
  if (/\bproduction\b/i.test(clause)) labels["env"] = "production";
  const amount = parseAmountUsd(clause);
  if (amount !== null) labels["amount_usd_gte"] = String(amount);
  return labels;
}

interface ClauseResult {
  rules: PolicyRule[];
  warnings: string[];
}

function compileClause(clause: string): ClauseResult {
  const warnings: string[] = [];
  const rules: PolicyRule[] = [];
  const { pattern, matched } = findToolPattern(clause);
  const labels = baseLabels(clause);
  const where: RuleWhere = Object.keys(labels).length > 0 ? { tool: pattern, labels } : { tool: pattern };
  if (!matched) {
    warnings.push(`broad matcher "*": no known action verb in clause "${clause}"`);
  }

  const hasNever = /\bnever\b/i.test(clause);
  const withoutAsking = /\bwithout (asking|approval)\b/i.test(clause);
  const needsApproval =
    /\bneeds? approval\b/i.test(clause) ||
    /\brequires? approval\b/i.test(clause) ||
    /\bask (me|us)? ?before\b/i.test(clause);
  const onlyRead = /^\s*only\s+read\b/i.test(clause);
  const escalateMatch = clause.match(/\bescalate\b.*?\bto\s+([a-z][a-z0-9_-]*)/i);
  const redact = /\bredact\b/i.test(clause);

  if (onlyRead) {
    rules.push({ on: "tool.call", where: { tool: "read_*" }, decide: "allow" });
    rules.push({ on: "tool.call", where: { tool: "update_*" }, decide: "deny" });
    rules.push({ on: "tool.call", where: { tool: "delete_*" }, decide: "deny" });
    return { rules, warnings };
  }

  if (escalateMatch) {
    const escWhere: RuleWhere = { tool: pattern };
    if (Object.keys(labels).length > 0) escWhere.labels = labels;
    rules.push({ on: "tool.call", where: escWhere, decide: "escalate", to: escalateMatch[1].toLowerCase() });
    return { rules, warnings };
  }

  if (redact) {
    rules.push({ on: "tool.call", where, decide: "redact" });
    return { rules, warnings };
  }

  if (hasNever && withoutAsking) {
    rules.push({ on: "tool.call", where, decide: "require_approval" });
    return { rules, warnings };
  }

  if (hasNever) {
    rules.push({ on: "tool.call", where, decide: "deny" });
    return { rules, warnings };
  }

  if (needsApproval) {
    rules.push({ on: "tool.call", where, decide: "require_approval" });
    return { rules, warnings };
  }

  warnings.push(`clause not recognized, skipped: "${clause}"`);
  return { rules, warnings };
}

/**
 * Deterministic intent compiler. No network, no LLM, no randomness.
 * Splits input on newlines and periods, then applies pattern handlers per clause.
 */
export function compileRules(text: string): CompiledPolicy {
  const warnings: string[] = [];
  const rules: PolicyRule[] = [];
  const clauses = text
    .split(/[\n.]+/)
    .map((c) => c.trim())
    .filter((c) => c.length > 0);
  for (const clause of clauses) {
    const result = compileClause(clause);
    rules.push(...result.rules);
    warnings.push(...result.warnings);
  }
  if (clauses.length === 0) {
    warnings.push("empty input: no rules compiled; default deny applies to every tool call");
  }
  const policy: CompiledPolicy = { version: "1", default: "deny", rules };
  if (warnings.length > 0) policy.warnings = warnings;
  return policy;
}

/** True when glob a matches every tool name that glob b matches. */
function patternSubsumes(a: string, b: string): boolean {
  if (a === "*") return true;
  if (a === b) return true;
  const aIsPrefix = !a.startsWith("*") && a.endsWith("*");
  if (aIsPrefix) {
    const prefix = a.slice(0, -1);
    if (!b.includes("*")) return b.startsWith(prefix);
    const bIsPrefix = !b.startsWith("*") && b.endsWith("*");
    if (bIsPrefix) return b.slice(0, -1).startsWith(prefix);
  }
  return false;
}

/** True when where-clause a matches a superset of the calls where-clause b matches. */
function whereSubsumes(a: RuleWhere, b: RuleWhere): boolean {
  if (!patternSubsumes(a.tool ?? "*", b.tool ?? "*")) return false;
  const la = a.labels ?? {};
  const lb = b.labels ?? {};
  for (const key of Object.keys(la)) {
    if (!(key in lb) || lb[key] !== la[key]) return false;
  }
  if (a.reversibility !== undefined && a.reversibility !== b.reversibility) return false;
  return true;
}

function ruleKey(rule: PolicyRule): string {
  return JSON.stringify({ on: rule.on, where: rule.where, decide: rule.decide, to: rule.to ?? null });
}

function describeRule(rule: PolicyRule): string {
  return `tool "${rule.where.tool ?? "*"}", decide "${rule.decide}"`;
}

/**
 * Validate a policy for conflicts, shadowed rules, and risky shapes.
 * Assumes first-match-wins evaluation order (the callgate convention):
 * an earlier rule whose matcher subsumes a later rule's matcher means the
 * later rule never fires.
 */
export function validatePolicy(policy: CompiledPolicy): ValidationReport {
  const conflicts: ValidationReport["conflicts"] = [];
  const unreachable: ValidationReport["unreachable"] = [];
  const warnings: string[] = [];
  const rules = policy.rules;

  if (rules.length === 0) {
    warnings.push("policy contains no rules; default deny applies to every tool call");
  }

  const seen = new Map<string, number>();
  const duplicatePairs = new Set<string>();
  rules.forEach((rule, j) => {
    const key = ruleKey(rule);
    if (seen.has(key)) {
      const i = seen.get(key) as number;
      warnings.push(`rule ${j} duplicates rule ${i}`);
      duplicatePairs.add(`${i}:${j}`);
    } else {
      seen.set(key, j);
    }
    if ((rule.where.tool ?? "*") === "*" && rule.decide === "allow") {
      warnings.push(`rule ${j} allows tool "*": overly broad allow, narrow the matcher`);
    }
  });

  for (let i = 0; i < rules.length; i++) {
    for (let j = i + 1; j < rules.length; j++) {
      if (duplicatePairs.has(`${i}:${j}`)) continue;
      const a = rules[i];
      const b = rules[j];
      // Only an earlier rule that subsumes a later rule is suspicious: under
      // first-match-wins the later rule can never fire. A narrower earlier
      // rule followed by a broader later rule is the standard exception
      // pattern (e.g. "production deletes need approval" before "deny all
      // deletes"), not an error.
      if (!whereSubsumes(a.where, b.where)) continue;
      if (a.decide !== b.decide) {
        conflicts.push({
          rules: [i, j],
          reason:
            `rule ${j} (${describeRule(b)}) never fires: shadowed by broader earlier ` +
            `rule ${i} (${describeRule(a)}) with a different decision`,
        });
      } else {
        unreachable.push({
          rule: j,
          reason: `rule ${j} (${describeRule(b)}) never fires: fully shadowed by earlier rule ${i} (${describeRule(a)})`,
        });
      }
    }
  }

  return { conflicts, unreachable, warnings };
}

const MODEL_PROMPT = `You are a policy compiler. Convert the user's natural-language constraints into a JSON policy with EXACTLY this shape:
{"version":"1","default":"deny","rules":[{"on":"tool.call","where":{"tool":"<glob>","labels":{}},"decide":"<decision>"}]}

Constraints:
- "on" is always "tool.call".
- "decide" must be one of: allow, deny, require_approval, redact, defer, escalate, simulate.
- "tool" is a glob: "*" matches every tool, "read_*" matches read_customer, etc.
- "never X" becomes decide "deny". "never X without asking" or "X needs approval" becomes "require_approval".
- "only read X" becomes three rules: allow "read_*", deny "update_*", deny "delete_*".
- Amounts like "$500" become labels: {"amount_usd_gte":"500"}.
- The word "production" becomes labels: {"env":"production"}.
- Output ONLY the JSON object. No markdown fences, no explanation.

Example 1:
Input: "Never delete production data. Refunds over $500 need approval."
Output: {"version":"1","default":"deny","rules":[{"on":"tool.call","where":{"tool":"delete_*","labels":{"env":"production"}},"decide":"deny"},{"on":"tool.call","where":{"tool":"refund_*","labels":{"amount_usd_gte":"500"}},"decide":"require_approval"}]}

Example 2:
Input: "Only read customer records."
Output: {"version":"1","default":"deny","rules":[{"on":"tool.call","where":{"tool":"read_*"},"decide":"allow"},{"on":"tool.call","where":{"tool":"update_*"},"decide":"deny"},{"on":"tool.call","where":{"tool":"delete_*"},"decide":"deny"}]}

Now compile this input.
Input: """`;

function extractJson(raw: string): string {
  const fenced = raw.match(/```(?:json)?\s*([\s\S]*?)```/);
  const candidate = fenced ? fenced[1] : raw;
  const start = candidate.indexOf("{");
  const end = candidate.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) {
    throw new Error("compileWithModel: model did not return a JSON object");
  }
  return candidate.slice(start, end + 1);
}

function normalizePolicy(input: unknown): CompiledPolicy {
  if (typeof input !== "object" || input === null) {
    throw new Error("compileWithModel: model output is not an object");
  }
  const o = input as Record<string, unknown>;
  if (!Array.isArray(o["rules"])) {
    throw new Error("compileWithModel: model output has no rules array");
  }
  const normRules: PolicyRule[] = (o["rules"] as unknown[]).map((r, i) => {
    if (typeof r !== "object" || r === null) {
      throw new Error(`compileWithModel: rule ${i} is not an object`);
    }
    const ro = r as Record<string, unknown>;
    const decide = ro["decide"];
    if (typeof decide !== "string" || !DECISIONS.includes(decide as Decision)) {
      throw new Error(`compileWithModel: rule ${i} has invalid decide ${JSON.stringify(decide)}`);
    }
    const whereRaw = (ro["where"] ?? {}) as Record<string, unknown>;
    const where: RuleWhere = {};
    if (typeof whereRaw["tool"] === "string") where.tool = whereRaw["tool"];
    if (typeof whereRaw["reversibility"] === "string") where.reversibility = whereRaw["reversibility"];
    const riskRaw = whereRaw["risk"];
    if (typeof riskRaw === "object" && riskRaw !== null) {
      const gte = (riskRaw as Record<string, unknown>)["gte"];
      if (typeof gte === "number") where.risk = { gte };
    }
    const labelsRaw = whereRaw["labels"];
    if (typeof labelsRaw === "object" && labelsRaw !== null) {
      const labels: Record<string, string> = {};
      for (const [k, v] of Object.entries(labelsRaw as Record<string, unknown>)) {
        if (typeof v === "string") labels[k] = v;
      }
      where.labels = labels;
    }
    const rule: PolicyRule = { on: "tool.call", where, decide: decide as Decision };
    if (typeof ro["to"] === "string") rule.to = ro["to"];
    return rule;
  });
  return {
    version: typeof o["version"] === "string" ? o["version"] : "1",
    default: "deny",
    rules: normRules,
  };
}

/**
 * Compile intent with an LLM. The prompt is schema-constrained with few-shot
 * examples; the result is parsed, normalized, and validated. Throws when the
 * model produces conflicting rules, because a conflicting policy is worse
 * than no policy. The validator is the safety case: the compiler, human or
 * model, can be wrong.
 */
export async function compileWithModel(
  text: string,
  model: (prompt: string) => Promise<string>,
): Promise<CompiledPolicy> {
  const prompt = `${MODEL_PROMPT}\n${text}\n"""\nOutput:`;
  const raw = await model(prompt);
  const parsed: unknown = JSON.parse(extractJson(raw));
  const policy = normalizePolicy(parsed);
  const report = validatePolicy(policy);
  if (report.conflicts.length > 0) {
    const detail = report.conflicts
      .map((c) => `rules ${c.rules[0]} and ${c.rules[1]}: ${c.reason}`)
      .join("; ");
    throw new Error(`compileWithModel: model produced conflicting rules: ${detail}`);
  }
  return policy;
}

// Re-exported for tests that exercise the prompt builder indirectly.
export const __internal = { MODEL_PROMPT, patternSubsumes, whereSubsumes };
