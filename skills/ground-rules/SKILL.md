---
name: ground-rules
description: Compile natural-language agent constraints into validated, enforceable policy rules
---

# ground-rules skill

Use this skill when the user wants an AI agent to follow constraints: approval before destructive actions, read-only access, spending limits, escalation paths.

## What it does

Turns intent like "Never delete production data without asking" into a versioned, deny-by-default policy object that an enforcement gate (for example callgate) can execute. A built-in validator catches conflicting rules, shadowed rules, and risky shapes like allowing every tool.

## Install

npm i ground-rules

## Usage

```ts
import { compileRules, validatePolicy, compileWithModel } from "ground-rules";

// 1. Deterministic compile, no network, no LLM
const policy = compileRules([
  "Never delete production data without asking.",
  "Only read customer records.",
  "Refunds over $500 need approval.",
].join("\n"));
// policy.rules: require_approval on update_* (env=production),
//   allow read_* + deny update_*/delete_*, require_approval on refund_* (amount_usd_gte=500)

// 2. Validate before enforcing
const report = validatePolicy(policy);
// { conflicts: [], unreachable: [], warnings: [] }
// Fix conflicts before deploying. A conflicting policy is worse than no policy.

// 3. Novel phrasing: bring your own model
const policy2 = await compileWithModel("Be careful with the billing system", async (prompt) => {
  // call any LLM here, return its raw text
  return await myLlm.complete(prompt);
});
// throws if the model produced conflicting rules
```

## Policy shape

```ts
{
  version: "1",
  default: "deny",
  rules: [{
    on: "tool.call",
    where: { tool: "read_*", labels: { env: "production" } },
    decide: "allow" | "deny" | "require_approval" | "redact" | "defer" | "escalate" | "simulate",
    to: "escalation-target" // only with decide: "escalate"
  }]
}
```

## Rules of thumb

- Always run validatePolicy on hand-written or model-generated policies before enforcing them.
- "never X without asking" compiles to require_approval, not deny. "never X" alone compiles to deny.
- Amounts become labels (amount_usd_gte); the enforcing gate must evaluate them.
- Prefer the deterministic compileRules for common phrasings; reserve compileWithModel for novel language.
