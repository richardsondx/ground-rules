import { compileRules, validatePolicy } from "../src/index.js";

console.log("=== (1) compile a 4-line intent block into enforced policy ===");
const intent = [
  "Never delete production data without asking.",
  "Only read customer records.",
  "Refunds over $500 need approval.",
  "Never publish to social media.",
].join("\n");
console.log("Intent:\n" + intent + "\n");
const policy = compileRules(intent);
console.log("Compiled policy:");
console.log(JSON.stringify(policy, null, 2));

console.log("\n=== (2) validate a hand-written conflicting policy ===");
const handwritten = {
  version: "1",
  default: "deny" as const,
  rules: [
    { on: "tool.call" as const, where: { tool: "*" }, decide: "deny" as const },
    { on: "tool.call" as const, where: { tool: "delete_*" }, decide: "allow" as const },
    { on: "tool.call" as const, where: { tool: "read_*" }, decide: "allow" as const },
    { on: "tool.call" as const, where: { tool: "read_*" }, decide: "allow" as const },
  ],
};
const report = validatePolicy(handwritten);
console.log("Validation report:");
console.log(JSON.stringify(report, null, 2));
