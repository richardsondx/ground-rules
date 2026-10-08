import { describe, expect, it } from "vitest";
import {
  compileRules,
  compileWithModel,
  validatePolicy,
  type CompiledPolicy,
} from "../src/index.js";

function rule(tool: string, decide: CompiledPolicy["rules"][number]["decide"]): CompiledPolicy["rules"][number] {
  return { on: "tool.call", where: { tool }, decide };
}

describe("compileRules", () => {
  it("'Never touch production without asking' becomes require_approval, not deny", () => {
    const p = compileRules("Never touch production without asking");
    expect(p.rules).toHaveLength(1);
    expect(p.rules[0].decide).toBe("require_approval");
    expect(p.rules[0].where.tool).toBe("update_*");
    expect(p.rules[0].where.labels).toEqual({ env: "production" });
  });

  it("'Never delete customer data' becomes deny on delete_*", () => {
    const p = compileRules("Never delete customer data");
    expect(p.rules).toHaveLength(1);
    expect(p.rules[0].decide).toBe("deny");
    expect(p.rules[0].where.tool).toBe("delete_*");
  });

  it("'Refunds over $500 need approval' becomes require_approval with amount label", () => {
    const p = compileRules("Refunds over $500 need approval");
    expect(p.rules).toHaveLength(1);
    expect(p.rules[0].decide).toBe("require_approval");
    expect(p.rules[0].where.tool).toBe("refund_*");
    expect(p.rules[0].where.labels).toEqual({ amount_usd_gte: "500" });
  });

  it("'Only read customer data' becomes allow read_* plus deny update_*/delete_*", () => {
    const p = compileRules("Only read customer data");
    expect(p.rules).toHaveLength(3);
    expect(p.rules[0]).toMatchObject({ decide: "allow", where: { tool: "read_*" } });
    expect(p.rules[1]).toMatchObject({ decide: "deny", where: { tool: "update_*" } });
    expect(p.rules[2]).toMatchObject({ decide: "deny", where: { tool: "delete_*" } });
  });

  it("parses comma amounts: $1,200 becomes 1200", () => {
    const p = compileRules("Purchases over $1,200 need approval");
    expect(p.rules[0].where.labels).toEqual({ amount_usd_gte: "1200" });
  });

  it("'Ask me before sending emails' becomes require_approval on send_*", () => {
    const p = compileRules("Ask me before sending emails");
    expect(p.rules).toHaveLength(1);
    expect(p.rules[0].decide).toBe("require_approval");
    expect(p.rules[0].where.tool).toBe("send_*");
  });

  it("empty input yields default-deny policy with a warning", () => {
    const p = compileRules("   ");
    expect(p.rules).toHaveLength(0);
    expect(p.default).toBe("deny");
    expect(p.warnings?.length).toBeGreaterThan(0);
  });

  it("unknown verbs fall back to tool '*' with a broad-matcher warning", () => {
    const p = compileRules("Never flurble the database");
    expect(p.rules).toHaveLength(1);
    expect(p.rules[0].decide).toBe("deny");
    expect(p.rules[0].where.tool).toBe("*");
    expect(p.warnings?.join(" ")).toContain("broad matcher");
  });

  it("multi-line input compiles one rule set per clause", () => {
    const p = compileRules("Never delete customer data\nOnly read reports");
    expect(p.rules.length).toBeGreaterThanOrEqual(2);
    expect(p.rules[0].decide).toBe("deny");
  });

  it("'Never publish without approval' becomes require_approval", () => {
    const p = compileRules("Never publish without approval");
    expect(p.rules[0].decide).toBe("require_approval");
    expect(p.rules[0].where.tool).toBe("publish_*");
  });

  it("every policy is deny-by-default at version 1", () => {
    const p = compileRules("Never touch production");
    expect(p.default).toBe("deny");
    expect(p.version).toBe("1");
  });

  it("'Escalate ... to ...' captures the escalation target", () => {
    const p = compileRules("Escalate database changes to security-oncall");
    expect(p.rules[0].decide).toBe("escalate");
    expect(p.rules[0].to).toBe("security-oncall");
  });
});

describe("validatePolicy", () => {
  it("detects a broad deny shadowed by a narrower allow as a conflict", () => {
    const report = validatePolicy({
      version: "1",
      default: "deny",
      rules: [rule("*", "deny"), rule("delete_*", "allow")],
    });
    expect(report.conflicts).toHaveLength(1);
    expect(report.conflicts[0].rules).toEqual([0, 1]);
    expect(report.conflicts[0].reason).toContain("delete_*");
  });

  it("flags a later rule fully shadowed by an earlier same-decision rule as unreachable", () => {
    const report = validatePolicy({
      version: "1",
      default: "deny",
      rules: [rule("*", "deny"), rule("delete_*", "deny")],
    });
    expect(report.conflicts).toHaveLength(0);
    expect(report.unreachable).toHaveLength(1);
    expect(report.unreachable[0].rule).toBe(1);
  });

  it("warns on an overly broad allow of tool '*'", () => {
    const report = validatePolicy({
      version: "1",
      default: "deny",
      rules: [rule("*", "allow")],
    });
    expect(report.warnings.join(" ")).toContain("overly broad allow");
  });

  it("warns when the policy has zero rules", () => {
    const report = validatePolicy({ version: "1", default: "deny", rules: [] });
    expect(report.warnings.join(" ")).toContain("no rules");
  });

  it("warns on exact duplicate rules", () => {
    const report = validatePolicy({
      version: "1",
      default: "deny",
      rules: [rule("read_*", "allow"), rule("read_*", "allow")],
    });
    expect(report.warnings.join(" ")).toContain("duplicates rule 0");
  });

  it("passes a sane read-only policy with no findings", () => {
    const report = validatePolicy({
      version: "1",
      default: "deny",
      rules: [rule("read_*", "allow"), rule("delete_*", "deny")],
    });
    expect(report.conflicts).toHaveLength(0);
    expect(report.unreachable).toHaveLength(0);
    expect(report.warnings).toHaveLength(0);
  });

  it("detects a conflict on the exact same matcher with different decisions", () => {
    const report = validatePolicy({
      version: "1",
      default: "deny",
      rules: [rule("update_*", "deny"), rule("update_*", "require_approval")],
    });
    expect(report.conflicts).toHaveLength(1);
  });

  it("conflict reasons name the shadowed and shadowing rules", () => {
    const report = validatePolicy({
      version: "1",
      default: "deny",
      rules: [rule("*", "deny"), rule("send_*", "allow")],
    });
    expect(report.conflicts[0].reason).toContain("rule 1");
    expect(report.conflicts[0].reason).toContain("rule 0");
  });

  it("does not flag the exception pattern: narrower earlier rule, broader later rule", () => {
    const report = validatePolicy({
      version: "1",
      default: "deny",
      rules: [
        { on: "tool.call", where: { tool: "delete_*", labels: { env: "production" } }, decide: "require_approval" },
        rule("delete_*", "deny"),
      ],
    });
    expect(report.conflicts).toHaveLength(0);
    expect(report.unreachable).toHaveLength(0);
  });

  it("compiled multi-intent output validates with no conflicts", () => {
    const policy = compileRules(
      "Never delete production data without asking.\nOnly read customer records.\nRefunds over $500 need approval.",
    );
    const report = validatePolicy(policy);
    expect(report.conflicts).toHaveLength(0);
  });
});

describe("compileWithModel", () => {
  const validJson = JSON.stringify({
    version: "1",
    default: "deny",
    rules: [{ on: "tool.call", where: { tool: "refund_*" }, decide: "require_approval" }],
  });

  it("parses model JSON into a policy", async () => {
    const p = await compileWithModel("Refunds need approval", async () => validJson);
    expect(p.rules).toHaveLength(1);
    expect(p.rules[0].decide).toBe("require_approval");
    expect(p.default).toBe("deny");
  });

  it("throws when the model produces conflicting rules", async () => {
    const conflicting = JSON.stringify({
      version: "1",
      default: "deny",
      rules: [
        { on: "tool.call", where: { tool: "*" }, decide: "deny" },
        { on: "tool.call", where: { tool: "delete_*" }, decide: "allow" },
      ],
    });
    await expect(compileWithModel("Be safe", async () => conflicting)).rejects.toThrow(/conflict/i);
  });

  it("sends a schema-constrained prompt containing the user text", async () => {
    let seen = "";
    await compileWithModel("Never touch prod", async (prompt: string) => {
      seen = prompt;
      return validJson;
    });
    expect(seen).toContain("Never touch prod");
    expect(seen).toContain("tool.call");
    expect(seen).toContain("require_approval");
  });
});
