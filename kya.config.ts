// The one file to edit: what callers must prove, and where it applies.
import { definePolicy } from "./src/kya/index.ts";
import type { Env } from "./src/env.ts";
import type { Rule } from "./src/rules.ts";

const list = (value = "") => value.split(",").map((s) => s.trim()).filter(Boolean);

/**
 * Mirror of your AIR verification program. Deployment-specific IDs come from Worker vars
 * (wrangler.jsonc, or .dev.vars locally); the claim rules live here, in code review.
 */
export const policy = (env: Env) =>
  definePolicy({
    programId: env.KYA_PROGRAM_ID,
    trustedIssuers: list(env.KYA_TRUSTED_ISSUERS),
    vct: env.KYA_VCT,
    fieldsToDisclose: ["tier"],
    conditions: [{ attribute: "tier", operator: "in", value: ["Gold", "Platinum"] }],
  });

/** First match wins. Unmatched paths pass through without a check. */
export const rules: Rule[] = [
  { path: "/members/*", mode: "gate" },
  { path: "/assets/*", mode: "off" },
  { path: "/*", mode: "triage" },
];
