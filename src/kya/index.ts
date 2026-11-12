// KYA (Know Your Agent): classify a request by the AIR credential proof it carries.
// Framework-agnostic: works with any runtime that has fetch and Web Crypto. Only nonce.ts is
// Cloudflare-specific; pass your own consumeNonce to use another store.
import { discovery } from "./discovery.ts";
import { type ResolveDid } from "./did.ts";
import { policyProblems, type Policy } from "./policy.ts";
import { type Decision } from "./reasons.ts";
import { verifyPresentation, type ConsumeNonce } from "./verify.ts";

export const KYA_HEADER = "X-AIR-KYA";

export function createKya({ policy, resolveDid, consumeNonce }: { policy: Policy; resolveDid: ResolveDid; consumeNonce: ConsumeNonce }) {
  const problems = policyProblems(policy);
  return {
    policy,
    problems,
    /** No header → anonymous. A header that fails any check → ineligible. A passing proof → eligible. */
    async classify(request: Request): Promise<Decision> {
      const proof = request.headers.get(KYA_HEADER);
      if (proof === null) return { viewer: "anonymous", reason: "no_credential", claims: {} };
      if (problems.length) return { viewer: "ineligible", reason: "policy_not_configured", claims: {} };
      return verifyPresentation(proof, policy, { resolveDid, consumeNonce });
    },
    discovery: () => discovery(policy, problems),
  };
}

export type Kya = ReturnType<typeof createKya>;
export { createDidResolver, didWebUrl, type DidDocument, type ResolveDid } from "./did.ts";
export { definePolicy, policyProblems, type Condition, type Operator, type Policy, type PolicyInput } from "./policy.ts";
export type { Decision, Reason, Viewer } from "./reasons.ts";
export { parsePresentation, verifyPresentation, type ConsumeNonce } from "./verify.ts";
