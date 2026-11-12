import type { Policy } from "./policy.ts";

/** Published at /.well-known/air-kya: everything an agent needs to produce an accepted proof. */
export function discovery(policy: Policy, problems: string[]) {
  return {
    kya: "AIR SD-JWT VC presentation, key-bound to a single-use nonce from this site",
    ...(problems.length ? { configured: false, problems } : {}),
    header: "X-AIR-KYA",
    challenge: "/kya/challenge",
    programId: policy.programId,
    fieldsToDisclose: policy.fieldsToDisclose,
    vct: policy.vct,
    trustedIssuers: policy.trustedIssuers,
    conditions: policy.conditions,
    steps: [
      "POST /kya/challenge → { nonce, programId, fieldsToDisclose }",
      "POST <AIR Credential API>/v2/credentials/verify-by-agent { programId, fieldsToDisclose, nonce } with your agent JWT",
      "Send verificationResult.verifiablePresentation.verifiableCredential[0] in the X-AIR-KYA request header",
      "Each nonce works once: repeat for every gated request",
    ],
    docs: "https://docs.air3.com/products/agents/edge-gating-cloudflare",
  };
}
