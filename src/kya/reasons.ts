/**
 * How the edge sees a caller:
 * - anonymous:  sent no proof. Not a proof of humanity: people and unverified bots both land here.
 * - ineligible: sent a proof that failed (invalid, untrusted, replayed, or policy not met).
 * - eligible:   sent a valid proof that satisfies the policy.
 */
export type Viewer = "anonymous" | "ineligible" | "eligible";

/** Fixed reason codes. Only these strings ever leave the edge; tokens and library errors never do. */
export type Reason =
  | "no_credential"
  | "policy_satisfied"
  | "policy_not_configured"
  | "invalid_credential"
  | "untrusted_issuer"
  | "did_unresolvable"
  | "did_mismatch"
  | "unknown_kid"
  | "expired"
  | "unexpected_vct"
  | "disclosure_mismatch"
  | "holder_binding_required"
  | "invalid_holder_binding"
  | "nonce_reused_or_unknown"
  | `condition_not_met:${string}`;

export type Decision = {
  viewer: Viewer;
  reason: Reason;
  /** The disclosed claims, only when eligible. Exactly the policy's fieldsToDisclose. */
  claims: Record<string, unknown>;
};

/** Thrown by a check stage; the reason becomes the decision. */
export class KyaError extends Error {
  constructor(readonly reason: Reason) {
    super(reason);
  }
}

export function fail(reason: Reason): never {
  throw new KyaError(reason);
}
