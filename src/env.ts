import type { NonceStore } from "./kya/nonce.ts";

/** Worker bindings and vars (wrangler.jsonc, .dev.vars, `wrangler secret put`). */
export interface Env {
  NONCES: DurableObjectNamespace<NonceStore>;
  /** AIR verification program ID. */
  KYA_PROGRAM_ID: string;
  /** Comma-separated issuer DIDs. */
  KYA_TRUSTED_ISSUERS: string;
  /** Accepted credential type. */
  KYA_VCT: string;
  /** Optional JSON array of DID documents to trust without fetching (local test issuer, or pinning). */
  KYA_PINNED_DIDS?: string;
  /** Optional. Where to forward allowed requests. Empty: the zone's own origin (Worker on a route). */
  ORIGIN_URL?: string;
  /** Optional secret. Sent to the origin so it can refuse traffic that skipped the edge. */
  KYA_ORIGIN_SECRET?: string;
}
