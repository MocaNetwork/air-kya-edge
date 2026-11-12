import { importJWK, type JWK } from "jose";
import { fail, KyaError } from "./reasons.ts";

type VerificationMethod = { id: string; publicKeyJwk?: JWK };
export type DidDocument = {
  id?: string;
  verificationMethod?: VerificationMethod[];
  assertionMethod?: Array<string | VerificationMethod>;
};
export type ResolveDid = (did: string) => Promise<DidDocument>;

/** did:web:host[:path] → URL of its DID document. */
export function didWebUrl(did: string): string {
  if (!did.startsWith("did:web:")) fail("did_unresolvable");
  const [host, ...path] = did.slice("did:web:".length).split(":");
  const origin = `https://${decodeURIComponent(host!)}`;
  return path.length ? `${origin}/${path.join("/")}/did.json` : `${origin}/.well-known/did.json`;
}

/**
 * Resolves issuer DID documents. `pinned` documents are used as-is (no network); any other did:web
 * is fetched over HTTPS and cached in memory for `ttlSeconds`. Only issuers in the policy's
 * trustedIssuers are ever resolved.
 */
export function createDidResolver({ pinned = [], ttlSeconds = 300 }: { pinned?: DidDocument[]; ttlSeconds?: number } = {}): ResolveDid {
  const fixed = new Map(pinned.map((doc) => [doc.id, doc]));
  const cache = new Map<string, { doc: DidDocument; until: number }>();
  return async (did) => {
    const doc = fixed.get(did);
    if (doc) return doc;
    const hit = cache.get(did);
    if (hit && hit.until > Date.now()) return hit.doc;
    const res = await fetch(didWebUrl(did), { signal: AbortSignal.timeout(5_000) }).catch(() => null);
    if (!res?.ok) fail("did_unresolvable");
    const fresh = (await res.json()) as DidDocument;
    cache.set(did, { doc: fresh, until: Date.now() + ttlSeconds * 1000 });
    return fresh;
  };
}

/** The issuer's ES256 public key for `kid`, taken from the DID document's assertionMethod. */
export async function issuerKey(did: string, kid: string, resolveDid: ResolveDid) {
  const doc = await resolveDid(did).catch((error) => {
    throw error instanceof KyaError ? error : new KyaError("did_unresolvable");
  });
  if (doc.id !== did) fail("did_mismatch");
  const absolute = (id: string) => (id.startsWith("#") ? `${did}${id}` : id);
  const methods = new Map((doc.verificationMethod ?? []).map((vm) => [absolute(vm.id), vm]));
  const keys = (doc.assertionMethod ?? [])
    .map((ref) => (typeof ref === "string" ? methods.get(absolute(ref)) : ref))
    .filter((vm): vm is VerificationMethod => !!vm?.publicKeyJwk)
    .map((vm) => ({ ...vm.publicKeyJwk!, kid: absolute(vm.id) }));
  // AIR credentials use the full DID URL as kid; older ones only the fragment.
  const fragment = (value?: string) => value?.split("#").pop();
  const jwk = keys.find((k) => k.kid === kid) ?? keys.find((k) => fragment(k.kid) === fragment(kid));
  if (!jwk) fail("unknown_kid");
  return importJWK(jwk, "ES256");
}
