// Verifies an AIR SD-JWT VC presentation offline, at the edge. Same checks as AIR's backend guide
// (docs.air3.com/products/identity/verify-sd-jwt), on Web Crypto so it runs in Workers and Node.
import { SDJwtInstance, type Hasher } from "@sd-jwt/core";
import { base64url, decodeJwt, decodeProtectedHeader, importJWK, jwtVerify, type JWK, type JWTPayload } from "jose";
import { issuerKey, type ResolveDid } from "./did.ts";
import { unmetCondition, type Policy } from "./policy.ts";
import { fail, KyaError, type Decision } from "./reasons.ts";

export type ConsumeNonce = (nonce: string) => Promise<boolean>;
export type VerifyDeps = { resolveDid: ResolveDid; consumeNonce: ConsumeNonce };
type Key = Awaited<ReturnType<typeof importJWK>>;

const MAX_LENGTH = 16_384;
const DATA_URL_PREFIXES = ["data:application/dc+sd-jwt,", "data:application/vc+sd-jwt,"];

export const sha256: Hasher = async (data, algorithm) => {
  if (algorithm !== "sha-256") throw new Error("unsupported hash");
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
};

type Presentation = {
  issuerJwt: string;
  disclosures: string[];
  /** Empty when the presentation ends in `~` (no key binding). */
  kbJwt: string;
  /** `<issuer-jwt>~<disclosure>~…~`: the part the key-binding JWT's sd_hash covers. */
  withoutKb: string;
};

/** Accepts a compact SD-JWT (`<issuer-jwt>~<disclosures>~<kb-jwt>`) or AIR's `data:` URL form. */
export function parsePresentation(value: string): Presentation {
  const trimmed = value.trim();
  const prefix = DATA_URL_PREFIXES.find((p) => trimmed.startsWith(p));
  const compact = prefix ? trimmed.slice(prefix.length) : trimmed;
  if (!compact || compact.length > MAX_LENGTH) fail("invalid_credential");
  const parts = compact.split("~");
  if (parts.length < 2) fail("invalid_credential");
  return {
    issuerJwt: parts[0]!,
    disclosures: parts.slice(1, -1),
    kbJwt: parts.at(-1)!,
    withoutKb: `${parts.slice(0, -1).join("~")}~`,
  };
}

/** 1. The issuer is on the allowlist; its key comes from its DID document. */
async function checkIssuer(p: Presentation, policy: Policy, resolveDid: ResolveDid) {
  const header = decodeProtectedHeader(p.issuerJwt);
  if (!["dc+sd-jwt", "vc+sd-jwt"].includes(String(header.typ)) || header.alg !== "ES256" || typeof header.kid !== "string")
    fail("invalid_credential");
  // Unverified read, only to pick an issuer from the allowlist. The signature is checked next.
  const { iss } = decodeJwt(p.issuerJwt);
  if (typeof iss !== "string" || !policy.trustedIssuers.includes(iss)) fail("untrusted_issuer");
  return { iss, key: await issuerKey(iss, header.kid, resolveDid) };
}

/** 2. Issuer signature, validity window and credential type. */
async function checkIssuerSignature(p: Presentation, iss: string, key: Key, policy: Policy): Promise<JWTPayload> {
  const { payload } = await jwtVerify(p.issuerJwt, key, {
    algorithms: ["ES256"],
    issuer: iss,
    clockTolerance: policy.skewSeconds,
    requiredClaims: ["iat", "exp", "vct", "cnf"],
  }).catch((error: { code?: string }) => fail(error.code === "ERR_JWT_EXPIRED" ? "expired" : "invalid_credential"));
  if (payload.vct !== policy.vct) fail("unexpected_vct");
  return payload;
}

const disclosureName = (disclosure: string): unknown => {
  const decoded = JSON.parse(new TextDecoder().decode(base64url.decode(disclosure)));
  return Array.isArray(decoded) && decoded.length === 3 ? decoded[1] : null;
};

/** 3. Exactly the requested claims are disclosed, and each one matches a digest the issuer signed. */
async function checkDisclosures(p: Presentation, key: Key, policy: Policy): Promise<Record<string, unknown>> {
  const names = p.disclosures.map(disclosureName);
  const wanted = new Set(policy.fieldsToDisclose);
  const exact = names.length === wanted.size && names.every((n) => typeof n === "string" && wanted.has(n));
  if (!exact || new Set(names).size !== names.length) fail("disclosure_mismatch");

  const sdjwt = new SDJwtInstance({
    hasher: sha256,
    allowedDisclosureHashAlgorithms: ["sha-256"],
    verifier: async (data, signature) => !!(await jwtVerify(`${data}.${signature}`, key, { algorithms: ["ES256"] })),
  });
  const { payload } = await sdjwt
    .verify(p.withoutKb, { requiredClaimKeys: policy.fieldsToDisclose, skewSeconds: policy.skewSeconds })
    .catch(() => fail("invalid_credential"));
  return Object.fromEntries(policy.fieldsToDisclose.map((name) => [name, (payload as Record<string, unknown>)[name]]));
}

/** 4. The key-binding JWT is signed by the holder key in `cnf.jwk`, for this program, recently. Returns its nonce. */
async function checkHolderBinding(p: Presentation, signed: JWTPayload, policy: Policy): Promise<string> {
  const jwk = (signed.cnf as { jwk?: JWK } | undefined)?.jwk;
  if (!p.kbJwt || !jwk || jwk.kty !== "EC" || jwk.crv !== "P-256" || jwk.d) fail("holder_binding_required");
  const holderKey = await importJWK({ kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, "ES256").catch(() =>
    fail("invalid_holder_binding"),
  );
  const { payload } = await jwtVerify(p.kbJwt, holderKey, {
    algorithms: ["ES256"],
    typ: "kb+jwt",
    audience: policy.programId,
    maxTokenAge: policy.maxKbAgeSeconds,
    clockTolerance: policy.skewSeconds,
    requiredClaims: ["iat", "aud", "nonce", "sd_hash"],
  }).catch(() => fail("invalid_holder_binding"));
  const sdHash = base64url.encode(await sha256(p.withoutKb, "sha-256"));
  if (payload.sd_hash !== sdHash || typeof payload.nonce !== "string") fail("invalid_holder_binding");
  return payload.nonce;
}

/**
 * Runs every check in order and returns a decision. Never throws: any failure is an `ineligible`
 * decision with a fixed reason code.
 */
export async function verifyPresentation(value: string, policy: Policy, deps: VerifyDeps): Promise<Decision> {
  try {
    const presentation = parsePresentation(value);
    const { iss, key } = await checkIssuer(presentation, policy, deps.resolveDid);
    const signed = await checkIssuerSignature(presentation, iss, key, policy);
    const claims = await checkDisclosures(presentation, key, policy);
    const nonce = await checkHolderBinding(presentation, signed, policy);
    // 5. The nonce was issued by this site and is spent now, so the presentation cannot be replayed.
    if (!(await deps.consumeNonce(nonce))) fail("nonce_reused_or_unknown");
    // 6. Your conditions on the disclosed claims.
    const unmet = unmetCondition(policy, claims);
    if (unmet) fail(`condition_not_met:${unmet.attribute}`);
    return { viewer: "eligible", reason: "policy_satisfied", claims };
  } catch (error) {
    return { viewer: "ineligible", reason: error instanceof KyaError ? error.reason : "invalid_credential", claims: {} };
  }
}
