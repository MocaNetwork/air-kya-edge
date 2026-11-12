// A local stand-in for an AIR issuer, for tests and local development only. It issues SD-JWT VCs in
// AIR's format (did:web issuer, ES256, cnf.jwk holder key) and presents them the way AIR's
// verify-by-agent does: only the requested claims, plus a key-binding JWT over the site's nonce.
import { SDJwtInstance } from "@sd-jwt/core";
import { base64url, exportJWK, generateKeyPair, importJWK, type JWK } from "jose";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { sha256 } from "../src/kya/verify.ts";
import type { DidDocument } from "../src/kya/index.ts";

export const TEST_ISSUER_DID = "did:web:issuer.kya.test";
export const TEST_VCT = "urn:air-kya-edge:test:membership";
export const TEST_PROGRAM_ID = "local-test-program";

export type TestIssuer = { did: string; kid: string; privateKey: CryptoKey; didDocument: DidDocument };

async function fromJwk(jwk: JWK): Promise<TestIssuer> {
  const kid = `${TEST_ISSUER_DID}#key-1`;
  const { kty, crv, x, y } = jwk;
  return {
    did: TEST_ISSUER_DID,
    kid,
    privateKey: (await importJWK(jwk, "ES256")) as CryptoKey,
    didDocument: {
      id: TEST_ISSUER_DID,
      verificationMethod: [{ id: kid, publicKeyJwk: { kty, crv, x, y } }],
      assertionMethod: [kid],
    },
  };
}

/** A fresh issuer in memory (tests). */
export async function createTestIssuer(): Promise<TestIssuer> {
  const { privateKey } = await generateKeyPair("ES256", { extractable: true });
  return fromJwk(await exportJWK(privateKey));
}

/** The issuer saved in .local/, shared by `npm run setup`, the Worker (.dev.vars) and the example agent. */
export async function loadTestIssuer(dir = ".local"): Promise<TestIssuer> {
  const file = `${dir}/test-issuer.jwk.json`;
  const saved = await readFile(file, "utf8").catch(() => null);
  if (saved) return fromJwk(JSON.parse(saved));
  const { privateKey } = await generateKeyPair("ES256", { extractable: true });
  const jwk = await exportJWK(privateKey);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await writeFile(file, JSON.stringify(jwk), { mode: 0o600 });
  return fromJwk(jwk);
}

const signer = (key: CryptoKey) => async (data: string) =>
  base64url.encode(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(data))));

export type PresentOptions = {
  programId: string;
  nonce: string;
  fieldsToDisclose: string[];
  /** Claims in the credential. Only fieldsToDisclose are revealed. */
  claims?: Record<string, unknown>;
  // Knobs for negative tests:
  iss?: string;
  vct?: string;
  expiresInSeconds?: number;
  signingKey?: CryptoKey;
  aud?: string;
  kbIssuedAt?: number;
  withoutKeyBinding?: boolean;
};

export const DEFAULT_CLAIMS = { tier: "Gold", memberSince: "2024-03-01", email: "member@example.com" };

/** Issue a credential to a fresh holder key and present it. Returns the compact SD-JWT for X-AIR-KYA. */
export async function presentTestCredential(issuer: TestIssuer, options: PresentOptions): Promise<string> {
  const holder = await generateKeyPair("ES256", { extractable: true });
  const { kty, crv, x, y } = await exportJWK(holder.publicKey);
  const sdjwt = new SDJwtInstance({
    hasher: sha256,
    hashAlg: "sha-256",
    signAlg: "ES256",
    signer: signer(options.signingKey ?? issuer.privateKey),
    kbSigner: signer(holder.privateKey),
    kbSignAlg: "ES256",
    saltGenerator: (length) => base64url.encode(crypto.getRandomValues(new Uint8Array(length))),
  });
  const claims = options.claims ?? DEFAULT_CLAIMS;
  const now = Math.floor(Date.now() / 1000);
  const credential = await sdjwt.issue(
    {
      iss: options.iss ?? issuer.did,
      vct: options.vct ?? TEST_VCT,
      iat: now - 5,
      exp: now + (options.expiresInSeconds ?? 3600),
      cnf: { jwk: { kty, crv, x, y } },
      ...claims,
    },
    { _sd: Object.keys(claims) } as never,
    { header: { typ: "dc+sd-jwt", kid: issuer.kid } },
  );
  const frame = Object.fromEntries(options.fieldsToDisclose.map((field) => [field, true]));
  const kb = { payload: { nonce: options.nonce, aud: options.aud ?? options.programId, iat: options.kbIssuedAt ?? now } };
  return sdjwt.present(credential, frame, options.withoutKeyBinding ? undefined : { kb });
}
