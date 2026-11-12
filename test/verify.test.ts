import assert from "node:assert/strict";
import { test } from "node:test";
import { generateKeyPair } from "jose";
import { createTestIssuer, presentTestCredential, TEST_PROGRAM_ID, TEST_VCT, type PresentOptions } from "../dev/test-issuer.ts";
import { createDidResolver, createKya, definePolicy, verifyPresentation, type Policy } from "../src/kya/index.ts";

const issuer = await createTestIssuer();
const resolveDid = createDidResolver({ pinned: [issuer.didDocument] });
const policy = definePolicy({
  programId: TEST_PROGRAM_ID,
  trustedIssuers: [issuer.did],
  vct: TEST_VCT,
  fieldsToDisclose: ["tier"],
  conditions: [{ attribute: "tier", operator: "in", value: ["Gold", "Platinum"] }],
});

/** In-memory nonce store with the Durable Object's semantics: each issued nonce works once. */
function nonceStore() {
  const issued = new Set<string>();
  return {
    issue: () => {
      const nonce = crypto.randomUUID();
      issued.add(nonce);
      return nonce;
    },
    consume: async (nonce: string) => issued.delete(nonce),
  };
}

async function check(overrides: Partial<PresentOptions> = {}, p: Policy = policy) {
  const nonces = nonceStore();
  const proof = await presentTestCredential(issuer, { programId: p.programId, fieldsToDisclose: p.fieldsToDisclose, nonce: nonces.issue(), ...overrides });
  return verifyPresentation(proof, p, { resolveDid, consumeNonce: nonces.consume });
}

test("a valid Gold presentation is eligible and discloses only tier", async () => {
  assert.deepEqual(await check(), { viewer: "eligible", reason: "policy_satisfied", claims: { tier: "Gold" } });
});

test("no header is anonymous; any header that fails is ineligible", async () => {
  const kya = createKya({ policy, resolveDid, consumeNonce: async () => true });
  assert.equal((await kya.classify(new Request("https://site.test/"))).viewer, "anonymous");
  for (const value of ["", "garbage", "a~", "x".repeat(20_000)]) {
    const decision = await kya.classify(new Request("https://site.test/", { headers: { "X-AIR-KYA": value } }));
    assert.deepEqual(decision, { viewer: "ineligible", reason: "invalid_credential", claims: {} }, value.slice(0, 10));
  }
});

test("AIR's data: URL form is accepted", async () => {
  const nonces = nonceStore();
  const proof = await presentTestCredential(issuer, { programId: policy.programId, fieldsToDisclose: ["tier"], nonce: nonces.issue() });
  const decision = await verifyPresentation(`data:application/dc+sd-jwt,${proof}`, policy, { resolveDid, consumeNonce: nonces.consume });
  assert.equal(decision.viewer, "eligible");
});

const rejections: Array<[string, () => Promise<Partial<PresentOptions>>, string]> = [
  ["untrusted issuer", async () => ({ iss: "did:web:someone-else.test" }), "untrusted_issuer"],
  ["signature by another key", async () => ({ signingKey: (await generateKeyPair("ES256")).privateKey }), "invalid_credential"],
  ["expired credential", async () => ({ expiresInSeconds: -3600 }), "expired"],
  ["wrong credential type", async () => ({ vct: "urn:other" }), "unexpected_vct"],
  ["missing disclosure", async () => ({ fieldsToDisclose: [] }), "disclosure_mismatch"],
  ["extra disclosure", async () => ({ fieldsToDisclose: ["tier", "email"] }), "disclosure_mismatch"],
  ["no key binding", async () => ({ withoutKeyBinding: true }), "holder_binding_required"],
  ["key binding for another program", async () => ({ aud: "another-program" }), "invalid_holder_binding"],
  ["stale key binding", async () => ({ kbIssuedAt: Math.floor(Date.now() / 1000) - 3600 }), "invalid_holder_binding"],
  ["nonce this site never issued", async () => ({ nonce: crypto.randomUUID() }), "nonce_reused_or_unknown"],
  ["tier below policy", async () => ({ claims: { tier: "Silver" } }), "condition_not_met:tier"],
];
for (const [name, overrides, reason] of rejections) {
  test(`rejects ${name} (${reason})`, async () => {
    assert.deepEqual(await check(await overrides()), { viewer: "ineligible", reason, claims: {} });
  });
}

test("a presentation works once: replay is refused", async () => {
  const nonces = nonceStore();
  const proof = await presentTestCredential(issuer, { programId: policy.programId, fieldsToDisclose: ["tier"], nonce: nonces.issue() });
  const deps = { resolveDid, consumeNonce: nonces.consume };
  assert.equal((await verifyPresentation(proof, policy, deps)).viewer, "eligible");
  assert.equal((await verifyPresentation(proof, policy, deps)).reason, "nonce_reused_or_unknown");
});

test("tampered or duplicated disclosures and forged key bindings are refused", async () => {
  const nonces = nonceStore();
  const parts = (await presentTestCredential(issuer, { programId: policy.programId, fieldsToDisclose: ["tier"], nonce: nonces.issue() })).split("~");
  const deps = { resolveDid, consumeNonce: async () => true };
  const [salt] = JSON.parse(Buffer.from(parts[1]!, "base64url").toString());
  const forged = [...parts];
  forged[1] = Buffer.from(JSON.stringify([salt, "tier", "Platinum"])).toString("base64url");
  assert.equal((await verifyPresentation(forged.join("~"), policy, deps)).viewer, "ineligible");
  const duplicated = [parts[0], parts[1], ...parts.slice(1)].join("~");
  assert.equal((await verifyPresentation(duplicated, policy, deps)).reason, "disclosure_mismatch");
  const kb = parts.at(-1)!.split(".");
  const signature = Buffer.from(kb[2]!, "base64url");
  signature[0] = signature[0]! ^ 1;
  kb[2] = signature.toString("base64url");
  assert.equal((await verifyPresentation([...parts.slice(0, -1), kb.join(".")].join("~"), policy, deps)).reason, "invalid_holder_binding");
});

test("an unknown key id in the DID document is refused", async () => {
  const other = await createTestIssuer();
  const resolver = createDidResolver({ pinned: [{ ...other.didDocument, verificationMethod: [] }] });
  const nonces = nonceStore();
  const proof = await presentTestCredential(other, { programId: policy.programId, fieldsToDisclose: ["tier"], nonce: nonces.issue() });
  assert.equal((await verifyPresentation(proof, policy, { resolveDid: resolver, consumeNonce: nonces.consume })).reason, "unknown_kid");
});

test("policy changes flip the decision without code changes", async () => {
  const platinumOnly = { ...policy, conditions: [{ attribute: "tier", operator: "=" as const, value: "Platinum" }] };
  assert.equal((await check({}, platinumOnly)).reason, "condition_not_met:tier");
  assert.equal((await check({ claims: { tier: "Platinum" } }, platinumOnly)).viewer, "eligible");
});

test("an unconfigured policy makes every proof ineligible and says why", async () => {
  const empty = definePolicy({ programId: "", trustedIssuers: [], vct: "", fieldsToDisclose: ["tier"], conditions: [] });
  const kya = createKya({ policy: empty, resolveDid, consumeNonce: async () => true });
  const decision = await kya.classify(new Request("https://site.test/", { headers: { "X-AIR-KYA": "x~y" } }));
  assert.equal(decision.reason, "policy_not_configured");
  assert.equal(kya.discovery().configured, false);
  assert.deepEqual(kya.problems, ["programId is empty", "vct is empty", "trustedIssuers is empty"]);
});
