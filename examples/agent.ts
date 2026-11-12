// npm run agent -- <url> [--fixture] [--tier Silver] [--replay] [--no-proof]
//
// What an agent does to reach a KYA-protected page:
//   1. GET  /.well-known/air-kya   what the site accepts
//   2. POST /kya/challenge         a single-use nonce
//   3. POST AIR verify-by-agent    a presentation of only the requested claims, bound to that nonce
//   4. GET  <url>  X-AIR-KYA: <presentation>
//
// Live AIR: set AIR_AGENT_JWT to an agent session token (docs.air3.com/products/agents/partner-agent-api).
// --fixture: use the local test issuer from `npm run setup` instead of AIR.
import { parseArgs } from "node:util";
import { DEFAULT_CLAIMS, loadTestIssuer, presentTestCredential } from "../dev/test-issuer.ts";

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: { fixture: { type: "boolean" }, tier: { type: "string" }, replay: { type: "boolean" }, "no-proof": { type: "boolean" } },
});
const target = new URL(positionals[0] ?? "http://127.0.0.1:8787/members/report");
const CREDENTIAL_API = process.env.AIR_CREDENTIAL_API ?? "https://credential-testnet.api.sandbox.air3.com";

async function json(url: string | URL, init?: RequestInit) {
  const res = await fetch(url, init);
  if (!res.ok) throw new Error(`${init?.method ?? "GET"} ${url} → ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, any>>;
}

/** Pull the SD-JWT presentation out of a verify-by-agent response. */
function presentationFrom(body: Record<string, any>, programId: string): string | undefined {
  const vc = body.verificationResult?.verifiablePresentation?.verifiableCredential?.[0];
  return (typeof vc === "string" ? vc : vc?.id) ?? body.vp_token?.[programId]?.[0];
}

async function prove(): Promise<string> {
  const site = await json(new URL("/.well-known/air-kya", target));
  const { nonce, programId, fieldsToDisclose } = await json(new URL("/kya/challenge", target), { method: "POST" });
  console.log(`site wants ${fieldsToDisclose.join(", ")} for program ${programId} (issuers: ${site.trustedIssuers.join(", ")})`);

  if (values.fixture) {
    const claims = { ...DEFAULT_CLAIMS, ...(values.tier ? { tier: values.tier } : {}) };
    return presentTestCredential(await loadTestIssuer(), { programId, nonce, fieldsToDisclose, claims });
  }
  const token = process.env.AIR_AGENT_JWT;
  if (!token) throw new Error("Set AIR_AGENT_JWT (an AIR agent session token), or pass --fixture.");
  const result = await json(`${CREDENTIAL_API}/v2/credentials/verify-by-agent`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({ programId, fieldsToDisclose, nonce }),
  });
  const presentation = presentationFrom(result, programId);
  if (!presentation) throw new Error(`AIR returned ${result.verificationResult?.status ?? "no presentation"}`);
  return presentation;
}

async function visit(proof?: string) {
  const res = await fetch(target, { headers: proof ? { "X-AIR-KYA": proof } : {} });
  console.log(`\n${res.status} ${target.pathname}  viewer=${res.headers.get("x-air-viewer")}  reason=${res.headers.get("x-air-reason")}`);
  console.log(await res.text());
}

const proof = values["no-proof"] ? undefined : await prove();
await visit(proof);
if (values.replay && proof) await visit(proof); // same nonce again → nonce_reused_or_unknown
