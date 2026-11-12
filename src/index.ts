import { policy as policyFor, rules } from "../kya.config.ts";
import type { Env } from "./env.ts";
import { createDidResolver, createKya, type DidDocument, type Kya } from "./kya/index.ts";
import { fromOrigin, originFrom, refuse, toOrigin, type Origin } from "./proxy.ts";
import { modeFor } from "./rules.ts";

export { NonceStore } from "./kya/nonce.ts";

const noStore = { headers: { "Cache-Control": "no-store" } };
const nonces = (env: Env) => env.NONCES.getByName("kya");

// Built once per isolate, so the DID cache survives across requests.
let setup: { env: Env; kya: Kya; origin: Origin } | undefined;
function load(env: Env) {
  if (setup?.env !== env) {
    const pinned: DidDocument[] = env.KYA_PINNED_DIDS ? JSON.parse(env.KYA_PINNED_DIDS) : [];
    const kya = createKya({
      policy: policyFor(env),
      resolveDid: createDidResolver({ pinned }),
      consumeNonce: (nonce) => nonces(env).consume(nonce),
    });
    setup = { env, kya, origin: originFrom(env.ORIGIN_URL, env.KYA_ORIGIN_SECRET) };
  }
  return setup;
}

export default {
  async fetch(request, env): Promise<Response> {
    const { kya, origin } = load(env);
    const { pathname } = new URL(request.url);

    // 1. Agent-facing endpoints: what to prove, and a single-use nonce to prove it with.
    if (pathname === "/.well-known/air-kya" && request.method === "GET") return Response.json(kya.discovery(), noStore);
    if (pathname === "/kya/challenge" && request.method === "POST") {
      const { programId, fieldsToDisclose } = kya.policy;
      return Response.json({ nonce: await nonces(env).issue(60), programId, fieldsToDisclose, expiresInSeconds: 60 }, noStore);
    }

    // 2. Classify the caller, then gate or forward.
    const mode = modeFor(rules, pathname);
    if (mode === "off") return fetch(toOrigin(request, null, origin));
    const decision = await kya.classify(request);
    if (mode === "gate" && decision.viewer !== "eligible") return refuse(decision);
    // Responses for verified callers must never land in a shared cache.
    const init: RequestInit = decision.viewer === "anonymous" ? {} : { cache: "no-store" };
    return fromOrigin(await fetch(toOrigin(request, decision, origin), init), decision);
  },
} satisfies ExportedHandler<Env>;
