import assert from "node:assert/strict";
import { test } from "node:test";
import { rules } from "../kya.config.ts";
import type { Decision } from "../src/kya/index.ts";
import { fromOrigin, originFrom, refuse, toOrigin } from "../src/proxy.ts";
import { modeFor } from "../src/rules.ts";

const eligible: Decision = { viewer: "eligible", reason: "policy_satisfied", claims: { tier: "Gold" } };
const anonymous: Decision = { viewer: "anonymous", reason: "no_credential", claims: {} };

test("first matching rule wins; unmatched paths are off", () => {
  assert.equal(modeFor(rules, "/members/report"), "gate");
  assert.equal(modeFor(rules, "/assets/app.js"), "off");
  assert.equal(modeFor(rules, "/pricing"), "triage");
  assert.equal(modeFor([{ path: "/pricing", mode: "gate" }], "/pricing/x"), "off");
});

test("the origin never sees caller-supplied X-AIR-* headers or the proof", () => {
  const spoofed = new Request("https://shop.example/pricing?q=1", {
    headers: { "X-AIR-Viewer": "eligible", "X-AIR-Claims": "e30", "X-AIR-KYA": "proof", "X-KYA-Origin-Secret": "guess", Accept: "text/html" },
  });
  const forwarded = toOrigin(spoofed, anonymous, originFrom("https://origin.example", "s3cret"));
  assert.equal(forwarded.url, "https://origin.example/pricing?q=1");
  assert.equal(forwarded.headers.get("X-AIR-Viewer"), "anonymous");
  assert.equal(forwarded.headers.get("X-AIR-Claims"), null);
  assert.equal(forwarded.headers.get("X-AIR-KYA"), null);
  assert.equal(forwarded.headers.get("X-KYA-Origin-Secret"), "s3cret");
  assert.equal(forwarded.headers.get("Accept"), "text/html");
});

test("eligible callers' claims reach the origin; with no ORIGIN_URL the host is kept", () => {
  const forwarded = toOrigin(new Request("https://shop.example/members/x"), eligible, originFrom(undefined, undefined));
  assert.equal(new URL(forwarded.url).host, "shop.example");
  assert.deepEqual(JSON.parse(Buffer.from(forwarded.headers.get("X-AIR-Claims")!, "base64url").toString()), { tier: "Gold" });
  assert.equal(forwarded.headers.get("X-KYA-Origin-Secret"), null);
});

test("ORIGIN_URL must be https except on localhost", () => {
  assert.throws(() => originFrom("http://origin.example", "s"));
  assert.doesNotThrow(() => originFrom("http://127.0.0.1:8788", "s"));
});

test("responses are labelled, and proof-dependent ones are not cacheable", () => {
  const origin = new Response("ok", { headers: { "Cache-Control": "public, max-age=600" } });
  const forEligible = fromOrigin(origin.clone(), eligible);
  assert.equal(forEligible.headers.get("X-AIR-Viewer"), "eligible");
  assert.equal(forEligible.headers.get("Cache-Control"), "private, no-store");
  assert.match(forEligible.headers.get("Vary")!, /X-AIR-KYA/);
  assert.equal(fromOrigin(origin, anonymous).headers.get("Cache-Control"), "public, max-age=600");
});

test("gate refusals point to discovery", async () => {
  const res = refuse({ viewer: "ineligible", reason: "condition_not_met:tier", claims: {} });
  assert.equal(res.status, 403);
  assert.deepEqual(await res.json(), { error: "kya_required", viewer: "ineligible", reason: "condition_not_met:tier", discovery: "/.well-known/air-kya" });
});
