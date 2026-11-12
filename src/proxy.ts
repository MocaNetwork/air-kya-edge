import { base64url } from "jose";
import type { Decision } from "./kya/index.ts";

export const ORIGIN_SECRET_HEADER = "X-KYA-Origin-Secret";
export type Origin = { url?: URL; secret?: string };

/** Validates ORIGIN_URL. Throws on an unsafe value so a misconfigured edge fails closed. */
export function originFrom(originUrl: string | undefined, secret: string | undefined): Origin {
  if (!originUrl) return { secret };
  const url = new URL(originUrl);
  const local = ["127.0.0.1", "localhost"].includes(url.hostname);
  if (url.protocol !== "https:" && !(local && url.protocol === "http:")) throw new Error("ORIGIN_URL must be https");
  return { url, secret };
}

/**
 * The request the origin receives. Caller-supplied X-AIR-* and secret headers are dropped (including
 * the proof itself), then the edge's decision is attached. The origin can trust these headers only
 * because nobody else can set them: lock it to the edge with the shared secret.
 */
export function toOrigin(request: Request, decision: Decision | null, origin: Origin): Request {
  const url = new URL(request.url);
  if (origin.url) {
    url.protocol = origin.url.protocol;
    url.host = origin.url.host;
  }
  const forwarded = new Request(url, request);
  const reserved = [...forwarded.headers.keys()].filter((name) => name.startsWith("x-air-") || name === ORIGIN_SECRET_HEADER.toLowerCase());
  for (const name of reserved) forwarded.headers.delete(name);
  if (decision) {
    forwarded.headers.set("X-AIR-Viewer", decision.viewer);
    forwarded.headers.set("X-AIR-Reason", decision.reason);
    if (decision.viewer === "eligible") forwarded.headers.set("X-AIR-Claims", encodeClaims(decision.claims));
  }
  if (origin.secret) forwarded.headers.set(ORIGIN_SECRET_HEADER, origin.secret);
  return forwarded;
}

/** Disclosed claims as base64url JSON (header-safe). Decode: JSON.parse(Buffer.from(value, "base64url")). */
export const encodeClaims = (claims: Record<string, unknown>) => base64url.encode(JSON.stringify(claims));

/** The origin's response, labelled with the decision. Proof-dependent responses are never cached. */
export function fromOrigin(response: Response, decision: Decision): Response {
  const labelled = new Response(response.body, response);
  labelled.headers.set("X-AIR-Viewer", decision.viewer);
  labelled.headers.set("X-AIR-Reason", decision.reason);
  labelled.headers.append("Vary", "X-AIR-KYA");
  if (decision.viewer !== "anonymous") labelled.headers.set("Cache-Control", "private, no-store");
  return labelled;
}

/** Gate refusal. Points the caller at discovery so an agent can learn what to prove. */
export function refuse(decision: Decision): Response {
  return Response.json(
    { error: "kya_required", viewer: decision.viewer, reason: decision.reason, discovery: "/.well-known/air-kya" },
    {
      status: 403,
      headers: {
        "Cache-Control": "no-store",
        Link: '</.well-known/air-kya>; rel="service-desc"',
        "X-AIR-Viewer": decision.viewer,
        "X-AIR-Reason": decision.reason,
      },
    },
  );
}
