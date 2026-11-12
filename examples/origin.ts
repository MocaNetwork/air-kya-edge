// npm run origin: a stand-in for your site on http://127.0.0.1:8788. It shows the origin's two jobs:
//   1. Refuse anything that did not come through the edge (shared secret, constant-time compare).
//   2. Read X-AIR-Viewer / X-AIR-Claims and decide what to serve (triage).
import { createHash, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage } from "node:http";

try {
  process.loadEnvFile(".dev.vars");
} catch {}
const SECRET = process.env.KYA_ORIGIN_SECRET;
const PORT = Number(process.env.PORT ?? 8788);

const digest = (value: string) => createHash("sha256").update(value).digest();
function fromEdge(req: IncomingMessage): boolean {
  const sent = req.headers["x-kya-origin-secret"];
  return !!SECRET && typeof sent === "string" && timingSafeEqual(digest(sent), digest(SECRET));
}

function claimsOf(req: IncomingMessage): Record<string, unknown> {
  const header = req.headers["x-air-claims"];
  return typeof header === "string" ? JSON.parse(Buffer.from(header, "base64url").toString()) : {};
}

createServer((req, res) => {
  const send = (status: number, body: unknown) => {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(body, null, 2));
  };
  if (!fromEdge(req)) return send(403, { error: "This origin only answers the KYA edge." });

  const path = new URL(req.url ?? "/", "http://origin").pathname;
  const viewer = req.headers["x-air-viewer"] ?? "unchecked";
  const claims = claimsOf(req);

  // Gated by the edge: only eligible callers get here.
  if (path.startsWith("/members/")) return send(200, { page: path, viewer, content: `Members-only report for ${claims.tier} members.` });

  // Triage: one URL, different content per caller class.
  const offer =
    viewer === "eligible"
      ? { prices: "member", discount: "20%", rateLimit: "generous" }
      : viewer === "ineligible"
        ? { prices: "standard", note: "Your proof did not qualify. See /.well-known/air-kya." }
        : { prices: "standard" };
  send(200, { page: path, viewer, ...offer });
}).listen(PORT, "127.0.0.1", () => console.log(`Origin on http://127.0.0.1:${PORT} (secret ${SECRET ? "set" : "MISSING: run npm run setup"})`));
