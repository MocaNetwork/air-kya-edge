// npm run setup: create the local test issuer and a .dev.vars that trusts it.
import { randomBytes } from "node:crypto";
import { access, writeFile } from "node:fs/promises";
import { loadTestIssuer, TEST_PROGRAM_ID, TEST_VCT } from "./test-issuer.ts";

const issuer = await loadTestIssuer();
const exists = await access(".dev.vars").then(() => true, () => false);
if (exists) {
  console.log("Kept existing .dev.vars. Delete it and re-run `npm run setup` to regenerate.");
} else {
  await writeFile(
    ".dev.vars",
    [
      "# Local development only (npm run setup). Trusts the test issuer in .local/.",
      `KYA_PROGRAM_ID=${TEST_PROGRAM_ID}`,
      `KYA_TRUSTED_ISSUERS=${issuer.did}`,
      `KYA_VCT=${TEST_VCT}`,
      `KYA_PINNED_DIDS='${JSON.stringify([issuer.didDocument])}'`,
      "ORIGIN_URL=http://127.0.0.1:8788",
      `KYA_ORIGIN_SECRET=${randomBytes(24).toString("base64url")}`,
      "",
    ].join("\n"),
    { mode: 0o600 },
  );
  console.log("Wrote .dev.vars for the local test issuer.");
}
console.log(`Test issuer: ${issuer.did}`);
console.log("Next: `npm run origin` and `npm run dev` in two terminals, then `npm run agent -- http://127.0.0.1:8787/members/report --fixture`.");
