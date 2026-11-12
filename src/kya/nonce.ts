import { DurableObject } from "cloudflare:workers";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Single-use challenges. A Durable Object makes `consume` atomic, so two concurrent requests
 * carrying the same presentation cannot both pass. Expired nonces are swept by an alarm.
 */
export class NonceStore extends DurableObject {
  async issue(ttlSeconds = 60): Promise<string> {
    const nonce = crypto.randomUUID();
    await this.ctx.storage.put(nonce, Date.now() + ttlSeconds * 1000);
    if ((await this.ctx.storage.getAlarm()) === null) await this.ctx.storage.setAlarm(Date.now() + 60_000);
    return nonce;
  }

  /** True once per issued, unexpired nonce; false for anything else. */
  async consume(nonce: string): Promise<boolean> {
    if (!UUID.test(nonce)) return false;
    return this.ctx.storage.transaction(async (tx) => {
      const expiry = await tx.get<number>(nonce);
      await tx.delete(nonce);
      return typeof expiry === "number" && expiry > Date.now();
    });
  }

  async alarm(): Promise<void> {
    const entries = await this.ctx.storage.list<number>();
    const expired = [...entries].filter(([, expiry]) => expiry <= Date.now()).map(([key]) => key);
    if (expired.length) await this.ctx.storage.delete(expired);
    if (entries.size > expired.length) await this.ctx.storage.setAlarm(Date.now() + 60_000);
  }
}
