export type Operator = "=" | "!=" | ">" | ">=" | "<" | "<=" | "in";
export type Condition = { attribute: string; operator: Operator; value: unknown };

/** What a caller must prove. Mirrors an AIR verification program plus edge-side conditions. */
export type Policy = {
  /** AIR verification program ID. Also the expected `aud` of the key-binding JWT. */
  programId: string;
  /** Issuer DIDs (did:web) whose credentials you accept. */
  trustedIssuers: string[];
  /** Credential type (`vct`) you accept. */
  vct: string;
  /** Claims the agent must disclose: exactly these, nothing more. */
  fieldsToDisclose: string[];
  /** Every condition must hold for the caller to be eligible. */
  conditions: Condition[];
  /** Maximum age of the key-binding JWT. */
  maxKbAgeSeconds: number;
  /** Allowed clock skew for iat/exp checks. */
  skewSeconds: number;
};

export type PolicyInput = Omit<Policy, "maxKbAgeSeconds" | "skewSeconds"> &
  Partial<Pick<Policy, "maxKbAgeSeconds" | "skewSeconds">>;

export const definePolicy = (input: PolicyInput): Policy => ({ maxKbAgeSeconds: 300, skewSeconds: 60, ...input });

/** Why a policy cannot be enforced yet. Empty when it is ready. */
export function policyProblems(policy: Policy): string[] {
  const problems: string[] = [];
  if (!policy.programId) problems.push("programId is empty");
  if (!policy.vct) problems.push("vct is empty");
  if (!policy.trustedIssuers.length) problems.push("trustedIssuers is empty");
  if (!policy.fieldsToDisclose.length) problems.push("fieldsToDisclose is empty");
  for (const { attribute } of policy.conditions)
    if (!policy.fieldsToDisclose.includes(attribute)) problems.push(`condition on "${attribute}" is not in fieldsToDisclose`);
  return problems;
}

function holds(actual: unknown, { operator, value }: Condition): boolean {
  switch (operator) {
    case "in":
      return Array.isArray(value) && value.includes(actual);
    case "=":
      return actual === value;
    case "!=":
      return actual !== value;
  }
  if (typeof actual !== "number" || typeof value !== "number") return false;
  switch (operator) {
    case ">":
      return actual > value;
    case ">=":
      return actual >= value;
    case "<":
      return actual < value;
    case "<=":
      return actual <= value;
  }
}

/** The first condition the claims do not satisfy, if any. */
export const unmetCondition = (policy: Policy, claims: Record<string, unknown>) =>
  policy.conditions.find((condition) => !holds(claims[condition.attribute], condition));
