export type CategoryId =
  | "exposure"
  | "accounts"
  | "recovery"
  | "devices"
  | "network"
  | "finance"
  | "data"
  | "response";
export type AssetKind =
  | "email"
  | "phone"
  | "device"
  | "domain"
  | "financial"
  | "password_manager"
  | "identity"
  | "network";
export type EvidenceStatus =
  | "pass"
  | "partial"
  | "fail"
  | "unknown"
  | "not_applicable";
export type CheckStatus = EvidenceStatus | "stale" | "conflict" | "imported";
export type EvidenceMethod = "guided" | "local" | "provider" | "import";
export type Severity = "critical" | "high" | "medium" | "low";
export type SafeFact = string | number | boolean | null | string[] | number[];
export interface Category {
  id: CategoryId;
  name: string;
  description: string;
  weight: number;
}
export interface Asset {
  id: string;
  kind: AssetKind;
  label: string;
  value?: string;
  critical: boolean;
  recoveryAssetIds?: string[];
}
export type AssetPatch = Partial<
  Pick<Asset, "label" | "value" | "critical" | "recoveryAssetIds">
>;
export interface Evidence {
  id: string;
  checkId: string;
  assetId?: string;
  status: EvidenceStatus;
  method: EvidenceMethod;
  observedAt: string;
  notes?: string;
  facts?: Record<string, SafeFact>;
}
export type EvidenceInput = Omit<Evidence, "id" | "observedAt"> & {
  observedAt?: string;
};
export interface RemediationAction {
  id: string;
  checkId: string;
  assetId?: string;
  status: "planned" | "completed";
  notes?: string;
  createdAt: string;
  updatedAt: string;
}
export interface CheckDefinition {
  id: string;
  categoryId: CategoryId;
  title: string;
  description: string;
  weight: number;
  severity: Severity;
  freshnessDays: number;
  guidance: string[];
  verification: string;
  partialCriteria?: string;
  acceptedMethods: EvidenceMethod[];
  remediation: {
    title: string;
    steps: string[];
    effort: "quick" | "moderate" | "involved";
    lockoutRisk: boolean;
    rollback: string;
  };
  assetKinds?: AssetKind[];
  automated?: string;
  module?: string;
  region?: string;
}
export interface SubjectResult {
  assetId?: string;
  status: CheckStatus;
  evidenceId?: string;
  reason: string;
}
export interface CheckResult extends SubjectResult {
  checkId: string;
  earnedPoints: number;
  maxPoints: number;
  assessed: boolean;
  subjects: SubjectResult[];
}
export interface CategoryResult {
  categoryId: CategoryId;
  score: number | null;
  coverage: number;
  earnedPoints: number;
  maxPoints: number;
  assessedPoints: number;
  checkCount: number;
}
export interface Finding {
  id: string;
  checkId: string;
  assetId?: string;
  severity: Severity;
  title: string;
  description: string;
  kind: "gap" | "verification" | "dependency";
  action: string;
}
export interface Evaluation {
  score: number | null;
  coverage: number;
  categories: CategoryResult[];
  checks: CheckResult[];
  findings: Finding[];
  evaluatedAt: string;
  catalogVersion: string;
  scoreVersion: string;
}
export interface AuditSnapshot {
  id: string;
  createdAt: string;
  evaluation: Evaluation;
  assetIds: string[];
  evidenceIds: string[];
  workspaceName: string;
  settings: Workspace["settings"];
}
export interface ThreatEvent {
  id: string;
  source: "hibp" | "cisa" | "rss" | "web";
  title: string;
  description: string;
  url: string;
  publishedAt: string;
  ingestedAt: string;
  relevance: "unassessed" | "potential" | "confirmed";
  assetId?: string;
  identifiers?: string[];
}
export interface Workspace {
  schemaVersion: 1;
  id: string;
  name: string;
  createdAt: string;
  updatedAt: string;
  assets: Asset[];
  evidence: Evidence[];
  actions: RemediationAction[];
  snapshots: AuditSnapshot[];
  threatEvents: ThreatEvent[];
  settings: { region: string; modules: string[]; monitoring: boolean };
}
export interface DependencyFinding {
  kind: "missing" | "cycle" | "single_point";
  assetIds: string[];
  message: string;
  severity: Severity;
}
export interface ProviderReceipt {
  status: "ok" | "unavailable" | "error";
  message: string;
  retryAfterSeconds?: number;
  /** Fixed public source diagnostics; never includes response bodies or arbitrary exception text. */
  sources?: ProviderSourceDiagnostic[];
}
export interface ProviderSourceDiagnostic {
  source: "cisa" | "hibp";
  status: "ok" | "unavailable";
  httpStatus?: number;
  code?:
    | "http_error"
    | "timeout"
    | "response_too_large"
    | "empty_response"
    | "invalid_json"
    | "invalid_schema"
    | "illegal_invocation"
    | "request_error"
    | "unknown_error";
  errorName?:
    | "Error"
    | "TypeError"
    | "AbortError"
    | "SyntaxError"
    | "ZodError"
    | "UnknownError";
}
export interface Breach {
  name: string;
  title: string;
  domain: string;
  breachDate: string;
  addedDate: string;
  dataClasses: string[];
  verified: boolean;
}
export interface HibpResult {
  receipt: ProviderReceipt;
  breaches: Breach[];
  checkedAt: string;
  scope: string;
  subject: string;
}
export interface ThreatFeedResult {
  receipt: ProviderReceipt;
  events: ThreatEvent[];
  checkedAt: string;
}
export interface ProviderOptions {
  fetch?: typeof fetch;
  now?: string | Date;
  timeoutMs?: number;
}
export interface FootprintResult {
  receipt: ProviderReceipt;
  results: { url: string; title: string; description: string }[];
  checkedAt: string;
  scope: string;
  query: string;
}
