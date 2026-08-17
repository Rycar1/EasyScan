export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: string;
  url: string;
  method: string;
  description: string;
  evidence: string;
  remediation: string;
  tags: string[];
  observedAt: string;
}

/**
 * A session-only request / response pair captured while a finding was
 * observed.  The desktop UI intentionally renders this verbatim so analysts
 * can reproduce the evidence without switching to a separate inspector.
 */
export interface FindingEvidence {
  id: string;
  findingId: string;
  observedAt: string;
  source: string;
  request: string;
  response: string;
}

export interface TrafficSummary {
  id: string;
  observedAt: string;
  source: string;
  method: string;
  url: string;
  status: number;
  contentType: string;
  findings: string[];
  fingerprints: string[];
}

export interface RuntimeLog {
  id: string;
  createdAt: string;
  level: string;
  component: string;
  message: string;
}

export interface PassiveLogSummary {
  doneHttp: number;
  undoHttp: number;
  undoPort: number;
  undoTask: number;
  requestsDone: number;
  requestsTotal: number;
  fingerprints: number;
  vulnerabilities: number;
}

export interface Endpoint {
  method: string;
  path: string;
  parameters: string[];
  sources: string[];
}

export interface Asset {
  host: string;
  urls: string[];
  fingerprints: string[];
  fingerprintEvidence: FingerprintEvidence[];
  endpoints: Endpoint[];
  lastSeen: string;
}

export interface FingerprintEvidence {
  fingerprint: string;
  sources: string[];
  confidence: string;
  score: number;
}

export interface FingerprintAssociation {
  fingerprint: string;
  count: number;
}

export interface FingerprintRuleQuality {
  fingerprint: string;
  hits: number;
  assets: number;
  confidence: string;
  lastSeen: string;
  cooccurrences: FingerprintAssociation[];
}

export interface HFingerStats {
  source: string;
  customDir: string;
  loaded: number;
  products: number;
  builtinRules: number;
  customRules: number;
  customFiles: number;
  failedFiles: number;
  errors: string[];
}

export interface ActiveTask {
  id: string;
  kind: string;
  target: string;
  status: string;
  createdAt: string;
  startedAt: string;
  finishedAt: string;
  error: string;
  summary: Record<string, number>;
}

export interface TaskResult {
  id: string;
  taskId: string;
  kind: string;
  target: string;
  status: string;
  detail: string;
  metadata: Record<string, string>;
  observedAt: string;
}

export interface Feature {
  id: string;
  enabled: boolean;
  locked: boolean;
  label?: string;
  description?: string;
  kind?: string;
  level?: number;
  min?: number;
  max?: number;
}

export interface ServiceStatus {
  running: boolean | null;
  proxyAddress: string;
  apiAddress: string;
  message: string;
}

export interface Snapshot {
  status: ServiceStatus;
  logs: RuntimeLog[];
  passiveLogSummary: PassiveLogSummary;
  traffic: TrafficSummary[];
  findings: Finding[];
  assets: Asset[];
  fingerprintQuality: FingerprintRuleQuality[];
  tasks: ActiveTask[];
  features: Feature[];
  passiveSQLiErrorEnabled: boolean | null;
  passiveSQLiBooleanEnabled: boolean | null;
  passiveSQLiTimeEnabled: boolean | null;
  passiveSQLiProbeQPS: number | null;
  passiveSQLiMaxRequests: number | null;
  passiveSQLiMaxParameters: number | null;
  passiveXSSProbeQPS: number | null;
  passiveXSSMaxRequests: number | null;
  passiveXSSMaxParameters: number | null;
  passivePOCQPS: number | null;
  passivePOCConcurrency: number | null;
  passiveFileProbeQPS: number | null;
  passiveFileProbeMaxPrefixes: number | null;
  passiveFastjsonProbeQPS: number | null;
  passiveShiroProbeQPS: number | null;
  passiveCmdProbeQPS: number | null;
  passiveSSRFProbeQPS: number | null;
  passiveXXEProbeQPS: number | null;
  passiveUploadProbeQPS: number | null;
  oobDomain: string;
  shiroKeys: string[];
  hfinger: HFingerStats;
  excludedDomains: string[];
  excludedSuffixes: string[];
  excludedContentTypes: string[];
  excludedPaths: string[];
  excludedQueryParameters: string[];
  excludedPostParameters: string[];
  swaggerExcludedPaths: string[];
  fileProbeCustomPaths: string[];
}

export interface TaskRequest {
  kind: string;
  target: string;
  session_headers: Record<string, string>;
}

type UnknownRecord = Record<string, unknown>;

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function record(value: unknown): UnknownRecord {
  return isRecord(value) ? value : {};
}

function valueOf(source: UnknownRecord, ...keys: string[]): unknown {
  for (const key of keys) {
    if (key in source) {
      return source[key];
    }
  }
  return undefined;
}

function text(source: UnknownRecord, ...keys: string[]): string {
  const value = valueOf(source, ...keys);
  return typeof value === "string" ? value : value == null ? "" : String(value);
}

function bool(source: UnknownRecord, ...keys: string[]): boolean | null {
  const value = valueOf(source, ...keys);
  return typeof value === "boolean" ? value : null;
}

function numeric(source: UnknownRecord, ...keys: string[]): number | null {
  const value = valueOf(source, ...keys);
  const numberValue = typeof value === "number" ? value : Number(value);
  return Number.isFinite(numberValue) ? numberValue : null;
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.map((item) => String(item)).filter(Boolean) : [];
}

function normalizeFingerprintName(value: string): string {
  return value.trim().replace(/^KScan\s*·\s*/iu, "").trim();
}

function normalizeFingerprintLogMessage(value: string): string {
  return value.replace(/^(\s*识别指纹：\s*)KScan\s*·\s*/iu, "$1");
}

function records(value: unknown): UnknownRecord[] {
  return Array.isArray(value) ? value.filter(isRecord) : [];
}

function stringMap(value: unknown): Record<string, string> {
  if (!isRecord(value)) {
    return {};
  }

  return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [key, typeof entry === "string" ? entry : String(entry)]),
  );
}

function numberMap(value: unknown): Record<string, number> {
  if (!isRecord(value)) {
    return {};
  }

  return Object.fromEntries(
    Object.entries(value)
      .map(([key, entry]) => [key, Number(entry)] as const)
      .filter(([, entry]) => Number.isFinite(entry)),
  );
}

function normalizeSeverity(value: string): Severity {
  const normalized = value.trim().toLowerCase();
  if (normalized === "critical" || normalized === "high" || normalized === "medium" || normalized === "low") {
    return normalized;
  }
  return "info";
}

function normalizeFinding(source: UnknownRecord): Finding {
  return {
    id: text(source, "id", "ID"),
    ruleId: text(source, "rule_id", "ruleId", "RuleID"),
    title: text(source, "title", "Title") || "未命名发现",
    severity: normalizeSeverity(text(source, "severity", "Severity")),
    confidence: text(source, "confidence", "Confidence"),
    url: text(source, "url", "URL"),
    method: text(source, "method", "Method"),
    description: text(source, "description", "Description"),
    evidence: text(source, "evidence", "Evidence"),
    remediation: text(source, "remediation", "Remediation"),
    tags: strings(valueOf(source, "tags", "Tags")),
    observedAt: text(source, "observed_at", "observedAt", "ObservedAt"),
  };
}

function normalizeFindingEvidence(source: UnknownRecord, findingId = ""): FindingEvidence {
  return {
    id: text(source, "id", "ID"),
    findingId: text(source, "finding_id", "findingId", "FindingID") || findingId,
    observedAt: text(source, "observed_at", "observedAt", "ObservedAt"),
    source: text(source, "source", "Source"),
    request: text(source, "request", "Request"),
    response: text(source, "response", "Response"),
  };
}

export function normalizeFindingEvidenceList(value: unknown, findingId = ""): FindingEvidence[] {
  if (Array.isArray(value)) {
    return records(value).map((item) => normalizeFindingEvidence(item, findingId));
  }

  if (!isRecord(value)) {
    return [];
  }

  // Accept a keyed payload too.  This is useful while upgrading a running
  // desktop instance from the previous snapshot-backed representation.
  return Object.entries(value).flatMap(([key, items]) => records(items).map((item) => normalizeFindingEvidence(item, key)));
}

function normalizeTraffic(source: UnknownRecord): TrafficSummary {
  return {
    id: text(source, "id", "ID"),
    observedAt: text(source, "observed_at", "observedAt", "ObservedAt"),
    source: text(source, "source", "Source"),
    method: text(source, "method", "Method"),
    url: text(source, "url", "URL"),
    status: numeric(source, "status", "Status") ?? 0,
    contentType: text(source, "content_type", "contentType", "ContentType"),
    findings: strings(valueOf(source, "findings", "Findings")),
    fingerprints: strings(valueOf(source, "fingerprints", "Fingerprints")).map(normalizeFingerprintName).filter(Boolean),
  };
}

function normalizeRuntimeLog(source: UnknownRecord): RuntimeLog {
  const component = text(source, "component", "Component");
  const message = text(source, "message", "Message");
  return {
    id: text(source, "id", "ID"),
    createdAt: text(source, "created_at", "createdAt", "CreatedAt"),
    level: text(source, "level", "Level"),
    component,
    message: component.trim().toLowerCase() === "fingerprint" ? normalizeFingerprintLogMessage(message) : message,
  };
}

export function normalizeRuntimeLogs(value: unknown): RuntimeLog[] {
  return records(value).map(normalizeRuntimeLog);
}

function nonNegativeInteger(value: number | null): number {
  return Math.max(0, Math.round(value ?? 0));
}

function normalizePassiveLogSummary(value: unknown): PassiveLogSummary {
  const source = record(value);
  return {
    doneHttp: nonNegativeInteger(numeric(source, "done_http", "doneHttp", "DoneHTTP")),
    undoHttp: nonNegativeInteger(numeric(source, "undo_http", "undoHttp", "UndoHTTP")),
    undoPort: nonNegativeInteger(numeric(source, "undo_port", "undoPort", "UndoPort")),
    undoTask: nonNegativeInteger(numeric(source, "undo_task", "undoTask", "UndoTask")),
    requestsDone: nonNegativeInteger(numeric(source, "requests_done", "requestsDone", "RequestsDone")),
    requestsTotal: nonNegativeInteger(numeric(source, "requests_total", "requestsTotal", "RequestsTotal")),
    fingerprints: nonNegativeInteger(numeric(source, "fingerprints", "Fingerprints")),
    vulnerabilities: nonNegativeInteger(numeric(source, "vulnerabilities", "vulnerabilities", "Vulnerabilities")),
  };
}

function normalizeEndpoint(source: UnknownRecord): Endpoint {
  return {
    method: text(source, "method", "Method"),
    path: text(source, "path", "Path"),
    parameters: strings(valueOf(source, "parameters", "Parameters")),
    sources: strings(valueOf(source, "sources", "Sources")),
  };
}

function normalizeFingerprintEvidence(source: UnknownRecord): FingerprintEvidence {
  return {
    fingerprint: normalizeFingerprintName(text(source, "fingerprint", "Fingerprint")),
    sources: strings(valueOf(source, "sources", "Sources")),
    confidence: text(source, "confidence", "Confidence"),
    score: numeric(source, "score", "Score") ?? 0,
  };
}

function normalizeFingerprintAssociation(source: UnknownRecord): FingerprintAssociation {
  return {
    fingerprint: normalizeFingerprintName(text(source, "fingerprint", "Fingerprint")),
    count: numeric(source, "count", "Count") ?? 0,
  };
}

function normalizeFingerprintQuality(source: UnknownRecord): FingerprintRuleQuality {
  return {
    fingerprint: normalizeFingerprintName(text(source, "fingerprint", "Fingerprint")),
    hits: numeric(source, "hits", "Hits") ?? 0,
    assets: numeric(source, "assets", "Assets") ?? 0,
    confidence: text(source, "confidence", "Confidence"),
    lastSeen: text(source, "last_seen", "lastSeen", "LastSeen"),
    cooccurrences: records(valueOf(source, "cooccurrences", "Cooccurrences")).map(normalizeFingerprintAssociation),
  };
}

function normalizeAsset(source: UnknownRecord): Asset {
  return {
    host: text(source, "host", "Host"),
    urls: strings(valueOf(source, "urls", "URLs")),
    fingerprints: strings(valueOf(source, "fingerprints", "Fingerprints")).map(normalizeFingerprintName).filter(Boolean),
    fingerprintEvidence: records(valueOf(source, "fingerprint_evidence", "fingerprintEvidence", "FingerprintEvidence")).map(normalizeFingerprintEvidence).filter((item) => Boolean(item.fingerprint)),
    endpoints: records(valueOf(source, "endpoints", "Endpoints")).map(normalizeEndpoint),
    lastSeen: text(source, "last_seen", "lastSeen", "LastSeen"),
  };
}

function normalizeTask(source: UnknownRecord): ActiveTask {
  return {
    id: text(source, "id", "ID"),
    kind: text(source, "kind", "Kind"),
    target: text(source, "target", "Target"),
    status: text(source, "status", "Status"),
    createdAt: text(source, "created_at", "createdAt", "CreatedAt"),
    startedAt: text(source, "started_at", "startedAt", "StartedAt"),
    finishedAt: text(source, "finished_at", "finishedAt", "FinishedAt"),
    error: text(source, "error", "Error"),
    summary: numberMap(valueOf(source, "summary", "Summary")),
  };
}

export function normalizeTaskResults(value: unknown): TaskResult[] {
  return records(value).map((source) => ({
    id: text(source, "id", "ID"),
    taskId: text(source, "task_id", "taskId", "TaskID"),
    kind: text(source, "kind", "Kind"),
    target: text(source, "target", "Target"),
    status: text(source, "status", "Status"),
    detail: text(source, "detail", "Detail"),
    metadata: stringMap(valueOf(source, "metadata", "Metadata")),
    observedAt: text(source, "observed_at", "observedAt", "ObservedAt"),
  }));
}

function normalizeFeatures(value: unknown): Feature[] {
  if (Array.isArray(value)) {
    return records(value).map((source) => ({
      id: text(source, "id", "ID", "key", "Key"),
      enabled: bool(source, "enabled", "Enabled") ?? false,
      locked: bool(source, "locked", "Locked") ?? false,
      label: text(source, "label", "Label", "title", "Title") || undefined,
      description: text(source, "description", "Description") || undefined,
      kind: text(source, "kind", "Kind") || undefined,
      level: numeric(source, "level", "Level") ?? undefined,
      min: numeric(source, "min", "Min") ?? undefined,
      max: numeric(source, "max", "Max") ?? undefined,
    })).filter((feature) => feature.id);
  }

  if (!isRecord(value)) {
    return [];
  }

  return Object.entries(value).map(([id, definition]) => {
    if (typeof definition === "boolean") {
      return {id, enabled: definition, locked: false};
    }
    const source = record(definition);
    return {
      id,
      enabled: bool(source, "enabled", "Enabled") ?? false,
      locked: bool(source, "locked", "Locked") ?? false,
      label: text(source, "label", "Label", "title", "Title") || undefined,
      description: text(source, "description", "Description") || undefined,
      kind: text(source, "kind", "Kind") || undefined,
      level: numeric(source, "level", "Level") ?? undefined,
      min: numeric(source, "min", "Min") ?? undefined,
      max: numeric(source, "max", "Max") ?? undefined,
    };
  });
}

function normalizeStatus(value: unknown): ServiceStatus {
  const source = record(value);
  const services = record(valueOf(source, "services", "Services"));
  const running = bool(source, "running", "Running", "services_running", "servicesRunning")
    ?? bool(services, "running", "Running");

  return {
    running,
    proxyAddress: text(source, "proxy_address", "proxyAddress", "proxy", "Proxy")
      || text(services, "proxy_address", "proxyAddress", "proxy", "Proxy"),
    apiAddress: text(source, "api_address", "apiAddress", "api", "API")
      || text(services, "api_address", "apiAddress", "api", "API"),
    message: text(source, "message", "Message", "detail", "Detail"),
  };
}

export function normalizeSnapshot(value: unknown): Snapshot {
  const source = record(value);
  const features = normalizeFeatures(valueOf(source, "features", "Features"));
  const status = normalizeStatus(valueOf(source, "status", "Status"));
  const legacyLevel = numeric(source, "sqli_level", "sqliLevel", "SQLiLevel");
  const passiveSQLiErrorEnabled = bool(source, "passive_sqli_error_enabled", "passiveSQLiErrorEnabled", "SQLiErrorEnabled")
    ?? (legacyLevel === null ? null : legacyLevel >= 1);
  const passiveSQLiBooleanEnabled = bool(source, "passive_sqli_boolean_enabled", "passiveSQLiBooleanEnabled", "SQLiBooleanEnabled")
    ?? (legacyLevel === null ? null : legacyLevel >= 2);
  const passiveSQLiTimeEnabled = bool(source, "passive_sqli_time_enabled", "passiveSQLiTimeEnabled", "SQLiTimeEnabled")
    ?? (legacyLevel === null ? null : legacyLevel >= 3);
  const passiveSQLiProbeQPS = numeric(source, "passive_sqli_probe_qps", "passiveSQLiProbeQPS", "PassiveSQLiProbeQPS");
  const passiveSQLiMaxRequests = numeric(source, "passive_sqli_max_requests", "passiveSQLiMaxRequests", "PassiveSQLiMaxRequests");
  const passiveSQLiMaxParameters = numeric(source, "passive_sqli_max_parameters", "passiveSQLiMaxParameters", "PassiveSQLiMaxParameters");
  const passiveXSSProbeQPS = numeric(source, "passive_xss_probe_qps", "passiveXSSProbeQPS", "PassiveXSSProbeQPS");
  const passiveXSSMaxRequests = numeric(source, "passive_xss_max_requests", "passiveXSSMaxRequests", "PassiveXSSMaxRequests");
  const passiveXSSMaxParameters = numeric(source, "passive_xss_max_parameters", "passiveXSSMaxParameters", "PassiveXSSMaxParameters");
  const passivePOCQPS = numeric(source, "passive_poc_qps", "passivePOCQPS", "PassivePOCQPS");
  const passivePOCConcurrency = numeric(source, "passive_poc_concurrency", "passivePOCConcurrency", "PassivePOCConcurrency");
  const passiveFileProbeQPS = numeric(source, "passive_file_probe_qps", "passiveFileProbeQPS", "PassiveFileProbeQPS");
  const passiveFileProbeMaxPrefixes = numeric(source, "passive_file_probe_max_prefixes", "passiveFileProbeMaxPrefixes", "PassiveFileProbeMaxPrefixes");
  const passiveFastjsonProbeQPS = numeric(source, "passive_fastjson_probe_qps", "passiveFastjsonProbeQPS", "PassiveFastjsonProbeQPS");
  const passiveShiroProbeQPS = numeric(source, "passive_shiro_probe_qps", "passiveShiroProbeQPS", "PassiveShiroProbeQPS");
  const passiveCmdProbeQPS = numeric(source, "passive_cmd_probe_qps", "passiveCmdProbeQPS", "PassiveCmdProbeQPS");
  const passiveSSRFProbeQPS = numeric(source, "passive_ssrf_probe_qps", "passiveSSRFProbeQPS", "PassiveSSRFProbeQPS");
  const passiveXXEProbeQPS = numeric(source, "passive_xxe_probe_qps", "passiveXXEProbeQPS", "PassiveXXEProbeQPS");
  const passiveUploadProbeQPS = numeric(source, "passive_upload_probe_qps", "passiveUploadProbeQPS", "PassiveUploadProbeQPS");
  const oobDomain = text(source, "oob_domain", "oobDomain", "OOBDomain");
  const shiroKeys = strings(valueOf(source, "shiro_keys", "shiroKeys", "ShiroKeys"));
  const hfingerSource = record(valueOf(source, "hfinger", "HFinger"));
  const excludedDomains = strings(valueOf(source, "excluded_domains", "excludedDomains", "ExcludedDomains"));
  const excludedSuffixes = strings(valueOf(
    source,
    "excluded_suffixes",
    "excludedSuffixes",
    "ExcludedSuffixes",
    // Keep older desktop snapshots readable while the binding updates roll out.
    "excluded_extensions",
    "excludedExtensions",
    "ExcludedExtensions",
  ));
  const excludedContentTypes = strings(valueOf(
    source,
    "excluded_content_types",
    "excludedContentTypes",
    "ExcludedContentTypes",
  ));
  const excludedPaths = strings(valueOf(
    source,
    "excluded_paths",
    "excludedPaths",
    "ExcludedPaths",
  ));
  const excludedQueryParameters = strings(valueOf(
    source,
    "excluded_query_parameters",
    "excludedQueryParameters",
    "ExcludedQueryParameters",
  ));
  const excludedPostParameters = strings(valueOf(
    source,
    "excluded_post_parameters",
    "excludedPostParameters",
    "ExcludedPostParameters",
  ));
  const swaggerExcludedPaths = strings(valueOf(
    source,
    "swagger_excluded_paths",
    "swaggerExcludedPaths",
    "SwaggerExcludedPaths",
  ));
  const fileProbeCustomPaths = strings(valueOf(
    source,
    "file_probe_custom_paths",
    "fileProbeCustomPaths",
    "FileProbeCustomPaths",
  ));

  return {
    status,
    logs: records(valueOf(source, "logs", "Logs")).map(normalizeRuntimeLog),
    passiveLogSummary: normalizePassiveLogSummary(valueOf(source, "passive_log_summary", "passiveLogSummary", "PassiveLogSummary")),
    traffic: records(valueOf(source, "traffic", "Traffic")).map(normalizeTraffic),
    findings: records(valueOf(source, "findings", "Findings")).map(normalizeFinding),
    assets: records(valueOf(source, "assets", "Assets")).map(normalizeAsset),
    fingerprintQuality: records(valueOf(source, "fingerprint_quality", "fingerprintQuality", "FingerprintQuality")).map(normalizeFingerprintQuality).filter((item) => Boolean(item.fingerprint)),
    tasks: records(valueOf(source, "tasks", "Tasks")).map(normalizeTask),
    features,
    passiveSQLiErrorEnabled,
    passiveSQLiBooleanEnabled,
    passiveSQLiTimeEnabled,
    passiveSQLiProbeQPS: passiveSQLiProbeQPS === null ? null : Math.max(1, Math.min(20, Math.round(passiveSQLiProbeQPS))),
    passiveSQLiMaxRequests: passiveSQLiMaxRequests === null ? null : Math.max(3, Math.min(100, Math.round(passiveSQLiMaxRequests))),
    passiveSQLiMaxParameters: passiveSQLiMaxParameters === null ? null : Math.max(1, Math.min(20, Math.round(passiveSQLiMaxParameters))),
    passiveXSSProbeQPS: passiveXSSProbeQPS === null ? null : Math.max(1, Math.min(20, Math.round(passiveXSSProbeQPS))),
    passiveXSSMaxRequests: passiveXSSMaxRequests === null ? null : Math.max(2, Math.min(100, Math.round(passiveXSSMaxRequests))),
    passiveXSSMaxParameters: passiveXSSMaxParameters === null ? null : Math.max(1, Math.min(20, Math.round(passiveXSSMaxParameters))),
    passivePOCQPS: passivePOCQPS === null ? null : Math.max(1, Math.min(20, Math.round(passivePOCQPS))),
    passivePOCConcurrency: passivePOCConcurrency === null ? null : Math.max(1, Math.min(8, Math.round(passivePOCConcurrency))),
    passiveFileProbeQPS: passiveFileProbeQPS === null ? null : Math.max(1, Math.min(20, Math.round(passiveFileProbeQPS))),
    passiveFileProbeMaxPrefixes: passiveFileProbeMaxPrefixes === null ? null : Math.max(0, Math.round(passiveFileProbeMaxPrefixes)),
    passiveFastjsonProbeQPS: passiveFastjsonProbeQPS === null ? null : Math.max(1, Math.min(20, Math.round(passiveFastjsonProbeQPS))),
    passiveShiroProbeQPS: passiveShiroProbeQPS === null ? null : Math.max(1, Math.min(20, Math.round(passiveShiroProbeQPS))),
    passiveCmdProbeQPS: passiveCmdProbeQPS === null ? null : Math.max(1, Math.min(20, Math.round(passiveCmdProbeQPS))),
    passiveSSRFProbeQPS: passiveSSRFProbeQPS === null ? null : Math.max(1, Math.min(20, Math.round(passiveSSRFProbeQPS))),
    passiveXXEProbeQPS: passiveXXEProbeQPS === null ? null : Math.max(1, Math.min(20, Math.round(passiveXXEProbeQPS))),
    passiveUploadProbeQPS: passiveUploadProbeQPS === null ? null : Math.max(1, Math.min(20, Math.round(passiveUploadProbeQPS))),
    oobDomain,
    hfinger: {
      source: text(hfingerSource, "source", "Source") || "内置指纹库",
      customDir: text(hfingerSource, "custom_dir", "customDir", "CustomDir"),
      loaded: numeric(hfingerSource, "loaded", "Loaded") ?? 0,
      products: numeric(hfingerSource, "products", "Products") ?? 0,
      builtinRules: numeric(hfingerSource, "builtin_rules", "builtinRules", "BuiltinRules") ?? 0,
      customRules: numeric(hfingerSource, "custom_rules", "customRules", "CustomRules") ?? 0,
      customFiles: numeric(hfingerSource, "custom_files", "customFiles", "CustomFiles") ?? 0,
      failedFiles: numeric(hfingerSource, "failed_files", "failedFiles", "FailedFiles") ?? 0,
      errors: strings(valueOf(hfingerSource, "errors", "Errors")),
    },
    excludedDomains,
    excludedSuffixes,
    excludedContentTypes,
    excludedPaths,
    excludedQueryParameters,
    excludedPostParameters,
    swaggerExcludedPaths,
    fileProbeCustomPaths,
    shiroKeys,
  };
}

export const emptySnapshot: Snapshot = {
  status: {running: null, proxyAddress: "", apiAddress: "", message: ""},
  logs: [],
  passiveLogSummary: {
    doneHttp: 0,
    undoHttp: 0,
    undoPort: 0,
    undoTask: 0,
    requestsDone: 0,
    requestsTotal: 0,
    fingerprints: 0,
    vulnerabilities: 0,
  },
  traffic: [],
  findings: [],
  assets: [],
  fingerprintQuality: [],
  tasks: [],
  features: [],
  passiveSQLiErrorEnabled: null,
  passiveSQLiBooleanEnabled: null,
  passiveSQLiTimeEnabled: null,
  passiveSQLiProbeQPS: null,
  passiveSQLiMaxRequests: null,
  passiveSQLiMaxParameters: null,
  passiveXSSProbeQPS: null,
  passiveXSSMaxRequests: null,
  passiveXSSMaxParameters: null,
  passivePOCQPS: null,
  passivePOCConcurrency: null,
  passiveFileProbeQPS: null,
  passiveFileProbeMaxPrefixes: null,
  passiveFastjsonProbeQPS: null,
  passiveShiroProbeQPS: null,
  passiveCmdProbeQPS: null,
  passiveSSRFProbeQPS: null,
  passiveXXEProbeQPS: null,
  passiveUploadProbeQPS: null,
  oobDomain: "",
  shiroKeys: [],
  hfinger: {source: "内置指纹库", customDir: "", loaded: 0, products: 0, builtinRules: 0, customRules: 0, customFiles: 0, failedFiles: 0, errors: []},
  excludedDomains: [],
  excludedSuffixes: [],
  excludedContentTypes: [],
  excludedPaths: [],
  excludedQueryParameters: [],
  excludedPostParameters: [],
  swaggerExcludedPaths: [],
  fileProbeCustomPaths: [],
};

export interface AISettings {
  baseUrl: string;
  model: string;
  apiKey: string;
  configured: boolean;
  analysisEnabled: boolean;
  routesEnabled: boolean;
  secretsEnabled: boolean;
}

export function normalizeAISettings(value: unknown): AISettings {
  const source = record(value);
  return {
    baseUrl: text(source, "baseUrl", "base_url", "BaseURL"),
    model: text(source, "model", "Model"),
    apiKey: text(source, "apiKey", "api_key", "APIKey"),
    configured: bool(source, "configured", "Configured") ?? false,
    analysisEnabled: bool(source, "analysisEnabled", "analysis_enabled") ?? false,
    routesEnabled: bool(source, "routesEnabled", "routes_enabled") ?? false,
    secretsEnabled: bool(source, "secretsEnabled", "secrets_enabled") ?? false,
  };
}

export interface NucleiStatus {
  installed: boolean;
  configuredPath: string;
  version: string;
  message: string;
}

export function normalizeNucleiStatus(value: unknown): NucleiStatus {
  const source = record(value);
  return {
    installed: bool(source, "installed", "Installed") ?? false,
    configuredPath: text(source, "configuredPath", "configured_path", "ConfiguredPath"),
    version: text(source, "version", "Version"),
    message: text(source, "message", "Message"),
  };
}
