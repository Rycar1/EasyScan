export namespace desktop {
	
	export class NucleiStatus {
	    installed: boolean;
	    configured_path: string;
	    version?: string;
	    message?: string;
	
	    static createFrom(source: any = {}) {
	        return new NucleiStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.installed = source["installed"];
	        this.configured_path = source["configured_path"];
	        this.version = source["version"];
	        this.message = source["message"];
	    }
	}
	export class Status {
	    running: boolean;
	    proxy_address: string;
	    api_address: string;
	    mitm_enabled: boolean;
	    active_enabled: boolean;
	    message?: string;
	    certificate_path?: string;
	
	    static createFrom(source: any = {}) {
	        return new Status(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.proxy_address = source["proxy_address"];
	        this.api_address = source["api_address"];
	        this.mitm_enabled = source["mitm_enabled"];
	        this.active_enabled = source["active_enabled"];
	        this.message = source["message"];
	        this.certificate_path = source["certificate_path"];
	    }
	}
	export class Snapshot {
	    status: Status;
	    logs: model.RuntimeLog[];
	    passive_log_summary: model.PassiveLogSummary;
	    traffic: model.TrafficSummary[];
	    findings: model.Finding[];
	    assets: model.Asset[];
	    fingerprint_quality: model.FingerprintRuleQuality[];
	    tasks: model.ActiveTask[];
	    features: features.Definition[];
	    passive_sqli_error_enabled: boolean;
	    passive_sqli_boolean_enabled: boolean;
	    passive_sqli_time_enabled: boolean;
	    passive_sqli_probe_qps: number;
	    passive_sqli_max_requests: number;
	    passive_sqli_max_parameters: number;
	    passive_xss_probe_qps: number;
	    passive_xss_max_requests: number;
	    passive_xss_max_parameters: number;
	    passive_poc_qps: number;
	    passive_poc_concurrency: number;
	    passive_file_probe_qps: number;
	    passive_file_probe_max_prefixes: number;
	    passive_fastjson_probe_qps: number;
	    passive_shiro_probe_qps: number;
	    passive_cmd_probe_qps: number;
	    passive_ssrf_probe_qps: number;
	    passive_xxe_probe_qps: number;
	    passive_upload_probe_qps: number;
	    oob_domain: string;
	    shiro_keys: string[];
	    hfinger: fingerprint.HFingerStats;
	    excluded_domains: string[];
	    excluded_suffixes: string[];
	    excluded_content_types: string[];
	    excluded_paths: string[];
	    excluded_query_parameters: string[];
	    excluded_post_parameters: string[];
	    swagger_excluded_paths: string[];
	    file_probe_custom_paths: string[];
	
	    static createFrom(source: any = {}) {
	        return new Snapshot(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.status = this.convertValues(source["status"], Status);
	        this.logs = this.convertValues(source["logs"], model.RuntimeLog);
	        this.passive_log_summary = this.convertValues(source["passive_log_summary"], model.PassiveLogSummary);
	        this.traffic = this.convertValues(source["traffic"], model.TrafficSummary);
	        this.findings = this.convertValues(source["findings"], model.Finding);
	        this.assets = this.convertValues(source["assets"], model.Asset);
	        this.fingerprint_quality = this.convertValues(source["fingerprint_quality"], model.FingerprintRuleQuality);
	        this.tasks = this.convertValues(source["tasks"], model.ActiveTask);
	        this.features = this.convertValues(source["features"], features.Definition);
	        this.passive_sqli_error_enabled = source["passive_sqli_error_enabled"];
	        this.passive_sqli_boolean_enabled = source["passive_sqli_boolean_enabled"];
	        this.passive_sqli_time_enabled = source["passive_sqli_time_enabled"];
	        this.passive_sqli_probe_qps = source["passive_sqli_probe_qps"];
	        this.passive_sqli_max_requests = source["passive_sqli_max_requests"];
	        this.passive_sqli_max_parameters = source["passive_sqli_max_parameters"];
	        this.passive_xss_probe_qps = source["passive_xss_probe_qps"];
	        this.passive_xss_max_requests = source["passive_xss_max_requests"];
	        this.passive_xss_max_parameters = source["passive_xss_max_parameters"];
	        this.passive_poc_qps = source["passive_poc_qps"];
	        this.passive_poc_concurrency = source["passive_poc_concurrency"];
	        this.passive_file_probe_qps = source["passive_file_probe_qps"];
	        this.passive_file_probe_max_prefixes = source["passive_file_probe_max_prefixes"];
	        this.passive_fastjson_probe_qps = source["passive_fastjson_probe_qps"];
	        this.passive_shiro_probe_qps = source["passive_shiro_probe_qps"];
	        this.passive_cmd_probe_qps = source["passive_cmd_probe_qps"];
	        this.passive_ssrf_probe_qps = source["passive_ssrf_probe_qps"];
	        this.passive_xxe_probe_qps = source["passive_xxe_probe_qps"];
	        this.passive_upload_probe_qps = source["passive_upload_probe_qps"];
	        this.oob_domain = source["oob_domain"];
	        this.shiro_keys = source["shiro_keys"];
	        this.hfinger = this.convertValues(source["hfinger"], fingerprint.HFingerStats);
	        this.excluded_domains = source["excluded_domains"];
	        this.excluded_suffixes = source["excluded_suffixes"];
	        this.excluded_content_types = source["excluded_content_types"];
	        this.excluded_paths = source["excluded_paths"];
	        this.excluded_query_parameters = source["excluded_query_parameters"];
	        this.excluded_post_parameters = source["excluded_post_parameters"];
	        this.swagger_excluded_paths = source["swagger_excluded_paths"];
	        this.file_probe_custom_paths = source["file_probe_custom_paths"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class TaskRequest {
	    kind: string;
	    target: string;
	    session_headers?: Record<string, string>;
	
	    static createFrom(source: any = {}) {
	        return new TaskRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.kind = source["kind"];
	        this.target = source["target"];
	        this.session_headers = source["session_headers"];
	    }
	}

}

export namespace features {
	
	export class Definition {
	    id: string;
	    title: string;
	    description: string;
	    enabled: boolean;
	    editable: boolean;
	    locked: boolean;
	    risk: string;
	    kind?: string;
	    level?: number;
	    min?: number;
	    max?: number;
	
	    static createFrom(source: any = {}) {
	        return new Definition(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.title = source["title"];
	        this.description = source["description"];
	        this.enabled = source["enabled"];
	        this.editable = source["editable"];
	        this.locked = source["locked"];
	        this.risk = source["risk"];
	        this.kind = source["kind"];
	        this.level = source["level"];
	        this.min = source["min"];
	        this.max = source["max"];
	    }
	}

}

export namespace fingerprint {
	
	export class HFingerStats {
	    source: string;
	    custom_dir: string;
	    loaded: number;
	    products: number;
	    builtin_rules: number;
	    custom_rules: number;
	    custom_files: number;
	    failed_files: number;
	    errors?: string[];
	
	    static createFrom(source: any = {}) {
	        return new HFingerStats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.source = source["source"];
	        this.custom_dir = source["custom_dir"];
	        this.loaded = source["loaded"];
	        this.products = source["products"];
	        this.builtin_rules = source["builtin_rules"];
	        this.custom_rules = source["custom_rules"];
	        this.custom_files = source["custom_files"];
	        this.failed_files = source["failed_files"];
	        this.errors = source["errors"];
	    }
	}

}

export namespace model {
	
	export class ActiveTask {
	    id: string;
	    kind: string;
	    target: string;
	    status: string;
	    // Go type: time
	    created_at: any;
	    // Go type: time
	    started_at?: any;
	    // Go type: time
	    finished_at?: any;
	    error?: string;
	    summary?: Record<string, number>;
	
	    static createFrom(source: any = {}) {
	        return new ActiveTask(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.kind = source["kind"];
	        this.target = source["target"];
	        this.status = source["status"];
	        this.created_at = this.convertValues(source["created_at"], null);
	        this.started_at = this.convertValues(source["started_at"], null);
	        this.finished_at = this.convertValues(source["finished_at"], null);
	        this.error = source["error"];
	        this.summary = source["summary"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Endpoint {
	    method: string;
	    path: string;
	    parameters?: string[];
	    sources?: string[];
	
	    static createFrom(source: any = {}) {
	        return new Endpoint(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.method = source["method"];
	        this.path = source["path"];
	        this.parameters = source["parameters"];
	        this.sources = source["sources"];
	    }
	}
	export class FingerprintEvidence {
	    fingerprint: string;
	    sources?: string[];
	    confidence?: string;
	    score?: number;
	
	    static createFrom(source: any = {}) {
	        return new FingerprintEvidence(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.fingerprint = source["fingerprint"];
	        this.sources = source["sources"];
	        this.confidence = source["confidence"];
	        this.score = source["score"];
	    }
	}
	export class Asset {
	    host: string;
	    urls: string[];
	    fingerprints: string[];
	    fingerprint_evidence?: FingerprintEvidence[];
	    endpoints?: Endpoint[];
	    // Go type: time
	    last_seen: any;
	
	    static createFrom(source: any = {}) {
	        return new Asset(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.urls = source["urls"];
	        this.fingerprints = source["fingerprints"];
	        this.fingerprint_evidence = this.convertValues(source["fingerprint_evidence"], FingerprintEvidence);
	        this.endpoints = this.convertValues(source["endpoints"], Endpoint);
	        this.last_seen = this.convertValues(source["last_seen"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class Finding {
	    id: string;
	    rule_id: string;
	    title: string;
	    severity: string;
	    confidence: string;
	    url: string;
	    method?: string;
	    description: string;
	    evidence?: string;
	    remediation?: string;
	    tags?: string[];
	    // Go type: time
	    observed_at: any;
	
	    static createFrom(source: any = {}) {
	        return new Finding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.rule_id = source["rule_id"];
	        this.title = source["title"];
	        this.severity = source["severity"];
	        this.confidence = source["confidence"];
	        this.url = source["url"];
	        this.method = source["method"];
	        this.description = source["description"];
	        this.evidence = source["evidence"];
	        this.remediation = source["remediation"];
	        this.tags = source["tags"];
	        this.observed_at = this.convertValues(source["observed_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class FindingEvidence {
	    id: string;
	    finding_id: string;
	    // Go type: time
	    observed_at: any;
	    source?: string;
	    request: string;
	    response: string;
	
	    static createFrom(source: any = {}) {
	        return new FindingEvidence(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.finding_id = source["finding_id"];
	        this.observed_at = this.convertValues(source["observed_at"], null);
	        this.source = source["source"];
	        this.request = source["request"];
	        this.response = source["response"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class FingerprintAssociation {
	    fingerprint: string;
	    count: number;
	
	    static createFrom(source: any = {}) {
	        return new FingerprintAssociation(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.fingerprint = source["fingerprint"];
	        this.count = source["count"];
	    }
	}
	
	export class FingerprintRuleQuality {
	    fingerprint: string;
	    hits: number;
	    assets: number;
	    confidence?: string;
	    // Go type: time
	    last_seen: any;
	    cooccurrences?: FingerprintAssociation[];
	
	    static createFrom(source: any = {}) {
	        return new FingerprintRuleQuality(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.fingerprint = source["fingerprint"];
	        this.hits = source["hits"];
	        this.assets = source["assets"];
	        this.confidence = source["confidence"];
	        this.last_seen = this.convertValues(source["last_seen"], null);
	        this.cooccurrences = this.convertValues(source["cooccurrences"], FingerprintAssociation);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class PassiveLogSummary {
	    done_http: number;
	    undo_http: number;
	    undo_port: number;
	    undo_task: number;
	    requests_done: number;
	    requests_total: number;
	    fingerprints: number;
	    vulnerabilities: number;
	
	    static createFrom(source: any = {}) {
	        return new PassiveLogSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.done_http = source["done_http"];
	        this.undo_http = source["undo_http"];
	        this.undo_port = source["undo_port"];
	        this.undo_task = source["undo_task"];
	        this.requests_done = source["requests_done"];
	        this.requests_total = source["requests_total"];
	        this.fingerprints = source["fingerprints"];
	        this.vulnerabilities = source["vulnerabilities"];
	    }
	}
	export class RuntimeLog {
	    id: string;
	    // Go type: time
	    created_at: any;
	    level: string;
	    component: string;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new RuntimeLog(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.created_at = this.convertValues(source["created_at"], null);
	        this.level = source["level"];
	        this.component = source["component"];
	        this.message = source["message"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class TaskResult {
	    id: string;
	    task_id: string;
	    kind: string;
	    target: string;
	    status: string;
	    detail?: string;
	    metadata?: Record<string, string>;
	    // Go type: time
	    observed_at: any;
	
	    static createFrom(source: any = {}) {
	        return new TaskResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.task_id = source["task_id"];
	        this.kind = source["kind"];
	        this.target = source["target"];
	        this.status = source["status"];
	        this.detail = source["detail"];
	        this.metadata = source["metadata"];
	        this.observed_at = this.convertValues(source["observed_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class TrafficSummary {
	    id: string;
	    // Go type: time
	    observed_at: any;
	    source?: string;
	    method?: string;
	    url: string;
	    status?: number;
	    content_type?: string;
	    findings?: string[];
	    fingerprints?: string[];
	
	    static createFrom(source: any = {}) {
	        return new TrafficSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.observed_at = this.convertValues(source["observed_at"], null);
	        this.source = source["source"];
	        this.method = source["method"];
	        this.url = source["url"];
	        this.status = source["status"];
	        this.content_type = source["content_type"];
	        this.findings = source["findings"];
	        this.fingerprints = source["fingerprints"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

