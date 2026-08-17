#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Convert EZ fingerprint libraries into HFinger YAML builtin rules.

Sources:
  F1 (ez指纹.txt):  rule_id/product/expression  (boolean expression)
  F2 (ez指纹2.txt): product_name/rules          (structured body/header/icon_hash/cert)

Output: third_party/hfinger/rulesets/core/ez-fingerprints-NN.yaml

Policy:
  * dedupe against existing builtin product names and between F1/F2
  * skip rules whose only evidence is weak/generic keywords (low confidence)
  * F1 boolean expressions -> HFinger matchers (all/any/score strategy)
"""
import json
import os
import re
import sys
import glob
import hashlib
import yaml

DRY_RUN = "--dry-run" in sys.argv

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
F1 = r"C:/Users/AgiUser/Downloads/ez指纹.txt"
F2 = r"C:/Users/AgiUser/Downloads/ez指纹2.txt"
CORE_DIR = os.path.join(BASE, "third_party", "hfinger", "rulesets", "core")
OUT_PREFIX = "ez-fingerprints"
CHUNK = 900

STRONG_TYPES = {
    "favicon.hash", "header.contains", "cookie.contains",
    "tls.cert.subject.contains", "tls.cert.issuer.contains", "tls.cert.dns.contains",
}

GENERIC_WORDS = {
    "login", "admin", "index", "home", "welcome", "error", "test", "default",
    "main", "web", "user", "password", "username", "signin", "signup", "dashboard",
    "portal", "system", "management", "console", "search", "menu", "loading",
    "copyright", "submit", "hello", "world", "page", "document", "welcome to",
    "sign in", "log in", "powered by", "all rights reserved", "version", "status",
    "ok", "true", "false", "null", "none", "title", "content", "http", "https",
    "html", "javascript", "jquery", "bootstrap", "css", "www", "api", "json",
}


def norm_name(name):
    return re.sub(r"[\s\-_\.]+", "", str(name).strip().lower())


def make_id(name, source):
    digest = hashlib.md5((source + ":" + norm_name(name)).encode("utf-8")).hexdigest()
    return f"ez-{digest[:14]}"


def is_weak_value(value):
    v = str(value).strip().lower()
    if len(v) < 5:
        return True
    if v in GENERIC_WORDS:
        return True
    return False


def is_specific_keyword(value):
    """A body/title keyword specific enough to identify a product on its own."""
    v = str(value).strip()
    vl = v.lower()
    if len(vl) < 6:
        return False
    if vl in GENERIC_WORDS:
        return False
    if re.search(r"[0-9._/\-]", v):
        return True
    if len(vl) >= 12:
        return True
    if " " in vl and len(vl) >= 10:
        return True
    return False


def matcher_is_weak(m):
    if m["type"] in STRONG_TYPES:
        return False
    return not is_specific_keyword(m.get("value", ""))


def load_builtin_names():
    names = set()
    ids = set()
    for path in glob.glob(os.path.join(CORE_DIR, "*.yaml")):
        with open(path, encoding="utf-8") as fh:
            try:
                data = yaml.safe_load(fh)
            except Exception:
                continue
        rules = (data or {}).get("rules", []) if isinstance(data, dict) else []
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if rule.get("name"):
                names.add(norm_name(rule["name"]))
            if rule.get("id"):
                ids.add(rule["id"])
    return names, ids


# ---------------------------------------------------------------------------
# F1 expression parsing
# ---------------------------------------------------------------------------
ATOM_RE = re.compile(r"(title|body|header|banner|cert|icon_hash|favicon|icon)\s*(\.contains\s*\(|==|!=)")


def read_quoted(expr, i):
    i += 1  # skip opening quote
    out = []
    n = len(expr)
    while i < n:
        c = expr[i]
        if c == "\\" and i + 1 < n:
            nxt = expr[i + 1]
            out.append({"n": "\n", "t": "\t", "r": "\r"}.get(nxt, nxt))
            i += 2
            continue
        if c == '"':
            return "".join(out), i + 1
        out.append(c)
        i += 1
    return "".join(out), i


def tokenize(expr):
    tokens = []
    i, n = 0, len(expr)
    while i < n:
        c = expr[i]
        if c.isspace():
            i += 1
            continue
        if c == "(":
            tokens.append(("LPAREN", "(")); i += 1; continue
        if c == ")":
            tokens.append(("RPAREN", ")")); i += 1; continue
        if expr[i:i + 2] == "&&":
            tokens.append(("AND", "&&")); i += 2; continue
        if expr[i:i + 2] == "||":
            tokens.append(("OR", "||")); i += 2; continue
        m = ATOM_RE.match(expr, i)
        if m:
            field = m.group(1)
            op_raw = m.group(2).strip()
            j = m.end()
            while j < n and expr[j].isspace():
                j += 1
            if j < n and expr[j] == '"':
                value, j = read_quoted(expr, j)
                if op_raw.startswith(".contains"):
                    while j < n and expr[j].isspace():
                        j += 1
                    if j < n and expr[j] == ")":
                        j += 1
                op = "contains" if op_raw.startswith(".contains") else ("eq" if op_raw == "==" else "neq")
                tokens.append(("ATOM", (field, op, value)))
                i = j
                continue
            i = m.end()
            continue
        i += 1
    return tokens


class Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self):
        t = self.peek()
        self.pos += 1
        return t

    def parse(self):
        if not self.tokens:
            return None
        node = self.parse_or()
        return node

    def parse_or(self):
        terms = [self.parse_and()]
        while self.peek() and self.peek()[0] == "OR":
            self.take()
            terms.append(self.parse_and())
        terms = [t for t in terms if t is not None]
        if not terms:
            return None
        return terms[0] if len(terms) == 1 else ("or", terms)

    def parse_and(self):
        factors = [self.parse_factor()]
        while self.peek() and self.peek()[0] == "AND":
            self.take()
            factors.append(self.parse_factor())
        factors = [f for f in factors if f is not None]
        if not factors:
            return None
        return factors[0] if len(factors) == 1 else ("and", factors)

    def parse_factor(self):
        t = self.peek()
        if t is None:
            return None
        if t[0] == "LPAREN":
            self.take()
            node = self.parse_or()
            if self.peek() and self.peek()[0] == "RPAREN":
                self.take()
            return node
        if t[0] == "ATOM":
            self.take()
            return ("atom", t[1])
        self.take()
        return self.parse_factor()


def collect_atoms(node, out):
    if node is None:
        return
    if node[0] == "atom":
        out.append(node[1])
    else:
        for child in node[1]:
            collect_atoms(child, out)


def strip_negatives(node):
    """Remove neq atoms; returns positive-only AST (or None)."""
    if node is None:
        return None
    if node[0] == "atom":
        field, op, value = node[1]
        return None if op == "neq" else node
    kind, children = node[0], node[1]
    kept = [strip_negatives(c) for c in children]
    kept = [c for c in kept if c is not None]
    if not kept:
        return None
    if len(kept) == 1:
        return kept[0]
    return (kind, kept)


def atom_to_matcher(atom):
    field, op, value = atom
    value = str(value)
    ev = f"EZ fingerprint evidence for field {field}"
    if field in ("icon_hash", "favicon", "icon"):
        num = re.sub(r"[^\d\-]", "", value)
        if num and num.lstrip("-").isdigit():
            return {"type": "favicon.hash", "value": int(num), "evidence": ev}
        return None
    if field == "title":
        return {"type": "title.contains", "value": value, "evidence": ev}
    if field == "body":
        return {"type": "body.contains", "value": value, "evidence": ev}
    if field == "header":
        return {"type": "header.contains", "value": value, "evidence": ev}
    if field == "banner":
        # EZ "banner" is the full HTTP header block; HFinger header.contains
        # (no key) matches every "Key: Value" line, which is the closest match.
        return {"type": "header.contains", "value": value, "evidence": ev}
    if field == "cert":
        return {"type": "tls.cert.subject.contains", "value": value, "evidence": ev}
    return {"type": "body.contains", "value": value, "evidence": ev}


def positives_to_plan(node):
    """Return (matchers, strategy, weights, threshold)."""
    if node is None:
        return [], "all", None, 0
    if node[0] == "atom":
        m = atom_to_matcher(node[1])
        return ([m], "all", None, 0) if m else ([], "all", None, 0)
    kind, children = node[0], node[1]
    if kind == "and":
        matchers = []
        for child in children:
            sub, _, _, _ = positives_to_plan(child)
            matchers.extend(sub)
        return matchers, "all", None, 0
    # or
    all_atoms = all(c[0] == "atom" for c in children)
    if all_atoms:
        matchers = [atom_to_matcher(c[1]) for c in children]
        matchers = [m for m in matchers if m]
        return matchers, "any", None, 0
    # OR of mixed terms -> score strategy
    matchers, weights = [], []
    for term in children:
        if term[0] == "atom":
            m = atom_to_matcher(term[1])
            if m:
                matchers.append(m)
                weights.append(100)
        elif term[0] == "and":
            atoms = []
            collect_atoms(term, atoms)
            atoms = [a for a in atoms if a[1] != "neq"]
            ms = [atom_to_matcher(a) for a in atoms]
            ms = [m for m in ms if m]
            if not ms:
                continue
            w = -(-100 // len(ms))
            for m in ms:
                matchers.append(m)
                weights.append(w)
        else:
            sub, _, _, _ = positives_to_plan(term)
            for m in sub:
                matchers.append(m)
                weights.append(100)
    if not matchers:
        return [], "all", None, 0
    return matchers, "score", weights, 100


def convert_f1(item):
    expr = item.get("expression", "")
    tokens = tokenize(expr)
    ast = Parser(tokens).parse()
    if ast is None:
        return None
    all_atoms = []
    collect_atoms(ast, all_atoms)
    negatives = [atom_to_matcher(a) for a in all_atoms if a[1] == "neq"]
    negatives = [m for m in negatives if m]
    pos_ast = strip_negatives(ast)
    matchers, strategy, weights, threshold = positives_to_plan(pos_ast)
    if not matchers:
        return None
    return {
        "matchers": matchers,
        "negatives": negatives,
        "strategy": strategy,
        "weights": weights,
        "threshold": threshold,
    }


# ---------------------------------------------------------------------------
# F2 conversion
# ---------------------------------------------------------------------------
def convert_f2(item):
    rules = item.get("rules", {}) or {}
    strong = []
    body = []
    icon = rules.get("icon_hash")
    if icon:
        num = re.sub(r"[^\d\-]", "", str(icon))
        if num and num.lstrip("-").isdigit():
            strong.append({"type": "favicon.hash", "value": int(num), "evidence": "EZ favicon hash evidence"})
    for kw in rules.get("cert", []) or []:
        if str(kw).strip():
            strong.append({"type": "tls.cert.subject.contains", "value": str(kw), "evidence": "EZ TLS cert evidence"})
    header = rules.get("header") or {}
    if isinstance(header, dict):
        for key, values in header.items():
            if isinstance(values, (list, tuple)):
                for v in values:
                    if str(v).strip():
                        strong.append({"type": "header.contains", "key": str(key), "value": str(v), "evidence": "EZ HTTP header evidence"})
            elif str(values).strip():
                strong.append({"type": "header.contains", "key": str(key), "value": str(values), "evidence": "EZ HTTP header evidence"})
    elif isinstance(header, (list, tuple)):
        for v in header:
            if str(v).strip():
                strong.append({"type": "header.contains", "value": str(v), "evidence": "EZ HTTP header evidence"})
    for kw in rules.get("body", []) or []:
        if str(kw).strip():
            body.append({"type": "body.contains", "value": str(kw), "evidence": "EZ response body evidence"})
    for kw in rules.get("static_keywords", []) or []:
        if str(kw).strip():
            body.append({"type": "body.contains", "value": str(kw), "evidence": "EZ static keyword evidence"})

    if not strong and not body:
        return None
    if strong:
        matchers = strong + body
        weights = [100] * len(strong) + [34] * len(body)
        return {"matchers": matchers, "negatives": [], "strategy": "score", "weights": weights, "threshold": 100}
    return {"matchers": body, "negatives": [], "strategy": "any", "weights": None, "threshold": 0}


# ---------------------------------------------------------------------------
# Confidence filter
# ---------------------------------------------------------------------------
def apply_confidence_filter(plan):
    """Drop weak alternative matchers; return False if rule is too low confidence."""
    matchers = plan["matchers"]
    strategy = plan["strategy"]
    if not any(not matcher_is_weak(m) for m in matchers):
        return False
    if strategy == "any":
        # Weak alternatives would match on their own and cause false positives,
        # so keep only specific/strong matchers.
        kept = [m for m in matchers if not matcher_is_weak(m)]
        if not kept:
            return False
        plan["matchers"] = kept
    # all/score: keep every matcher (AND adds precision; score weights de-emphasize).
    return True


# ---------------------------------------------------------------------------
# Category inference (mirrors rules/migrate.go inferCategory)
# ---------------------------------------------------------------------------
CATEGORY_RULES = [
    ("waf", ["waf", "web application firewall", "防火墙", "安全狗", "safedog", "fortiweb", "barracuda"]),
    ("cdn", ["cdn", "cloudflare", "akamai", "fastly", "网宿", "加速乐"]),
    ("security-device", ["vpn", "ssl vpn", "sslvpn", "堡垒", "网关", "gateway", "防火墙设备"]),
    ("middleware", ["kubernetes", "consul", "nacos", "dubbo", "rabbitmq", "rocketmq", "kafka", "tomcat", "nginx", "apache", "iis", "weblogic", "jboss", "websphere"]),
    ("devops", ["jenkins", "gitlab", "nexus", "harbor", "sonarqube", "airflow", "xxl-job"]),
    ("observability", ["grafana", "prometheus", "alertmanager", "kibana", "flink", "spark", "zabbix"]),
    ("database", ["elasticsearch", "redis", "mongo", "mysql", "phpmyadmin", "influx", "clickhouse", "druid", "postgresql", "oracle"]),
    ("framework", ["spring", "swagger", "openapi", "fastapi", "shiro", "asp.net", "java", "php", "python", "node", "vue", "react", "angular", "bootstrap", "jquery"]),
    ("oa", ["oa", "协同", "e-cology", "eoffice", "致远", "泛微", "通达", "蓝凌", "用友", "金蝶"]),
    ("cms", ["cms", "wordpress", "joomla", "drupal", "dedecms", "pbootcms", "typecho", "discuz"]),
    ("iot-device", ["camera", "nvr", "dvr", "nas", "router", "switch", "iot", "摄像", "路由", "打印机", "printer"]),
    ("ai-service", ["gradio", "streamlit", "jupyter", "ollama", "open webui", "dify"]),
]

F2_CATEGORY_MAP = {
    "开发框架": "framework", "前端框架": "framework", "后端框架": "framework",
    "Web框架": "framework", "web框架": "framework", "编程语言": "framework",
    "中间件": "middleware", "Web服务器": "middleware", "应用服务器": "middleware",
    "网络存储": "middleware", "操作系统": "middleware", "邮件系统": "middleware",
    "消息队列": "middleware", "数据库": "database", "缓存": "database",
    "数据分析": "observability", "监控": "observability", "安全": "waf",
    "WAF": "waf", "CDN": "cdn", "OA": "oa", "CMS": "cms", "物联网": "iot-device",
}


def infer_category(name, tags_text="", f2_category=""):
    if f2_category and f2_category in F2_CATEGORY_MAP:
        return F2_CATEGORY_MAP[f2_category]
    text = (name + " " + tags_text).lower()
    for category, needles in CATEGORY_RULES:
        for needle in needles:
            if needle in text:
                return category
    return "middleware"


def clean_name(name):
    name = str(name).strip()
    name = re.sub(r"[\x00-\x1f]+", "", name)
    name = re.sub(r"\s+", " ", name)
    return name or "Unknown"


# ---------------------------------------------------------------------------
# Rule assembly
# ---------------------------------------------------------------------------
def evidence_for(matcher_type, name):
    t = matcher_type
    if "favicon" in t:
        return f"EZ favicon hash evidence for {name}"
    if t.startswith("header") or t.startswith("cookie"):
        return f"EZ HTTP header evidence for {name}"
    if t.startswith("title"):
        return f"EZ HTML title evidence for {name}"
    if t.startswith("tls.cert"):
        return f"EZ TLS certificate evidence for {name}"
    if t.startswith("server.banner"):
        return f"EZ server banner evidence for {name}"
    return f"EZ response body evidence for {name}"


def build_rule(rule_id, name, category, plan, source_tag, vendor=""):
    matchers = []
    for i, m in enumerate(plan["matchers"]):
        matcher = dict(m)
        matcher["evidence"] = evidence_for(matcher["type"], name)
        if plan.get("weights"):
            matcher["weight"] = plan["weights"][i]
        matchers.append(matcher)
    negatives = []
    for m in plan.get("negatives", []):
        neg = dict(m)
        neg["evidence"] = evidence_for(neg["type"], name)
        negatives.append(neg)
    match = {
        "strategy": plan["strategy"],
        "matchers": matchers,
    }
    if plan["strategy"] == "score":
        match["threshold"] = plan.get("threshold", 100)
    if negatives:
        match["negative"] = negatives
    has_strong = any(m["type"] in STRONG_TYPES for m in matchers)
    multi_and = plan["strategy"] == "all" and len(matchers) >= 2
    confidence = "medium" if (has_strong or multi_and) else "low"
    rule = {
        "id": rule_id,
        "name": name,
        "category": category,
        "match": match,
        "tags": ["ez-fingerprint", source_tag],
        "metadata": {
            "confidence": confidence,
            "references": ["builtin:ez-fingerprint-library"],
        },
    }
    if vendor:
        rule["vendor"] = vendor
    return rule


def main():
    builtin_names, builtin_ids = load_builtin_names()
    print(f"builtin products={len(builtin_names)} ids={len(builtin_ids)}")

    with open(F1, encoding="utf-8") as fh:
        f1 = json.load(fh)
    with open(F2, encoding="utf-8") as fh:
        f2 = json.load(fh)

    used_ids = set(builtin_ids)
    used_names = set(builtin_names)
    added_f2_names = set()
    rules = []
    stats = {"f1_total": len(f1), "f2_total": len(f2),
             "f1_dup_builtin": 0, "f1_dup_f2": 0, "f1_dup_self": 0,
             "f1_low_conf": 0, "f1_convert_fail": 0, "f1_added": 0,
             "f2_dup_builtin": 0, "f2_dup_self": 0,
             "f2_low_conf": 0, "f2_convert_fail": 0, "f2_added": 0}

    # --- F2 first (structured, preferred on overlap) ---
    for item in f2:
        name = clean_name(item.get("product_name", ""))
        nn = norm_name(name)
        if not nn:
            continue
        if nn in used_names:
            stats["f2_dup_builtin"] += 1 if nn in builtin_names else 0
            stats["f2_dup_self"] += 1 if nn not in builtin_names else 0
            continue
        plan = convert_f2(item)
        if not plan:
            stats["f2_convert_fail"] += 1
            continue
        if not apply_confidence_filter(plan):
            stats["f2_low_conf"] += 1
            continue
        rid = make_id(name, "f2")
        if rid in used_ids:
            stats["f2_dup_self"] += 1
            continue
        category = infer_category(name, "", item.get("category", ""))
        rule = build_rule(rid, name, category, plan, "ez2", item.get("company", ""))
        rules.append(rule)
        used_ids.add(rid)
        used_names.add(nn)
        added_f2_names.add(nn)
        stats["f2_added"] += 1

    # --- F1 ---
    for item in f1:
        name = clean_name(item.get("product", ""))
        nn = norm_name(name)
        if not nn:
            continue
        if nn in builtin_names:
            stats["f1_dup_builtin"] += 1
            continue
        if nn in added_f2_names:
            stats["f1_dup_f2"] += 1
            continue
        if nn in used_names:
            stats["f1_dup_self"] += 1
            continue
        plan = convert_f1(item)
        if not plan:
            stats["f1_convert_fail"] += 1
            continue
        if not apply_confidence_filter(plan):
            stats["f1_low_conf"] += 1
            continue
        rid = make_id(name, "f1")
        if rid in used_ids:
            stats["f1_dup_self"] += 1
            continue
        category = infer_category(name, item.get("expression", ""))
        rule = build_rule(rid, name, category, plan, "ez1")
        rules.append(rule)
        used_ids.add(rid)
        used_names.add(nn)
        stats["f1_added"] += 1

    print("\n=== Conversion stats ===")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    print(f"  TOTAL rules to write: {len(rules)}")

    conf_count, strat_count = {}, {}
    for r in rules:
        conf_count[r["metadata"]["confidence"]] = conf_count.get(r["metadata"]["confidence"], 0) + 1
        strat_count[r["match"]["strategy"]] = strat_count.get(r["match"]["strategy"], 0) + 1
    print(f"  confidence breakdown: {conf_count}")
    print(f"  strategy breakdown: {strat_count}")

    if DRY_RUN:
        print("\n[DRY RUN] no files written. Sample rules:")
        print(yaml.safe_dump(rules[:3], allow_unicode=True, sort_keys=False, width=200))
        return

    # --- Write chunked YAML files ---
    # Remove previously generated ez files
    for old in glob.glob(os.path.join(CORE_DIR, OUT_PREFIX + "-*.yaml")):
        os.remove(old)

    written = []
    for idx in range(0, len(rules), CHUNK):
        chunk = rules[idx:idx + CHUNK]
        part = idx // CHUNK + 1
        filename = f"{OUT_PREFIX}-{part:02d}.yaml"
        path = os.path.join(CORE_DIR, filename)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# Auto-generated from EZ fingerprint libraries. Do not edit by hand.\n")
            yaml.safe_dump({"version": 1, "rules": chunk}, fh,
                           allow_unicode=True, sort_keys=False, width=1000)
        written.append((filename, len(chunk)))
        print(f"  wrote {filename}: {len(chunk)} rules")

    print(f"\nDone. {len(rules)} rules across {len(written)} files.")


if __name__ == "__main__":
    main()
