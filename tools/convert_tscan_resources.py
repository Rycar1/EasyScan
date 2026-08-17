#!/usr/bin/env python3
"""Convert selected TscanPlus resources into EasyScan data files.

This converter deliberately imports only passive, static metadata:

* all current FingerDir route fingerprints;
* Afrog fingerprint entries that are informational, HTTP GET-only, use a
  fixed path, and can be expressed with a status plus fixed response evidence;
* a curated subset of response-only JsRule information-discovery expressions;
* POC catalogue metadata only.  Request bodies, expressions, variables and
  other executable POC content are never copied to the EasyScan repository.

The default source path matches the local TscanPlus bundle used by this
project.  It can be overridden when a newer bundle is available:

    python tools/convert_tscan_resources.py --source D:\\TscanPlus_Win_Amd64\\config

PyYAML is required because TscanPlus distributes YAML databases.  The script
also runs the generated passive regular expressions through Go's regexp
compiler (RE2) unless --skip-go-check is supplied.
"""

from __future__ import annotations

import argparse
import ast
import collections
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except ImportError as exc:  # pragma: no cover - environment diagnostic
    raise SystemExit("缺少 PyYAML：请安装 pyyaml 后重新运行转换脚本。") from exc


DEFAULT_SOURCE = Path(r"C:\Users\AgiUser\Desktop\TscanPlus_Win_Amd64\config")
PROJECT_ROOT = Path(__file__).resolve().parents[1]

FINGERPRINT_OUTPUT = Path("fingerprints/tscan-path-fingerprints.yaml")
RULE_OUTPUT = Path("rules/tscan-information.yaml")
POC_INDEX_OUTPUT = Path("pocs/tscan-poc-index.json")

# These guards apply to stale source records if a later TscanPlus package
# includes backups/examples alongside its production resource set.  None of
# the current 38 FingerDir records match them, so all current entries remain.
LEGACY_OR_TEST_NAME = re.compile(
    r"(?:^|[-_\s])(backup|bak|old|example|sample|test)(?:$|[-_\s])|备份|旧版|示例|测试",
    re.IGNORECASE,
)

# TscanPlus' route database contains the product and vendor in one label.  The
# desktop UI intentionally shows only concise product names.  Keep vendor
# names where they are part of the natural Chinese product name.
FINGERDIR_PRODUCT_NAMES = {
    "Alibaba-Nacos": "Nacos",
    "Alibaba-Druid": "Druid",
    "泛微-协同办公OA": "泛微协同办公 OA",
    "SpringBoot-Actuator": "Spring Boot Actuator",
    "SpringBoot-Error": "Spring Boot",
    "Swagger-API": "Swagger",
    "帆软-FineReport": "帆软 FineReport",
    "XXL-JOB": "XXL-JOB",
    "GeoServer": "GeoServer",
    "百度-UEditor": "百度 UEditor",
    "易软天创-禅道系统": "禅道",
    "phpMyAdmin": "phpMyAdmin",
    "ArcGIS": "ArcGIS",
    "SMARTBI": "Smartbi",
    "HARBOR": "Harbor",
    "MINIO": "MinIO",
    "Tomcat-Manager": "Apache Tomcat",
    "Jenkins": "Jenkins",
    "Zabbix": "Zabbix",
    "Apereo-CAS": "Apereo CAS",
    "Weblogic": "Oracle WebLogic",
    "万户OA": "万户 OA",
    "致远OA": "致远 OA",
    "用友NC": "用友 NC",
    "蓝凌OA": "蓝凌 OA",
    "Grafana": "Grafana",
    "Kibana": "Kibana",
    "Elasticsearch": "Elasticsearch",
    "Redis-Commander": "Redis Commander",
    "RabbitMQ": "RabbitMQ",
    "Solr": "Apache Solr",
    "Confluence": "Confluence",
    "JIRA": "Jira",
    "GitLab": "GitLab",
    "Jupyter": "Jupyter",
    "PHPInfo": "PHPInfo",
    "Adminer": "Adminer",
    "Jeecg-Boot": "Jeecg-Boot",
}

# Product-only overrides for source names which cannot be cleaned accurately
# by suffix removal alone.  Keys are Afrog template IDs.
AFROG_PRODUCT_NAMES = {
    "acemanager-login": "ACEmanager",
    "acrolinx-dashboard": "Acrolinx",
    "adminer-panel": "Adminer",
    "adminset-panel": "AdminSet",
    "apisix-panel": "Apache APISIX",
    "arcgis-datastore-detect": "ArcGIS Data Store",
    "arcgis-login": "ArcGIS",
    "arcgis-sharing-rest-login": "ArcGIS",
    "axis-detect": "Apache Axis",
    "azure-kubernetes-service": "Azure Kubernetes Service",
    "cas-login": "Apereo CAS",
    "casemanager-panel": "CaseManager",
    "ctcms-detect": "赤兔 CMS",
    "default-apache-shiro": "Apache Shiro",
    "django-admin-panel": "Django",
    "dlink-panel": "D-Link",
    "druid-panel": "Druid",
    "emessage-panel": "eMessage",
    "fanruanoa-detect": "帆软 FineReport",
    "founder-newsedit-detect": "方正全媒体采编",
    "founder-newsedit-syslogin-detect": "方正全媒体采编",
    "geoserver-login-panel": "GeoServer",
    "gitlab-panel": "GitLab",
    "gocron-panel": "GoCron",
    "grafana-panel": "Grafana",
    "h3c-hci-management": "H3C HCI",
    "h3c-imc-panel": "H3C iMC",
    "hanwang-detect": "汉王人脸考勤管理系统",
    "huawei-esight-detect": "华为 eSight",
    "hue-login-panel": "Hue",
    "jenkins-api-panel": "Jenkins",
    "jenkins-login": "Jenkins",
    "kkfileview-panel": "kkFileView",
    "kubernetes-enterprise-manager": "Kubernetes Enterprise Manager",
    "kubernetes-version": "Kubernetes",
    "landray-oa-panel": "蓝凌 OA",
    "livehelperchat-admin-panel": "Live Helper Chat",
    "manageengine-analytics": "ManageEngine Analytics Plus",
    "mapgis-cloud-manager-panel": "MapGIS Cloud Manager",
    "microsoft-exchange-panel": "Microsoft Exchange",
    "minio-browser": "MinIO",
    "minio-console": "MinIO",
    "mobile-management-panel": "移动管理平台",
    "mongodb-ops-manager": "MongoDB Ops Manager",
    "nacos-detect": "Nacos",
    "neo4j-browser": "Neo4j",
    "newcapec-detect": "新开普",
    "novnc-login-panel": "noVNC",
    "o2oa-detect": "O2OA",
    "openemr-detect": "OpenEMR",
    "opengear-panel": "Opengear",
    "openstack-dashboard-login": "OpenStack Dashboard",
    "openvpn-admin": "OpenVPN Admin",
    "phpmyadmin-panel": "phpMyAdmin",
    "piwigo-detect": "Piwigo",
    "plesk-obsidian-login": "Plesk Obsidian",
    "qiyuesuo-panel": "契约锁",
    "rainbond-detect": "Rainbond",
    "realor-panel": "瑞友应用虚拟化系统",
    "roundcube-webmail": "Roundcube",
    "sap-fiori-launchpad": "SAP Fiori Launchpad",
    "sap-fiorilaunchpad-logon": "SAP Fiori Launchpad",
    "sap-icm-admin": "SAP ICM",
    "sap-netweaver-portal": "SAP NetWeaver Portal",
    "sap-nw-webgui": "SAP NetWeaver WebGUI",
    "sap-web-dispatcher-administration": "SAP Web Dispatcher",
    "secvpn-detect": "SecVPN",
    "seeyon-a8-management-monitor": "致远 A8",
    "seeyon-version": "致远 OA",
    "shiro-detect": "Apache Shiro",
    "solarwinds-orion": "SolarWinds Orion",
    "sonicwall-management-panel": "SonicWall",
    "sonicwall-sslvpn-panel": "SonicWall SSL VPN",
    "spring-detect": "Spring Framework",
    "springblade-detect": "SpringBlade",
    "springboot-actuator": "Spring Boot Actuator",
    "taihe-panel": "泰合信息安全运营中心",
    "tenda-panel": "Tenda",
    "tianjing-panel": "天镜脆弱性扫描与管理系统",
    "tianyue-panel": "天玥运维安全网关",
    "utt-panel": "UTT",
    "wayos-panel": "WayOS",
    "weblogic-panel": "Oracle WebLogic",
    "wordpress-login": "WordPress",
    "xiruanyun-xms-detect": "西软云 XMS",
    "xxljob-panel": "XXL-JOB",
    "yonyou-mobsm-detect": "用友 MOBSM",
    "yonyou-iuap-detect": "用友 YonBIP",
    "yunlian-pos-erp-detect": "云联 POS ERP",
    "zentao-detect": "禅道",
}

# Generic edge/provider recognizers already exist in EasyScan.  The remaining
# exclusions either have non-info severity or perform a vulnerability/probe
# action rather than identify a product page.
AFROG_EXCLUDED_IDS = {
    "cdn-detect",
    "waf-detect",
    "honeypot-detect",
    "panel-detect",
    "hfs-rce-cmd-exec",
    "javamelody-detect",
    "kubernetes-metrics",
    "swagger-disclosure",
    "thinkphp-debug-detected",
    "thinkphp-errors",
    "tomcat-manager",
}
AFROG_UNSAFE_NAME = re.compile(
    r"(?:\brce\b|cmd[-_ ]?exec|remote[-_ ]?code|vulnerab|\bcve\b|\bcnvd\b|"
    r"disclosure|unauthori[sz]ed|bypass|traversal|injection|deseriali[sz]|"
    r"debug|\berrors?\b|\bmetrics\b)",
    re.IGNORECASE,
)

# A single literal call is parsed from Afrog's DSL.  Its value is decoded with
# ast.literal_eval so escaped quotes from the source remain valid YAML text.
LITERAL = r"(?:'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")"
STATUS_CALL = re.compile(r"response\.status\s*==\s*(?P<value>[1-5]\d{2})")
BODY_CALL = re.compile(
    rf"(?P<neg>!\s*)?response\.body\.(?:i?bcontains)\(\s*b?(?P<value>{LITERAL})\s*\)",
    re.IGNORECASE,
)
HEADER_CALL = re.compile(
    rf"(?P<neg>!\s*)?response\.raw_header\.(?:i?bcontains)\(\s*b?(?P<value>{LITERAL})\s*\)",
    re.IGNORECASE,
)
CONTENT_TYPE_CALL = re.compile(
    rf"(?P<neg>!\s*)?response\.headers\[\s*['\"]content-type['\"]\s*\]\.contains\(\s*(?P<value>{LITERAL})\s*\)",
    re.IGNORECASE,
)

# Only the JsRule entries below are response-oriented information discovery
# signals.  Query/test-point, authentication/page inventory, and source rules
# that merely match a field name (rather than a disclosed value) are omitted.
# Overrides tighten broad upstream regexes before they become passive findings.
JS_INFORMATION_RULES: dict[int, dict[str, str]] = {
    10: {
        "slug": "email-address",
        "title": "响应中发现电子邮箱地址",
        "description": "响应正文中出现电子邮箱地址，可能包含个人信息。",
    },
    11: {
        "slug": "mobile-number",
        "title": "响应中发现手机号码",
        "description": "响应正文中出现中国大陆手机号码格式，可能包含个人信息。",
    },
    12: {
        "slug": "mysql-config",
        "title": "响应中发现 MySQL 配置片段",
        "description": "响应中出现 MySQL 配置段标识，可能暴露数据库连接配置。",
    },
    13: {
        "slug": "id-card-number",
        "title": "响应中发现身份证号码",
        "description": "响应正文中出现中国居民身份证号码格式，可能包含个人信息。",
    },
    16: {
        "slug": "aliyun-oss-endpoint",
        "title": "响应中发现阿里云 OSS 地址",
        "description": "响应中出现阿里云 OSS 域名，可用于排查公开存储资源。",
    },
    17: {
        "slug": "private-network-address",
        "title": "响应中发现内网地址",
        "description": "响应中出现本地或 RFC1918 内网地址，可能暴露内部网络信息。",
    },
    37: {
        "slug": "password-value",
        "title": "响应中发现密码字段值",
        "description": "响应中出现带值的密码字段，可能泄露认证信息。",
        "pattern": r"(?i)[\"']?(password|passwd|pwd)[\"']?\s*[:=]\s*[\"'][^\"'\r\n]{6,}[\"']",
    },
    38: {
        "slug": "aws-storage-endpoint",
        "title": "响应中发现 AWS 存储地址",
        "description": "响应中出现 AWS S3 或相关存储地址，可用于资产梳理。",
    },
    41: {
        "slug": "github-token",
        "title": "响应中发现 GitHub 访问令牌",
        "description": "响应中出现 GitHub 访问令牌格式，应立即核实并轮换。",
    },
    43: {
        "slug": "jdbc-connection",
        "title": "响应中发现 JDBC 连接字符串",
        "description": "响应中出现 JDBC 数据库连接字符串，可能泄露内部服务地址或账号配置。",
    },
    44: {
        "slug": "jwt-token",
        "title": "响应中发现 JWT 格式令牌",
        "description": "响应中出现 JWT 格式令牌，应确认其是否为可复用会话凭据。",
    },
    47: {
        "slug": "microsoft-teams-webhook",
        "title": "响应中发现 Microsoft Teams Webhook",
        "description": "响应中出现 Microsoft Teams Webhook 地址，可能泄露集成凭据。",
    },
    48: {
        "slug": "zoho-webhook",
        "title": "响应中发现 Zoho Webhook",
        "description": "响应中出现 Zoho Webhook 地址及令牌参数，可能泄露集成凭据。",
    },
    49: {
        "slug": "system-path",
        "title": "响应中发现系统路径",
        "description": "响应中出现 Windows 或 Unix 系统路径，可能暴露部署结构。",
    },
    51: {
        "slug": "sonarqube-token",
        "title": "响应中发现 SonarQube 令牌",
        "description": "响应中出现 SonarQube 令牌格式，应确认其是否仍有效。",
    },
    52: {
        "slug": "aws-region",
        "title": "响应中发现 AWS 区域信息",
        "description": "响应中出现 AWS 区域标识，可用于云资源暴露面梳理。",
    },
    54: {
        "slug": "oauth-access-token",
        "title": "响应中发现 OAuth 访问令牌",
        "description": "响应中出现 OAuth 访问令牌格式，应确认其是否仍可使用。",
    },
    55: {
        "slug": "application-error",
        "title": "响应中发现应用错误信息",
        "description": "响应中出现数据库或容器错误特征，可能泄露实现细节。",
    },
    57: {
        "slug": "source-map-reference",
        "title": "响应中发现 Source Map 引用",
        "description": "响应中出现 JavaScript Source Map 引用，可能暴露前端源码映射。",
    },
    58: {
        "slug": "wecom-credential",
        "title": "响应中发现企业微信凭据字段值",
        "description": "响应中出现带值的企业微信 CorpId 或 CorpSecret 字段，应确认其是否为有效凭据。",
        "pattern": r"(?i)[\"']?corp(id|secret)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_-]{6,}[\"']",
    },
    60: {
        "slug": "aliyun-access-key",
        "title": "响应中发现阿里云访问密钥标识",
        "description": "响应中出现阿里云访问密钥 ID 格式，应确认其是否为有效凭据。",
        "pattern": r"\bLTAI[a-zA-Z0-9]{12,20}\b",
    },
    999: {
        "slug": "openid-appsecret",
        "title": "响应中发现 OpenID 或 AppSecret 字段值",
        "description": "响应中出现带值的 OpenID 或 AppSecret 字段，可能泄露第三方应用凭据。",
    },
}

DEFAULT_REMEDIATION = "确认该响应内容是否应公开；移除不必要的数据，并轮换已暴露的凭据。"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="将 TscanPlus 指纹、信息规则和 POC 元数据转换为 EasyScan 资源。")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE, help="TscanPlus config 目录。")
    parser.add_argument("--output-root", type=Path, default=PROJECT_ROOT, help="EasyScan 项目根目录。")
    parser.add_argument("--skip-go-check", action="store_true", help="跳过 Go RE2 正则编译检查。")
    return parser.parse_args()


def read_source_text(path: Path) -> str:
    """Read UTF-8 resources while safely rejecting binary/garbled update files."""

    raw = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError("source", raw, 0, min(1, len(raw)), "unsupported source encoding")


def load_yaml(path: Path) -> Any:
    return yaml.safe_load(read_source_text(path))


def unique_strings(values: Any) -> list[str]:
    """Normalize TscanPlus list-or-comma-string fields without changing order."""

    if values is None:
        return []
    if isinstance(values, str):
        items: Iterable[Any] = re.split(r"[,，\s]+", values)
    elif isinstance(values, (list, tuple, set)):
        items = values
    else:
        items = [values]
    result: list[str] = []
    seen: set[str] = set()
    for item in items:
        text = str(item).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def valid_statuses(values: Any) -> list[int]:
    result: list[int] = []
    for item in unique_strings(values):
        try:
            status = int(item)
        except ValueError:
            continue
        if 100 <= status <= 599 and status not in result:
            result.append(status)
    return result


def canonical_product_name(name: str, template_id: str = "") -> str:
    """Return a short product name suitable for the fingerprint UI."""

    if template_id in AFROG_PRODUCT_NAMES:
        return AFROG_PRODUCT_NAMES[template_id]
    value = re.sub(r"\s+", " ", str(name)).strip(" -–—")
    value = re.sub(r"^(?:Detect|Detection)\s+", "", value, flags=re.IGNORECASE)
    # Remove display-only suffixes repeatedly.  Components such as Actuator
    # and Ops Manager are intentionally not in this list.
    suffix = re.compile(
        r"(?:\s*[-–—]?\s*)(?:version(?:\s+detect)?|detect(?:ion)?|"
        r"login(?:\s+panel)?|admin(?:\s+login)?|dashboard|panel|browser|console)\s*$",
        re.IGNORECASE,
    )
    previous = ""
    while value and value != previous:
        previous = value
        value = suffix.sub("", value).strip(" -–—")
    return value or template_id or str(name)


def fingerprint_record(
    *,
    name: str,
    source: str,
    paths: Any,
    status: Any,
    body_contains: Any = None,
    body_not_contains: Any = None,
    content_type_contains: Any = None,
    header_contains: Any = None,
) -> dict[str, Any]:
    """Build the stable passive-path fingerprint schema expected by EasyScan."""

    return {
        "name": name,
        "source": source,
        "paths": unique_strings(paths),
        "status": valid_statuses(status),
        "body_contains": unique_strings(body_contains),
        "body_not_contains": unique_strings(body_not_contains),
        "content_type_contains": unique_strings(content_type_contains),
        "header_contains": unique_strings(header_contains),
    }


def convert_fingerdir(source: Path) -> tuple[list[dict[str, Any]], int]:
    document = load_yaml(source / "FingerDir.yaml")
    if not isinstance(document, dict):
        raise ValueError("FingerDir.yaml 顶层必须是映射表")

    converted: list[dict[str, Any]] = []
    skipped = 0
    for raw_name, raw_rule in document.items():
        if LEGACY_OR_TEST_NAME.search(str(raw_name)):
            skipped += 1
            continue
        if not isinstance(raw_rule, dict):
            skipped += 1
            continue
        matchers = raw_rule.get("matchers") or {}
        if not isinstance(matchers, dict):
            skipped += 1
            continue
        record = fingerprint_record(
            name=FINGERDIR_PRODUCT_NAMES.get(str(raw_name), canonical_product_name(str(raw_name))),
            source="tscanplus/fingerdir",
            paths=raw_rule.get("paths"),
            status=matchers.get("status"),
            body_contains=matchers.get("body_contains"),
            body_not_contains=matchers.get("body_not_contains"),
            content_type_contains=matchers.get("content_type"),
            header_contains=matchers.get("header_contains"),
        )
        if not record["paths"] or not record["status"]:
            skipped += 1
            continue
        converted.append(record)
    return converted, skipped


def decode_dsl_literal(value: str) -> str | None:
    try:
        decoded = ast.literal_eval(value)
    except (SyntaxError, ValueError):
        return None
    return decoded if isinstance(decoded, str) else None


def _replace_matches(text: str, matches: list[tuple[int, int, str]]) -> str:
    """Replace recognised DSL predicates with symbolic tokens for validation."""

    result = text
    for start, end, symbol in sorted(matches, reverse=True):
        result = result[:start] + symbol + result[end:]
    return result


def parse_clean_response_expression(expression: str) -> dict[str, list[Any]] | None:
    """Translate a deliberately small, lossless subset of Afrog response DSL.

    A target EasyScan fingerprint stores a list of markers with OR semantics.
    Source expressions requiring two positive markers with AND semantics are
    rejected here rather than weakened to an inaccurate broad match.
    """

    matches: list[tuple[int, int, str]] = []
    status: list[int] = []
    body_contains: list[str] = []
    body_not_contains: list[str] = []
    header_contains: list[str] = []
    content_type_contains: list[str] = []

    for match in STATUS_CALL.finditer(expression):
        matches.append((match.start(), match.end(), "S"))
        code = int(match.group("value"))
        if code not in status:
            status.append(code)

    def consume_calls(
        matcher: re.Pattern[str],
        positive: list[str],
        negative: list[str] | None,
        symbol: str,
    ) -> None:
        for match in matcher.finditer(expression):
            decoded = decode_dsl_literal(match.group("value"))
            if decoded is None or not decoded:
                continue
            negated = bool(match.groupdict().get("neg") and match.group("neg").strip())
            if negated and negative is not None:
                if decoded not in negative:
                    negative.append(decoded)
            elif not negated and decoded not in positive:
                positive.append(decoded)
            else:
                continue
            matches.append((match.start(), match.end(), symbol))

    consume_calls(BODY_CALL, body_contains, body_not_contains, "E")
    consume_calls(HEADER_CALL, header_contains, None, "E")
    consume_calls(CONTENT_TYPE_CALL, content_type_contains, None, "E")

    if not matches or not status or not (body_contains or header_contains or content_type_contains):
        return None
    # Reject expressions that contain unrecognised predicates, variables,
    # extractors, or transport details.  Parentheses and boolean operators are
    # the only syntax allowed around recognised response predicates.
    symbolic = _replace_matches(expression, matches)
    if re.sub(r"[SE\s()&|]+", "", symbolic):
        return None

    # Remove a status condition connected with AND, then test whether the
    # remaining response evidence had an AND relationship of its own.
    evidence_logic = symbolic
    for _ in range(8):
        next_logic = re.sub(r"\bS\s*&&\s*", "", evidence_logic)
        next_logic = re.sub(r"\s*&&\s*S\b", "", next_logic)
        if next_logic == evidence_logic:
            break
        evidence_logic = next_logic
    if re.search(r"E\s*&&\s*E", evidence_logic):
        return None

    return {
        "status": status,
        "body_contains": body_contains,
        "body_not_contains": body_not_contains,
        "content_type_contains": content_type_contains,
        "header_contains": header_contains,
    }


def is_static_safe_path(path: Any) -> bool:
    if not isinstance(path, str) or not path.startswith("/"):
        return False
    lowered = path.lower()
    # PathDatabase uses exact URL paths and deliberately does not include a
    # query string in its match key.  Dropping the query would broaden a
    # source rule, so query/fragment routes are excluded instead.
    return not any(token in lowered for token in ("?", "#", "{{", "}}", "${", "..;", "%2e", "%3b", "\x00"))


def afrog_template_is_product_only(template_id: str, info: dict[str, Any]) -> bool:
    if template_id in AFROG_EXCLUDED_IDS:
        return False
    descriptor = " ".join(
        [template_id, str(info.get("name", "")), " ".join(unique_strings(info.get("tags")))]
    )
    return not AFROG_UNSAFE_NAME.search(descriptor)


def convert_afrog_fingerprints(source: Path) -> tuple[list[dict[str, Any]], collections.Counter[str]]:
    root = source / "Pocs" / "afrog" / "afrog-pocs" / "fingerprinting"
    selected: list[dict[str, Any]] = []
    stats: collections.Counter[str] = collections.Counter()
    grouped: dict[tuple[Any, ...], dict[str, Any]] = {}

    for path in sorted([*root.rglob("*.yaml"), *root.rglob("*.yml")]):
        stats["templates_total"] += 1
        try:
            document = load_yaml(path)
        except Exception:
            stats["invalid_yaml"] += 1
            continue
        if not isinstance(document, dict):
            stats["invalid_yaml"] += 1
            continue
        info = document.get("info") or {}
        template_id = str(document.get("id") or path.stem).strip()
        if not isinstance(info, dict) or str(info.get("severity", "")).lower() != "info":
            stats["non_info"] += 1
            continue
        if not afrog_template_is_product_only(template_id, info):
            stats["non_product_or_probe"] += 1
            continue
        rules = document.get("rules")
        if not isinstance(rules, dict):
            stats["invalid_rules"] += 1
            continue
        template_selected = False
        for _, rule in rules.items():
            if not isinstance(rule, dict):
                stats["unsupported_rule"] += 1
                continue
            request = rule.get("request") or {}
            if not isinstance(request, dict):
                stats["unsupported_rule"] += 1
                continue
            transport = str(request.get("type", "http")).strip().lower()
            method = str(request.get("method", "")).strip().upper()
            request_path = request.get("path")
            if transport not in ("", "http") or method != "GET" or not is_static_safe_path(request_path):
                stats["non_static_get"] += 1
                continue
            expression = rule.get("expression")
            if not isinstance(expression, str):
                stats["unsupported_expression"] += 1
                continue
            evidence = parse_clean_response_expression(expression)
            if evidence is None:
                stats["unsupported_expression"] += 1
                continue
            product = canonical_product_name(str(info.get("name") or template_id), template_id)
            record = fingerprint_record(
                name=product,
                source=f"tscanplus/afrog-fingerprinting/{path.name}",
                paths=[request_path],
                status=evidence["status"],
                body_contains=evidence["body_contains"],
                body_not_contains=evidence["body_not_contains"],
                content_type_contains=evidence["content_type_contains"],
                header_contains=evidence["header_contains"],
            )
            signature = (
                record["name"],
                record["source"],
                tuple(record["status"]),
                tuple(record["body_contains"]),
                tuple(record["body_not_contains"]),
                tuple(record["content_type_contains"]),
                tuple(record["header_contains"]),
            )
            existing = grouped.get(signature)
            if existing is None:
                grouped[signature] = record
                selected.append(record)
            else:
                existing["paths"] = unique_strings([*existing["paths"], request_path])
            template_selected = True
            stats["rules_selected"] += 1
        if template_selected:
            stats["templates_selected"] += 1
    return selected, stats


def response_targets(item: dict[str, Any]) -> list[str]:
    targets: list[str] = []
    if item.get("EnableForHeader"):
        targets.append("response_headers")
    if item.get("EnableForBody"):
        targets.append("response_body")
    return targets


def convert_js_information_rules(source: Path) -> tuple[list[dict[str, Any]], int]:
    raw = json.loads(read_source_text(source / "JsRule.json"))
    if not isinstance(raw, list):
        raise ValueError("JsRule.json 顶层必须是数组")
    by_index = {item.get("Index"): item for item in raw if isinstance(item, dict)}
    converted: list[dict[str, Any]] = []
    for index, spec in JS_INFORMATION_RULES.items():
        item = by_index.get(index)
        if item is None or not item.get("EnableForResponse"):
            raise ValueError(f"JsRule {index} 不存在或不是响应方向规则")
        targets = response_targets(item)
        if not targets:
            raise ValueError(f"JsRule {index} 缺少响应正文/响应头目标")
        pattern = spec.get("pattern") or str(item.get("Rule") or "")
        if not pattern:
            raise ValueError(f"JsRule {index} 缺少正则")
        converted.append(
            {
                "id": f"tscan.info.{spec['slug']}",
                "title": spec["title"],
                "severity": "info",
                "confidence": "tentative",
                "targets": targets,
                "pattern": pattern,
                "description": spec["description"],
                "remediation": DEFAULT_REMEDIATION,
                "tags": ["tscan", "passive", "information-disclosure"],
            }
        )
    return converted, len(raw)


def poc_source_and_category(relative: Path) -> tuple[str, str]:
    parts = relative.parts
    if len(parts) >= 3 and parts[0].lower() == "afrog" and parts[1].lower() == "afrog-pocs":
        raw_category = parts[2].lower()
        categories = {
            "vulnerability": "web-vulnerability",
            "cve": "cve",
            "cnvd": "cnvd",
            "fingerprinting": "fingerprint",
            "default-pwd": "weak-password",
            "unauthorized": "unauthorized-access",
            "disclosure": "information-disclosure",
        }
        return f"afrog/{raw_category}", categories.get(raw_category, raw_category)
    if len(parts) >= 2 and parts[0].lower() == "xray":
        source = f"xray/{parts[1]}"
        return source, "web-vulnerability"
    if parts and parts[0].lower() == "update":
        return "tscanplus/update", "web-vulnerability"
    return "tscanplus/unknown", "unknown"


def metadata_tags(*values: Any) -> list[str]:
    tags: list[str] = []
    for value in values:
        for tag in unique_strings(value):
            normalized = tag.strip().lower()
            if not normalized or normalized in tags:
                continue
            tags.append(normalized)
    return tags


def normalized_severity(value: Any) -> str:
    severity = str(value or "").strip().lower()
    return severity if severity in {"critical", "high", "medium", "low", "info"} else "unknown"


def poc_metadata(document: dict[str, Any], path: Path, relative: Path) -> dict[str, Any]:
    info = document.get("info") if isinstance(document.get("info"), dict) else {}
    detail = document.get("detail") if isinstance(document.get("detail"), dict) else {}
    vulnerability = detail.get("vulnerability") if isinstance(detail.get("vulnerability"), dict) else {}
    source, category = poc_source_and_category(relative)
    original_id = str(document.get("id") or document.get("name") or path.stem).strip()
    name = str(info.get("name") or document.get("name") or original_id).strip()
    return {
        "id": original_id or path.stem,
        "name": name or original_id or path.stem,
        "source": source,
        "category": category,
        "severity": normalized_severity(info.get("severity") or vulnerability.get("level") or document.get("severity")),
        "tags": metadata_tags(info.get("tags"), detail.get("tags"), document.get("tags")),
    }


def build_poc_index(source: Path) -> tuple[list[dict[str, Any]], collections.Counter[str], int]:
    root = source / "Pocs"
    files = sorted([*root.rglob("*.yaml"), *root.rglob("*.yml")])
    records: list[dict[str, Any]] = []
    source_stats: collections.Counter[str] = collections.Counter()
    skipped = 0
    used_ids: collections.Counter[str] = collections.Counter()
    for path in files:
        relative = path.relative_to(root)
        try:
            document = load_yaml(path)
        except Exception:
            skipped += 1
            continue
        if not isinstance(document, dict):
            skipped += 1
            continue
        record = poc_metadata(document, path, relative)
        used_ids[record["id"]] += 1
        if used_ids[record["id"]] > 1:
            record["id"] = f"{record['id']}--{used_ids[record['id']]}"
        records.append(record)
        source_stats[record["source"]] += 1
    records.sort(key=lambda item: (item["source"], item["id"], item["name"]))
    return records, source_stats, skipped


def write_yaml(path: Path, document: Any, heading: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "# " + heading + "\n# 由 tools/convert_tscan_resources.py 生成；请勿手工复制 TscanPlus 的主动 POC 内容。\n"
    content += yaml.safe_dump(document, allow_unicode=True, sort_keys=False, width=120)
    path.write_text(content, encoding="utf-8", newline="\n")


def write_json(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def verify_go_regex(rules: list[dict[str, Any]], output_root: Path) -> None:
    go = shutil.which("go")
    if not go:
        raise RuntimeError("未找到 Go，无法执行 RE2 正则编译检查。")
    entries = "\n".join(
        f"\t{{{json.dumps(rule['id'], ensure_ascii=False)}, {json.dumps(rule['pattern'], ensure_ascii=False)}}},"
        for rule in rules
    )
    program = f'''package main

import (
    "fmt"
    "os"
    "regexp"
)

func main() {{
    rules := []struct {{ id, pattern string }}{{
{entries}
    }}
    for _, rule := range rules {{
        if _, err := regexp.Compile(rule.pattern); err != nil {{
            fmt.Fprintf(os.Stderr, "%s: %v\\n", rule.id, err)
            os.Exit(1)
        }}
    }}
    fmt.Printf("RE2 OK: %d\\n", len(rules))
}}
'''
    with tempfile.TemporaryDirectory(prefix="easyscan-re2-") as temporary:
        check_file = Path(temporary) / "check.go"
        check_file.write_text(program, encoding="utf-8", newline="\n")
        result = subprocess.run(
            [go, "run", str(check_file)],
            cwd=output_root,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"Go RE2 正则检查失败：{detail}")
    print(result.stdout.strip())


def main() -> int:
    args = parse_args()
    source = args.source.resolve()
    output_root = args.output_root.resolve()
    required = [source / "FingerDir.yaml", source / "JsRule.json", source / "Pocs"]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise SystemExit("缺少 TscanPlus 资源：" + "；".join(missing))

    fingerdir, fingerdir_skipped = convert_fingerdir(source)
    afrog, afrog_stats = convert_afrog_fingerprints(source)
    fingerprints = [*fingerdir, *afrog]
    rules, js_total = convert_js_information_rules(source)
    pocs, poc_source_stats, poc_skipped = build_poc_index(source)

    write_yaml(
        output_root / FINGERPRINT_OUTPUT,
        {"fingerprints": fingerprints},
        "TscanPlus 路由型被动指纹。仅匹配已经观察到的请求/响应，不发起新请求。",
    )
    write_yaml(
        output_root / RULE_OUTPUT,
        {"rules": rules},
        "TscanPlus 响应型信息发现规则。",
    )
    # Keep the root an array so each item has exactly the six catalogue
    # metadata fields.  In particular, no POC request, variable, expression or
    # payload field can enter this file.
    write_json(output_root / POC_INDEX_OUTPUT, pocs)

    print("TscanPlus 资源转换完成：")
    print(f"  FingerDir 指纹：{len(fingerdir)} 条（跳过旧备份/测试或无效项 {fingerdir_skipped} 条）")
    print(f"  Afrog 指纹：{len(afrog)} 条规则组，来自 {afrog_stats['templates_selected']} 个纯信息产品模板")
    print(
        "  Afrog 过滤："
        f"总模板 {afrog_stats['templates_total']}，非 info {afrog_stats['non_info']}，"
        f"通用/漏洞/探测项 {afrog_stats['non_product_or_probe']}，"
        f"非静态 GET {afrog_stats['non_static_get']}，"
        f"不支持或会弱化语义的表达式 {afrog_stats['unsupported_expression']}。"
    )
    print(f"  指纹合计：{len(fingerprints)} 条")
    print(f"  JsRule 信息规则：{len(rules)} / {js_total} 条（仅响应方向且经人工策展）")
    if args.skip_go_check:
        print("  Go RE2 正则检查：已跳过")
    else:
        verify_go_regex(rules, output_root)
    print(f"  POC 元数据索引：{len(pocs)} 条，跳过不可解析/二进制文件 {poc_skipped} 条")
    print("  POC 来源统计：")
    for label, count in sorted(poc_source_stats.items()):
        print(f"    {label}: {count}")
    print(f"  输出：{FINGERPRINT_OUTPUT}；{RULE_OUTPUT}；{POC_INDEX_OUTPUT}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"转换失败：{exc}", file=sys.stderr)
        raise SystemExit(1)
