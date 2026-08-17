import type {RefObject, UIEventHandler} from "react";
import {Filter20Regular} from "@fluentui/react-icons";
import type {PassiveLogSummary, RuntimeLog} from "../types";

type RuntimeLogTone = "debug" | "info" | "success" | "warning" | "error";
type RuntimeLogKind = "request" | "finding" | "information" | "fingerprint" | "system";

type RuntimeLogDisplay =
  | {kind: "request"; method: string; target: string; status: string}
  | {kind: "fingerprint"; target: string; fingerprint: string}
  | {kind: "finding"; target: string; title: string}
  | {kind: "information"; target: string; title: string}
  | {kind: "system"; message: string};

interface PassiveLogConsoleProps {
  logs: RuntimeLog[];
  summary: PassiveLogSummary;
  filterRuleCount: number;
  isFollowingTail: boolean;
  onOpenFilters: () => void;
  onResumeTail: () => void;
  onScroll: UIEventHandler<HTMLDivElement>;
  titleByRuleId: Readonly<Record<string, string>>;
  viewportRef: RefObject<HTMLDivElement | null>;
}

export const logTailTolerance = 2;

function runtimeLogTone(level: string): RuntimeLogTone {
  switch (level.trim().toLowerCase()) {
    case "trace":
    case "debug":
      return "debug";
    case "success":
    case "ok":
      return "success";
    case "warn":
    case "warning":
      return "warning";
    case "error":
    case "fatal":
    case "panic":
      return "error";
    default:
      return "info";
  }
}

function runtimeLogLabel(level: string): string {
  switch (runtimeLogTone(level)) {
    case "debug": return "DBG";
    case "success": return "OK";
    case "warning": return "WRN";
    case "error": return "ERR";
    default: return "INF";
  }
}

function runtimeLogKind(component: string): RuntimeLogKind {
  const normalized = component.trim().toLowerCase();
  if (normalized === "finding") {
    return "finding";
  }
  if (normalized === "information") {
    return "information";
  }
  if (normalized === "fingerprint") {
    return "fingerprint";
  }
  if (normalized === "request") {
    return "request";
  }
  return "system";
}

export function isPassiveRuntimeLog(log: RuntimeLog): boolean {
  const kind = runtimeLogKind(log.component);
  const tone = runtimeLogTone(log.level);
  // 单个请求由底部汇总计数表示，原始事件仍保留在后端日志环中。
  if (kind === "request") {
    return false;
  }
  return kind !== "system" || tone === "warning" || tone === "error";
}

export function passiveRuntimeLogSignature(logs: RuntimeLog[]): string {
  return logs
    .filter(isPassiveRuntimeLog)
    .map((log) => [log.id, log.createdAt, log.level, log.component, log.message].join("\u001f"))
    .join("\u001e");
}

function runtimeLogDisplay(log: RuntimeLog, titleByRuleId: Readonly<Record<string, string>>): RuntimeLogDisplay {
  const kind = runtimeLogKind(log.component);
  if (kind === "request") {
    const match = /^接收请求：([A-Z]+)\s+(.+?)\s+→\s+(\d{3})/u.exec(log.message);
    if (match) {
      return {kind, method: match[1], target: match[2], status: match[3]};
    }
  }
  if (kind === "fingerprint") {
    const match = /^识别指纹：(.+?)（(.+)）$/u.exec(log.message);
    if (match) {
      return {kind, fingerprint: match[1], target: match[2]};
    }
  }
  if (kind === "finding" || kind === "information") {
    const match = /^发现风险：(.+?)（.+?，规则：(.+?)，目标：(.+)）$/u.exec(log.message);
    if (match) {
      return {kind, title: titleByRuleId[match[2]] || match[1], target: match[3]};
    }
  }
  return {kind: "system", message: log.message};
}

function RuntimeLogLine({log, titleByRuleId}: {log: RuntimeLog; titleByRuleId: Readonly<Record<string, string>>}) {
  const display = runtimeLogDisplay(log, titleByRuleId);
  return (
    <div className={`runtime-log-line is-${runtimeLogTone(log.level)} is-kind-${display.kind}`}>
      <span className="runtime-log-level">[{runtimeLogLabel(log.level)}]</span>
      {display.kind === "request" && <><span className="runtime-log-kind">[请求]</span><strong className="runtime-log-method">{display.method}</strong><code className="runtime-log-url">{display.target}</code><span className="runtime-log-status">{display.status}</span></>}
      {display.kind === "fingerprint" && <><span className="runtime-log-kind">[指纹]</span><code className="runtime-log-url">{display.target}</code><strong className="runtime-log-fingerprint">{display.fingerprint}</strong></>}
      {display.kind === "finding" && <><span className="runtime-log-kind">[漏洞]</span><code className="runtime-log-url">{display.target}</code><strong className="runtime-log-fingerprint">{display.title}</strong></>}
      {display.kind === "information" && <><span className="runtime-log-kind">[信息]</span><code className="runtime-log-url">{display.target}</code><strong className="runtime-log-fingerprint">{display.title}</strong></>}
      {display.kind === "system" && <span className="runtime-log-message">{display.message}</span>}
    </div>
  );
}

function PassiveLogSummaryLine({summary}: {summary: PassiveLogSummary}) {
  return (
    <div className="runtime-log-summary" aria-label="被动扫描汇总">
      <span className="runtime-log-summary-prefix">[*]</span>
      <code>
        已完成HTTP:{summary.doneHttp}, 待处理HTTP:{summary.undoHttp}, 待处理端口:{summary.undoPort}, 待处理任务:{summary.undoTask}, 请求:{summary.requestsDone}/{summary.requestsTotal}, 指纹:{summary.fingerprints}, 漏洞:{summary.vulnerabilities}
      </code>
    </div>
  );
}

export function PassiveLogConsole({
  logs,
  summary,
  filterRuleCount,
  isFollowingTail,
  onOpenFilters,
  onResumeTail,
  onScroll,
  titleByRuleId,
  viewportRef,
}: PassiveLogConsoleProps) {
  return (
    <section className="runtime-log-console" aria-label="被动扫描日志">
      <div className="runtime-log-console-bar">
        <span className="runtime-log-console-title"><span className="runtime-log-live-dot" aria-hidden="true" />被动扫描日志</span>
        <div className="runtime-log-console-meta">
          <button className="runtime-log-filter-button" onClick={onOpenFilters} title="配置 MITM 流量过滤规则" type="button">
            <Filter20Regular aria-hidden="true" />
            <span>MITM 过滤规则</span>
            <span className="runtime-log-filter-count">{filterRuleCount}</span>
          </button>
          <span className="runtime-log-legend"><i className="is-summary">汇总</i><i className="is-finding">漏洞</i><i className="is-fingerprint">指纹</i></span>
          {!isFollowingTail && (
            <button className="runtime-log-follow-button" onClick={onResumeTail} type="button">
              已暂停跟随 <span aria-hidden="true">↓</span> 回到最新
            </button>
          )}
          <span className="runtime-log-console-scope">仅当前会话</span>
        </div>
      </div>
      <div
        ref={viewportRef}
        className="runtime-log-viewport"
        role="log"
        aria-live="polite"
        aria-label="被动扫描原始运行日志"
        onScroll={onScroll}
      >
        <PassiveLogSummaryLine summary={summary} />
        {logs.map((log) => <RuntimeLogLine key={log.id} log={log} titleByRuleId={titleByRuleId} />)}
      </div>
    </section>
  );
}
