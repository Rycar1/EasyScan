import * as DesktopBindings from "../wailsjs/go/desktop/App";
import type {TaskRequest} from "./types";

type BindingFunction = (...args: unknown[]) => Promise<unknown>;
type BindingSurface = Record<string, unknown>;

const bindings = DesktopBindings as unknown as BindingSurface;

function method(...names: string[]): BindingFunction {
  for (const name of names) {
    const candidate = bindings[name];
    if (typeof candidate === "function") {
      return candidate as BindingFunction;
    }
  }
  throw new Error(`桌面端绑定不可用: ${names[0]}`);
}

export const desktopApi = {
  getSnapshot: (): Promise<unknown> => method("GetSnapshot", "Snapshot")(),
  startServices: async (): Promise<void> => {
    await method("StartServices")();
  },
  stopServices: async (): Promise<void> => {
    await method("StopServices")();
  },
  submitTask: (request: TaskRequest): Promise<unknown> => method("SubmitTask")(request),
  cancelTask: async (id: string): Promise<void> => {
    await method("CancelTask")(id);
  },
  getTaskResults: (id: string): Promise<unknown> => method("GetTaskResults", "TaskResults")(id),
  getFindingEvidence: (id: string): Promise<unknown> => method("FindingEvidence", "GetFindingEvidence")(id),
  updateFeature: async (id: string, enabled: boolean): Promise<void> => {
    await method("UpdateFeature", "SetFeature")(id, enabled);
  },
  updateSQLiTechniques: async (errorEnabled: boolean, booleanEnabled: boolean, timeEnabled: boolean): Promise<void> => {
    await method("UpdateSQLiTechniques", "SetSQLiTechniques")(errorEnabled, booleanEnabled, timeEnabled);
  },
  importHFingerRule: (): Promise<unknown> => method("ImportHFingerRule")(),
  reloadHFingerRules: (): Promise<unknown> => method("ReloadHFingerRules")(),
  updatePassiveSQLiProbeQPS: async (qps: number): Promise<void> => {
    await method("SetPassiveSQLiProbeQPS")(qps);
  },
  updatePassiveSQLiMaxRequests: async (requests: number): Promise<void> => {
    await method("SetPassiveSQLiMaxRequests")(requests);
  },
  updatePassiveSQLiMaxParameters: async (parameters: number): Promise<void> => {
    await method("SetPassiveSQLiMaxParameters")(parameters);
  },
  updatePassiveXSSProbeQPS: async (qps: number): Promise<void> => {
    await method("SetPassiveXSSProbeQPS")(qps);
  },
  updatePassiveXSSMaxRequests: async (requests: number): Promise<void> => {
    await method("SetPassiveXSSMaxRequests")(requests);
  },
  updatePassiveXSSMaxParameters: async (parameters: number): Promise<void> => {
    await method("SetPassiveXSSMaxParameters")(parameters);
  },
  updatePassivePOCQPS: async (qps: number): Promise<void> => {
    await method("SetPassivePOCQPS")(qps);
  },
  updatePassivePOCConcurrency: async (concurrency: number): Promise<void> => {
    await method("SetPassivePOCConcurrency")(concurrency);
  },
  updatePassiveFileProbeQPS: async (qps: number): Promise<void> => {
    await method("SetPassiveFileProbeQPS")(qps);
  },
  updatePassiveFileProbeMaxPrefixes: async (max: number): Promise<void> => {
    await method("SetPassiveFileProbeMaxPrefixes")(max);
  },
  updatePassiveFastjsonProbeQPS: async (qps: number): Promise<void> => {
    await method("SetPassiveFastjsonProbeQPS")(qps);
  },
  updatePassiveShiroProbeQPS: async (qps: number): Promise<void> => {
    await method("SetPassiveShiroProbeQPS")(qps);
  },
  updateShiroKeys: async (keys: string[]): Promise<void> => {
    await method("SetShiroKeys")(keys);
  },
  updateOOBDomain: async (domain: string): Promise<void> => {
    await method("SetOOBDomain")(domain);
  },
  getAISettings: (): Promise<unknown> => method("GetAISettings")(),
  saveAISettings: async (baseUrl: string, model: string, apiKey: string): Promise<void> => {
    await method("SaveAISettings")(baseUrl, model, apiKey);
  },
  updateExcludedDomains: async (domains: string[]): Promise<string[]> => {
    const result = await method("UpdateExcludedDomains", "SetExcludedDomains")(domains);
    return Array.isArray(result) ? result.map((domain) => String(domain)) : [];
  },
  updateExcludedSuffixes: async (suffixes: string[]): Promise<string[]> => {
    const result = await method("SetExcludedSuffixes")(suffixes);
    return Array.isArray(result) ? result.map((suffix) => String(suffix)) : [];
  },
  updateExcludedContentTypes: async (contentTypes: string[]): Promise<string[]> => {
    const result = await method("SetExcludedContentTypes")(contentTypes);
    return Array.isArray(result) ? result.map((contentType) => String(contentType)) : [];
  },
  updateExcludedPaths: async (paths: string[]): Promise<string[]> => {
    const result = await method("SetExcludedPaths")(paths);
    return Array.isArray(result) ? result.map((path) => String(path)) : [];
  },
  updateExcludedQueryParameters: async (parameters: string[]): Promise<string[]> => {
    const result = await method("SetExcludedQueryParameters")(parameters);
    return Array.isArray(result) ? result.map((parameter) => String(parameter)) : [];
  },
  updateExcludedPostParameters: async (parameters: string[]): Promise<string[]> => {
    const result = await method("SetExcludedPostParameters")(parameters);
    return Array.isArray(result) ? result.map((parameter) => String(parameter)) : [];
  },
  updateSwaggerExcludedPaths: async (paths: string[]): Promise<string[]> => {
    const result = await method("SetSwaggerExcludedPaths")(paths);
    return Array.isArray(result) ? result.map((path) => String(path)) : [];
  },
  updateCustomProbePaths: async (paths: string[]): Promise<string[]> => {
    const result = await method("SetCustomProbePaths")(paths);
    return Array.isArray(result) ? result.map((path) => String(path)) : [];
  },
  getNucleiStatus: (): Promise<unknown> => method("GetNucleiStatus")(),
  setNucleiBinaryPath: (path: string): Promise<unknown> => method("SetNucleiBinaryPath")(path),
  downloadNuclei: (): Promise<unknown> => method("DownloadNuclei")(),
  getRuntimeLogs: (limit: number): Promise<unknown> => method("RuntimeLogs", "GetRuntimeLogs")(limit),
};
