// Load unpacked only for assets you are authorized to test. Chrome exposes
// complete response content to DevTools extensions, so no data is retained by
// this extension; it is forwarded only to the configured local EasyScan API.
const defaults = { endpoint: "http://127.0.0.1:8787/api/v1/traffic", token: "" };

async function settings() {
  return { ...defaults, ...(await chrome.storage.local.get(defaults)) };
}

function headers(list) {
  return Object.fromEntries((list || []).map(({ name, value }) => [name, value]));
}

chrome.devtools.network.onRequestFinished.addListener(async entry => {
  const cfg = await settings();
  if (!/^https?:\/\//i.test(entry.request.url)) return;
  entry.getContent(async body => {
    const payload = {
      source: "chrome-devtools",
      observed_at: new Date().toISOString(),
      request: { method: entry.request.method, url: entry.request.url, headers: headers(entry.request.headers), body: entry.request.postData?.text || "" },
      response: { status: entry.response.status, headers: headers(entry.response.headers), body: body || "" }
    };
    try {
      await fetch(cfg.endpoint, { method: "POST", headers: { "Content-Type": "application/json", ...(cfg.token ? { Authorization: `Bearer ${cfg.token}` } : {}) }, body: JSON.stringify(payload) });
    } catch (_) { /* EasyScan may not be running; do not affect browsing. */ }
  });
});
