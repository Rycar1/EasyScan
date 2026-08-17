# EasyScan Chrome DevTools capture adapter

This optional unpacked DevTools extension forwards traffic from the currently
inspected tab to a local EasyScan server. It is intended only for applications
you are authorized to test.

1. Start `easyscan serve` for headless mode, or launch `easyscan-desktop.exe` for the Wails desktop client.
2. In Chrome, open `chrome://extensions`, enable developer mode, and choose
   **Load unpacked** for this directory.
3. Open DevTools for an authorized target. Captured HTTP/HTTPS transactions are
   forwarded asynchronously to `http://127.0.0.1:8787/api/v1/traffic`.

For a protected EasyScan API, set `endpoint` and `token` through DevTools
console before capture:

```js
chrome.storage.local.set({ endpoint: "http://127.0.0.1:8787/api/v1/traffic", token: "your-token" })
```

The extension deliberately has no broad host permissions and does not retain
traffic on disk. Chrome only makes response bodies available while DevTools is
open for the inspected tab.
