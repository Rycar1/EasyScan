# mitmproxy adapter

This optional addon forwards already-decrypted mitmproxy request/response flows
to EasyScan's local traffic API. It neither probes targets nor stores traffic.

```bash
mitmproxy -s integrations/mitmproxy/easyscan_addon.py \
  --set easyscan_endpoint=http://127.0.0.1:8787/api/v1/traffic
```

Use only with traffic and hosts you are authorized to intercept. If the API has
a token, add `--set easyscan_token=YOUR_TOKEN`.
