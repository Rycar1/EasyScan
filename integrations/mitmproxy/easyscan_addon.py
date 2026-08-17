"""Forward observed mitmproxy HTTP flows to a local EasyScan instance.

Run only while proxying traffic you are authorized to inspect:
  mitmproxy -s integrations/mitmproxy/easyscan_addon.py \
    --set easyscan_endpoint=http://127.0.0.1:8787/api/v1/traffic
"""
import json
import urllib.request
from mitmproxy import ctx, http


class EasyScan:
    def load(self, loader):
        loader.add_option("easyscan_endpoint", str, "http://127.0.0.1:8787/api/v1/traffic", "EasyScan traffic endpoint")
        loader.add_option("easyscan_token", str, "", "Optional EasyScan bearer token")

    def response(self, flow: http.HTTPFlow):
        payload = {
            "source": "mitmproxy",
            "request": {"method": flow.request.method, "url": flow.request.pretty_url, "headers": dict(flow.request.headers), "body": flow.request.get_text(strict=False)},
            "response": {"status": flow.response.status_code, "headers": dict(flow.response.headers), "body": flow.response.get_text(strict=False)},
        }
        headers = {"Content-Type": "application/json"}
        if ctx.options.easyscan_token:
            headers["Authorization"] = "Bearer " + ctx.options.easyscan_token
        request = urllib.request.Request(ctx.options.easyscan_endpoint, data=json.dumps(payload).encode(), headers=headers, method="POST")
        try:
            urllib.request.urlopen(request, timeout=2).close()
        except Exception as exc:
            ctx.log.debug(f"EasyScan forwarding skipped: {exc}")


addons = [EasyScan()]
