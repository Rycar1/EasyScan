# HFinger fingerprint accuracy and regression notes

## Upstream engine

EasyScan vendors the rule engine and embedded core YAML rules from
[HackAllSec/hfinger](https://github.com/HackAllSec/hfinger) commit
`f8384ae16c2ff8ccec0f8e7170b821d273518eee` under Apache-2.0. The vendored
subset contains `rules/` and `rulesets/`; HFinger's networking, CLI, proxy and
active scanning packages are not used.

HFinger is the only product fingerprint engine in the MITM analysis path. The
previous TideFinger, KScan and Wappalyzer execution paths and their bundled
databases were removed.

## Matching policy

1. Matching runs only for EasyScan proxy observations whose source is
   `http-proxy` or `https-mitm`.
2. EasyScan passes the already captured URL, path, status, response headers,
   body, title and response behavior fields to HFinger. The adapter does not
   request an extra route or resource.
3. HFinger confidence is mapped to EasyScan's compact score and reliability
   values. Matches are ordered by confidence and capped by
   `fingerprints.hfinger.max_matches_per_transaction`.
4. HFinger `cdn` category is controlled by `passive.cdn_detection`; the `waf`
   category is now bundled into `passive.hfinger` and no longer has a separate
   switch.
5. On HTTP 4xx/5xx, a product match must contain evidence from the matched
   rule's response header, Cookie, Server banner, TLS or DNS matcher. Body,
   title and path evidence alone are discarded.
6. Low-value labels are filtered before they reach assets or reports:
   `jQuery`, `jQuery official CDN`, `Bootstrap`, `Bootstrap CDN`, `GZIP`,
   `GZIP encode` and `GSE`.

## User YAML lifecycle

- `.yaml` and `.yml` files are loaded recursively from
  `fingerprints.hfinger.custom_dir`.
- Every file is parsed, normalized and schema-validated independently.
- A broken file is reported in `HFingerStats.errors` while valid files remain
  active.
- A custom rule with the same `id` as an embedded rule replaces that embedded
  rule.
- Reload builds a complete immutable rule slice before swapping it under a
  lock, so MITM matching can continue during the reload.
- Desktop import validates before copying, limits a file to 8 MiB, then reloads
  and publishes the updated rule statistics.

## Regression corpus

The committed tests cover:

- embedded rule loading (more than 1,000 rules);
- custom YAML import and positive matching;
- invalid-file isolation;
- nginx `Server` matching;
- WordPress multi-signal body matching;
- Grafana page matching;
- a generic HTML negative fixture;
- jQuery/Bootstrap-only static references producing no low-value labels;
- the Google gateway 404 path-reflection case producing no Discuz result;
- API-imported traffic not entering the MITM HFinger path.

The reported regression is explicit in both adapter and engine tests:

```text
https://safebrowsingohttpgateway.googleapis.com:443/admin/discuzfiles.md5
HTTP 404 + reflected /admin/discuzfiles.md5 => no Discuz fingerprint
```

Run the checks with:

```powershell
go test ./...
go test -race ./internal/fingerprint ./internal/engine
go vet ./...
go build ./...
cd frontend
npm run build
```

These checks describe the repository regression corpus rather than a global
accuracy percentage. Add newly observed false positives as focused fixtures so
that each rule-policy change remains reproducible.
