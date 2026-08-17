# HFinger integration notice

EasyScan vendors the HFinger rule engine and embedded core YAML rules from:

- Project: https://github.com/HackAllSec/hfinger
- Commit: `f8384ae16c2ff8ccec0f8e7170b821d273518eee`
- License: Apache-2.0 (see `LICENSE` and `NOTICE` in this directory)

The vendored subset contains `rules/` and `rulesets/`, which are the packages used by EasyScan's passive MITM fingerprint adapter. Networking, CLI, proxy, reporting, and active scanning packages from HFinger are not bundled because EasyScan supplies the captured HTTP transaction directly to the rule matcher.
