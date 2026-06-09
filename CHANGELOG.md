# Changelog

## v1.1.0

- added `mode = "read"` as a middle-ground default: unmatched repo/org reads are allowed, unmatched writes are denied
- exposed default mode selection (`deny` / `read` / `allow`) in the owner console builder
- kept policy evaluation and helper predicates aligned with the new default mode semantics
- documented the deployment lessons from the live rollout:
  - use the final production hostname from the start
  - do not bootstrap public TLS on a throwaway hostname and swap later
  - public certificate hostnames cannot contain underscores
  - for deeper hostnames behind Cloudflare, prefer DNS only unless edge-cert coverage for that exact name is configured
  - bring up TLS first on the final hostname, then log in through `/ui` when ready
