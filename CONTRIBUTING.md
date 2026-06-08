# Contributing

## Commit hygiene

- Keep each commit atomic: one logical change, no unrelated cleanup.
- Use Conventional Commits.
- Use past tense, lowercase subjects, no trailing period, ≤72 chars.
- Add a body for non-trivial changes: what changed, why, and any risk or follow-up.

Examples:

```text
fix(proxy): closed rest filter fail-open paths
feat(login): added owner session refresh
docs(readme): documented socket mode default
```

## Pull request hygiene

- Keep PR scope tight. Split unrelated refactors, renames, or mechanical cleanup.
- Describe the problem, the decision, and the verification.
- Call out any security-sensitive behavior changes, default changes, or operator-visible breakage.
- Update tests and docs with the code change; do not leave policy, threat-model, or deployment notes stale.
- Include exact verification commands in the PR body.

Recommended PR checklist:

- [ ] linked issue, ticket, or release goal
- [ ] tests added or updated for the changed behavior
- [ ] `go test ./... -count=1`
- [ ] docs and examples updated when behavior or defaults changed
- [ ] rollout or operator impact called out explicitly

## Release hygiene

- Release only from a clean tree with passing tests.
- Use annotated semver tags: `git tag -a vX.Y.Z -m "vX.Y.Z"`.
- Record the exact verification used for the release.
- For authz, authn, classifier, proxy, or filter changes, also run the live GitHub checks when credentials and an environment are available:
  - `./scripts/smoke-test.sh`
  - `./scripts/gh-cli-matrix.sh <proxy-host> <owner> <allowed-repo> <denied-repo>`
- If a live check could not run, say so in the PR or release notes instead of implying coverage.
