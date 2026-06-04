# 02 — Request Classifier

> **Historical note:** these describe the original *Rust* plan; the code shipped in **Go** (see go.mod and internal/). See ../README.md and ../SPEC.md for the as-built design.

**Depends on**: 01

## Summary

Extract `(owner/repo, read|write)` from incoming HTTP requests. This is the input to the policy engine.

## Tasks

### REST
- [ ] Parse `/api/v3/repos/{owner}/{repo}/**` to extract `owner/repo`
- [ ] Parse `/api/v3/orgs/{org}/**` to extract org (no repo)
- [ ] `/api/v3/user/**`, `/api/v3/search/**` → no repo, user-level
- [ ] HTTP method → access level: `GET`/`HEAD` → `Read`, else → `Write`

### GraphQL (minimal)
- [ ] Parse JSON body, extract `query` string
- [ ] Detect `mutation` keyword → `Write`, else → `Read`
- [ ] No repo extraction in v1 — returns `repo: None`

### Types
- [ ] `AccessLevel` enum: `Read`, `Write`
- [ ] `ClassifiedRequest { repo: Option<(owner, repo)>, org: Option<org>, access: AccessLevel }`

### Tests
- [ ] All REST URL patterns (repos, orgs, user, search, root)
- [ ] GraphQL mutation vs query detection
- [ ] Edge cases: trailing slashes, `/api/v3/repos/{owner}/{repo}` with no sub-path, unknown paths

## Acceptance

Unit tests cover all URL patterns. Unknown paths return `repo: None`. GraphQL correctly distinguishes mutations from queries.
