package nodecache

import (
	"encoding/json"
	"testing"
	"time"
)

func TestIngestExtractsNestedIDs(t *testing.T) {
	c := New(30 * time.Minute)
	defer c.Stop()

	resp := map[string]any{
		"data": map[string]any{
			"repository": map[string]any{
				"pullRequest": map[string]any{
					"id":      "PR_kwDOABC123",
					"node_id": "MDExOlB1bGxSZXF1ZXN0MTIz",
					"author": map[string]any{
						"id": "U_kgDOBuser1",
					},
					"reviews": map[string]any{
						"nodes": []any{
							map[string]any{"id": "PRR_review1"},
							map[string]any{"id": "PRR_review2"},
						},
					},
				},
			},
		},
	}
	body, _ := json.Marshal(resp)
	c.Ingest("myorg", "myrepo", body)

	for _, id := range []string{"PR_kwDOABC123", "MDExOlB1bGxSZXF1ZXN0MTIz", "U_kgDOBuser1", "PRR_review1", "PRR_review2"} {
		reqBody, _ := json.Marshal(map[string]any{"variables": map[string]any{"id": id}})
		owner, repo, ok := c.Lookup(reqBody)
		if !ok {
			t.Fatalf("expected to find %q in cache", id)
		}
		if owner != "myorg" || repo != "myrepo" {
			t.Fatalf("expected myorg/myrepo, got %s/%s for %s", owner, repo, id)
		}
	}
}

func TestLookupFindsNestedVariables(t *testing.T) {
	c := New(30 * time.Minute)
	defer c.Stop()

	resp, _ := json.Marshal(map[string]any{
		"data": map[string]any{
			"repository": map[string]any{
				"pullRequest": map[string]any{"id": "PR_abc"},
			},
		},
	})
	c.Ingest("owner", "repo", resp)

	reqBody, _ := json.Marshal(map[string]any{
		"query": "mutation MergePR($input: MergePullRequestInput!) { mergePullRequest(input: $input) { pullRequest { url } } }",
		"variables": map[string]any{
			"input": map[string]any{
				"pullRequestId": "PR_abc",
			},
		},
	})

	owner, repo, ok := c.Lookup(reqBody)
	if !ok {
		t.Fatal("expected cache hit for nested variable")
	}
	if owner != "owner" || repo != "repo" {
		t.Fatalf("expected owner/repo, got %s/%s", owner, repo)
	}
}

func TestLookupMiss(t *testing.T) {
	c := New(30 * time.Minute)
	defer c.Stop()

	reqBody, _ := json.Marshal(map[string]any{
		"variables": map[string]any{"id": "PR_notcached"},
	})
	_, _, ok := c.Lookup(reqBody)
	if ok {
		t.Fatal("expected cache miss")
	}
}

func TestLookupNoVariables(t *testing.T) {
	c := New(30 * time.Minute)
	defer c.Stop()

	reqBody, _ := json.Marshal(map[string]any{
		"query": "{ viewer { login } }",
	})
	_, _, ok := c.Lookup(reqBody)
	if ok {
		t.Fatal("expected no match without variables")
	}
}

func TestTTLExpiration(t *testing.T) {
	c := New(1 * time.Millisecond)
	defer c.Stop()

	resp, _ := json.Marshal(map[string]any{"data": map[string]any{"node": map[string]any{"id": "PR_expire"}}})
	c.Ingest("o", "r", resp)

	time.Sleep(5 * time.Millisecond)

	reqBody, _ := json.Marshal(map[string]any{"variables": map[string]any{"id": "PR_expire"}})
	_, _, ok := c.Lookup(reqBody)
	if ok {
		t.Fatal("expected expired entry to miss")
	}
}

func TestIngestInvalidJSON(t *testing.T) {
	c := New(30 * time.Minute)
	defer c.Stop()
	c.Ingest("o", "r", []byte("not json"))
}

func TestLookupInvalidJSON(t *testing.T) {
	c := New(30 * time.Minute)
	defer c.Stop()
	_, _, ok := c.Lookup([]byte("not json"))
	if ok {
		t.Fatal("expected false for invalid json")
	}
}

func TestLookupNonObjectJSON(t *testing.T) {
	c := New(30 * time.Minute)
	defer c.Stop()
	_, _, ok := c.Lookup([]byte(`"just a string"`))
	if ok {
		t.Fatal("expected false for non-object json")
	}
}
