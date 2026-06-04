package restfilter

import (
	"strings"
	"testing"
)

// Round-16 LOW: the count-oracle closure must cover enum bodies shaped {total_count, repositories[]}
// (and similar), not only the {total_count, items[]} search shape. Otherwise total_count still
// reveals how many denied repositories were dropped.
func TestCountOracleClosedForRepositoriesArray(t *testing.T) {
	body := []byte(`{"total_count":3,"repositories":[` +
		`{"full_name":"a/keep"},{"full_name":"b/drop"},{"full_name":"c/drop"}]}`)
	out := string(Filter("/installation/repositories", body, allowOnly("a/keep")))
	if strings.Contains(out, "b/drop") || strings.Contains(out, "c/drop") {
		t.Fatalf("denied repositories not dropped: %s", out)
	}
	if strings.Contains(out, `"total_count":3`) {
		t.Fatalf("count oracle not closed (total_count still 3): %s", out)
	}
	if !strings.Contains(out, `"total_count":1`) {
		t.Fatalf("total_count should drop by the 2 removed entries to 1: %s", out)
	}
	if !strings.Contains(out, `"incomplete_results":true`) {
		t.Fatalf("incomplete_results should be set: %s", out)
	}
}

// When nothing is dropped, the true total_count is preserved.
func TestCountOraclePreservedWhenNoRepositoriesDropped(t *testing.T) {
	body := []byte(`{"total_count":7,"repositories":[{"full_name":"a/keep"}]}`)
	out := string(Filter("/installation/repositories", body, allowOnly("a/keep")))
	if !strings.Contains(out, `"total_count":7`) {
		t.Fatalf("true count must be preserved when nothing dropped: %s", out)
	}
}
