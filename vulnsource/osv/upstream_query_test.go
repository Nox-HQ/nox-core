package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nox-hq/nox-core/vulnsource"
)

// A bundled OpenSSL 3.5.9 is asked about as OSV knows it: the repository as
// the package, in the GIT ecosystem, at the release tag.
func TestLookupAsksForOpenSSLByRepositoryAndTag(t *testing.T) {
	var got BatchRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			_ = json.NewDecoder(r.Body).Decode(&got)
		}
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]}]}`))
	}))
	defer srv.Close()
	src := New(srv.URL, srv.Client(), nil)
	if _, err := src.Lookup(context.Background(), []vulnsource.Query{{Name: "openssl", Ecosystem: "openssl", Version: "3.5.9"}}); err != nil {
		t.Fatal(err)
	}
	if len(got.Queries) != 1 {
		t.Fatalf("sent %d queries", len(got.Queries))
	}
	q := got.Queries[0]
	if q.Package.Name != "https://github.com/openssl/openssl" || q.Package.Ecosystem != "GIT" || q.Version != "openssl-3.5.9" {
		t.Errorf("sent %+v", q)
	}
}
