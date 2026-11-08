package vulnsource

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestRPMVerCmpAgainstRealRPM compares compareRPM with rpm 4.16's own
// rpm.vercmp, which parses both sides as epoch:version-release, on generated
// pairs. Opt-in: NOX_RPM_ORACLE=<dir> with pairs.txt (a<TAB>b) and rpm.out,
// one result per line, produced by real rpm:
//
//	docker run --rm -v "$DIR":/w:ro almalinux:9 sh /w/rpm-vercmp-oracle.sh | grep -v '^$' > "$DIR/rpm.out"
//
// (scripts/rpm-vercmp-oracle.sh, copied into $DIR). On 2026-11-08, 3000
// pairs generated from version fragments (digits, leading zeros, letters,
// ~, ^, separators, hyphens) gave 0 disagreements with rpm 4.16.1.3.
func TestRPMVerCmpAgainstRealRPM(t *testing.T) {
	dir := os.Getenv("NOX_RPM_ORACLE")
	if dir == "" {
		t.Skip("set NOX_RPM_ORACLE to a directory holding pairs.txt and rpm.out")
	}
	pf, err := os.Open(dir + "/pairs.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pf.Close() }()
	of, err := os.Open(dir + "/rpm.out")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = of.Close() }()
	ps, os2 := bufio.NewScanner(pf), bufio.NewScanner(of)
	n, bad := 0, 0
	for ps.Scan() && os2.Scan() {
		a, b, _ := strings.Cut(ps.Text(), "\t")
		want, err := strconv.Atoi(strings.TrimSpace(os2.Text()))
		if err != nil {
			t.Fatalf("rpm.out line %d: %v", n+1, err)
		}
		n++
		got, ok := compareRPM(a, b)
		if !ok || sgn(got) != want {
			bad++
			if bad <= 20 {
				t.Errorf("compareRPM(%q, %q) = %d, %v; rpm says %d", a, b, got, ok, want)
			}
		}
	}
	t.Logf("%d pairs, %d disagreements", n, bad)
	if n == 0 {
		t.Fatal("no pairs compared")
	}
}
