package openwrt

import (
	"os"
	"regexp"
	"testing"
)

// The agent's failure codes are written down in four places: the Go constants
// that produce them, the LuCI label map that translates them, the Chinese
// catalog that localises those labels, and the documentation table that tells
// an operator what to do about each one. Only the first is authoritative; the
// other three are copies, kept by hand, in three different languages.
//
// A missing entry is invisible in every direction. The status page falls back to
// printing the bare code, which reads as a glitch rather than as a reason, and
// the docs table quietly stops being the complete list it claims to be. That is
// not hypothetical: `stopped` was produced by the agent, translated in the LuCI
// catalog, and absent from both documentation tables, and nothing said so.

const (
	reasonGoPath     = "../internal/conn/reason.go"
	statusGoPath     = "../agentrt/status.go"
	statusViewPath   = "luci-app-nettact/files/www/luci-static/resources/view/nettact/status.js"
	docsEnPath       = "../../docs/en/agent-config.md"
	docsZhPath       = "../../docs/zh/agent-config.md"
	reasonLabelsName = "REASON_LABELS"
)

var (
	// Reason constants: `ReasonDNS Reason = "dns"`.
	goReasonRe = regexp.MustCompile(`Reason\w+\s+Reason\s*=\s*"([a-z_]+)"`)
	// agentrt's own codes: `statusCodeNoToken = "no_token"`.
	goStatusCodeRe = regexp.MustCompile(`statusCode\w+\s*=\s*"([a-z_]+)"`)
	// A key of the JS label map: `tls_cert_expired: _('…')`.
	jsLabelRe = regexp.MustCompile(`(?m)^\s*([a-z_]+):\s*_\(`)
	// The label map itself. Its own object literal, not the array form
	// blockRe matches.
	jsLabelBlockRe = regexp.MustCompile(`(?s)var\s+` + reasonLabelsName + `\s*=\s*\{(.*?)\n\};`)
	// A leading code cell in a Markdown table row: "| `dns` | … |".
	docRowRe = regexp.MustCompile("(?m)^\\|\\s*`([a-z_]+)`\\s*\\|")
)

// agentReasonCodes is the authoritative vocabulary: everything Classify can
// return, plus the terminal/enrollment codes agentrt adds.
func agentReasonCodes(t *testing.T) map[string]bool {
	t.Helper()
	codes := map[string]bool{}
	for path, re := range map[string]*regexp.Regexp{
		reasonGoPath: goReasonRe,
		statusGoPath: goStatusCodeRe,
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
			codes[m[1]] = true
		}
	}
	if len(codes) == 0 {
		t.Fatalf("no reason codes found in %s / %s — did the declarations change shape?",
			reasonGoPath, statusGoPath)
	}
	return codes
}

// TestReasonLabelsCoverEveryCode holds the LuCI label map to the Go vocabulary.
// A code with no entry renders on the router as its bare identifier.
func TestReasonLabelsCoverEveryCode(t *testing.T) {
	want := agentReasonCodes(t)

	raw, err := os.ReadFile(statusViewPath)
	if err != nil {
		t.Fatalf("reading %s: %v", statusViewPath, err)
	}
	block := jsLabelBlockRe.FindStringSubmatch(string(raw))
	if block == nil {
		t.Fatalf("%s: no `var %s = {...}` found", statusViewPath, reasonLabelsName)
	}
	got := map[string]bool{}
	for _, m := range jsLabelRe.FindAllStringSubmatch(block[1], -1) {
		got[m[1]] = true
	}

	for code := range want {
		if !got[code] {
			t.Errorf("%s: %s has no entry for %q", statusViewPath, reasonLabelsName, code)
		}
	}
	for code := range got {
		if !want[code] {
			t.Errorf("%s: %s translates %q, which the agent never emits", statusViewPath, reasonLabelsName, code)
		}
	}
}

// TestDocsReasonTableCoversEveryCode does the same for the bilingual reason
// tables, which present themselves as the complete list of what an operator can
// see and what to do about it.
func TestDocsReasonTableCoversEveryCode(t *testing.T) {
	want := agentReasonCodes(t)

	for _, path := range []string{docsEnPath, docsZhPath} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		got := map[string]bool{}
		for _, m := range docRowRe.FindAllStringSubmatch(string(raw), -1) {
			got[m[1]] = true
		}
		for code := range want {
			if !got[code] {
				t.Errorf("%s: the reason table has no row for %q", path, code)
			}
		}
	}
}
