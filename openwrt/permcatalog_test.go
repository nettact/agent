package openwrt

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/nettact/protocol/permission"
)

// The LuCI settings page carries its own copy of the permission catalog: it runs
// against the router, which has no NetTact server to ask, and the server it
// reports to may not be reachable — or even enrolled — while someone is filling
// the form in. That copy is the only place in the tree where the permission
// model is written down twice, so these tests hold it to protocol/permission.
//
// A drift here is not cosmetic. A missing id silently disappears from the
// chooser; a wrong `requires` edge lets the page save a policy the agent refuses
// at startup, leaving the router respawning every ten seconds with the reason
// only in syslog.

const (
	catalogPath   = "luci-app-nettact/files/www/luci-static/resources/nettact/permcatalog.js"
	poPath        = "luci-app-nettact/po/zh_Hans/nettact.po"
	genconfigPath = "nettact-agent/files/usr/lib/nettact/genconfig.sh"
)

type jsEntry struct {
	id       string
	def      bool
	label    string
	requires string
}

var (
	entryRe = regexp.MustCompile(`\{\s*id:\s*'([^']+)',\s*def:\s*(true|false),\s*label:\s*'([^']*)'(?:,\s*requires:\s*'([^']+)')?\s*\}`)
	blockRe = func(name string) *regexp.Regexp {
		return regexp.MustCompile(`(?s)var\s+` + name + `\s*=\s*\[(.*?)\]`)
	}
	quotedRe = regexp.MustCompile(`'([^']+)'`)
)

func loadCatalog(t *testing.T) ([]jsEntry, string) {
	t.Helper()
	raw, err := os.ReadFile(catalogPath)
	if err != nil {
		t.Fatalf("reading %s: %v", catalogPath, err)
	}
	src := string(raw)
	matches := entryRe.FindAllStringSubmatch(src, -1)
	if len(matches) == 0 {
		t.Fatalf("%s: no permission entries matched; did the table's shape change?", catalogPath)
	}
	// An entry the regex cannot read is DROPPED, not reported, which would make
	// every check below quietly pass over it. Counting the `id:` keys catches
	// that here — in whichever test ran first — instead of leaving it to show up
	// as a puzzling off-by-one somewhere else.
	if n := strings.Count(src, "{ id: '"); n != len(matches) {
		t.Fatalf("%s: %d entries look like `{ id: '...'` but only %d parse; check the shape of the odd one out",
			catalogPath, n, len(matches))
	}
	out := make([]jsEntry, 0, len(matches))
	for _, m := range matches {
		out = append(out, jsEntry{id: m[1], def: m[2] == "true", label: m[3], requires: m[4]})
	}
	return out, src
}

// stringList pulls the ids out of a top-level `var NAME = [ 'a', 'b' ]` array.
func stringList(t *testing.T, src, name string) []string {
	t.Helper()
	block := blockRe(name).FindStringSubmatch(src)
	if block == nil {
		t.Fatalf("%s: no `var %s = [...]` found", catalogPath, name)
	}
	var out []string
	for _, m := range quotedRe.FindAllStringSubmatch(block[1], -1) {
		out = append(out, m[1])
	}
	return out
}

// TestCatalogIDsMatchProtocol checks the ids AND their order. Order is not
// cosmetic: a rendered permission list has to be canonical so the same choice
// always produces the same UCI value and the same generated YAML.
func TestCatalogIDsMatchProtocol(t *testing.T) {
	entries, _ := loadCatalog(t)

	got := make([]string, len(entries))
	for i, e := range entries {
		got[i] = e.id
	}
	want := permission.All().Strings()

	if len(got) != len(want) {
		t.Errorf("catalog has %d permissions, protocol has %d", len(got), len(want))
	}
	for i := 0; i < len(got) && i < len(want); i++ {
		if got[i] != want[i] {
			t.Errorf("position %d: catalog has %q, protocol has %q", i, got[i], want[i])
		}
	}
}

// TestCatalogDefaultsMatchProtocol checks the `def` flags, which are what the
// chooser's "Recommended" preset is derived from.
func TestCatalogDefaultsMatchProtocol(t *testing.T) {
	entries, _ := loadCatalog(t)

	std := permission.DefaultStandalone()
	for _, e := range entries {
		if got, want := e.def, std.Has(permission.ID(e.id)); got != want {
			t.Errorf("%s: catalog def=%v, protocol default grant=%v", e.id, got, want)
		}
	}
}

// TestCatalogDependenciesMatchProtocol walks each entry's `requires` chain and
// compares the set it produces with the protocol's own transitive closure.
//
// Comparing closures rather than single edges is deliberate: the JS chooser
// follows the chain to add parents, so what has to be right is the set it
// arrives at. It also catches a permission that gains a SECOND parent in Go —
// the chain would then reach fewer ids than the closure and fail here, instead
// of silently dropping a dependency in the UI.
func TestCatalogDependenciesMatchProtocol(t *testing.T) {
	entries, _ := loadCatalog(t)

	byID := make(map[string]jsEntry, len(entries))
	for _, e := range entries {
		byID[e.id] = e
	}

	for _, e := range entries {
		chain := map[string]bool{e.id: true}
		for cur := e.requires; cur != ""; cur = byID[cur].requires {
			if chain[cur] {
				t.Fatalf("%s: `requires` chain loops through %s", e.id, cur)
			}
			if _, ok := byID[cur]; !ok {
				t.Fatalf("%s: requires %q, which is not in the catalog", e.id, cur)
			}
			chain[cur] = true
		}

		want := permission.Closure(permission.NewSet(permission.ID(e.id)))
		if len(chain) != len(want) {
			t.Errorf("%s: catalog closure %v, protocol closure %v", e.id, keys(chain), want.Strings())
			continue
		}
		for id := range want {
			if !chain[string(id)] {
				t.Errorf("%s: protocol requires %q, catalog chain does not reach it", e.id, id)
			}
		}
	}
}

// TestCatalogBundlesMatchProtocol checks the three presets the chooser offers.
// They are derived in JS (recommended = the default-flagged entries, full =
// everything, host_metrics = recommended plus a listed delta), so this is what
// keeps the derivation honest rather than the lists themselves.
func TestCatalogBundlesMatchProtocol(t *testing.T) {
	entries, src := loadCatalog(t)
	extra := stringList(t, src, "HOST_METRICS_EXTRA")

	var all, recommended []string
	inExtra := make(map[string]bool, len(extra))
	for _, id := range extra {
		inExtra[id] = true
	}
	var hostMetrics []string
	for _, e := range entries {
		all = append(all, e.id)
		if e.def {
			recommended = append(recommended, e.id)
		}
		if e.def || inExtra[e.id] {
			hostMetrics = append(hostMetrics, e.id)
		}
	}

	got := map[string][]string{
		"recommended":  recommended,
		"host_metrics": hostMetrics,
		"full":         all,
	}

	bundles := permission.Bundles()
	if len(bundles) != len(got) {
		t.Errorf("protocol offers %d bundles, the catalog derives %d", len(bundles), len(got))
	}
	for _, b := range bundles {
		have, ok := got[b.ID]
		if !ok {
			t.Errorf("bundle %q has no equivalent in the catalog", b.ID)
			continue
		}
		want := b.Set.Strings()
		if strings.Join(have, ",") != strings.Join(want, ",") {
			t.Errorf("bundle %q:\n catalog:  %v\n protocol: %v", b.ID, have, want)
		}
	}

	// Every id in the delta must exist, and none of them may already be in the
	// default grant — otherwise the "adds these" wording in the UI is a lie.
	std := permission.DefaultStandalone()
	for _, id := range extra {
		if std.Has(permission.ID(id)) {
			t.Errorf("HOST_METRICS_EXTRA lists %q, which is already in the default grant", id)
		}
	}
}

// TestCatalogUnsupportedIDsExist keeps the "not available on a router" marking
// from outliving a renamed permission, where it would silently stop warning.
func TestCatalogUnsupportedIDsExist(t *testing.T) {
	entries, src := loadCatalog(t)
	known := make(map[string]bool, len(entries))
	for _, e := range entries {
		known[e.id] = true
	}
	for _, id := range stringList(t, src, "UNSUPPORTED_ON_ROUTER") {
		if !known[id] {
			t.Errorf("UNSUPPORTED_ON_ROUTER lists %q, which is not in the catalog", id)
		}
	}
}

// TestGenconfigPresetsMatchProtocol checks the preset lists genconfig.sh expands
// `permission_mode` into.
//
// This is the second copy of the bundle data — the shell needs it because UCI,
// not the settings page, is the source of truth: `permission_mode=host_metrics`
// has to mean the same thing whether LuCI wrote it or someone hand-edited
// /etc/config/nettact. The failure mode when it drifts is the worst kind: the
// router renders a config with no `permissions:` key at all, the agent falls
// back to its built-in grant, and nothing anywhere reports that the choice was
// ignored. That is exactly what shipped before this test existed.
func TestGenconfigPresetsMatchProtocol(t *testing.T) {
	raw, err := os.ReadFile(genconfigPath)
	if err != nil {
		t.Fatalf("reading %s: %v", genconfigPath, err)
	}
	src := string(raw)

	bundles := make(map[string]permission.Set, 3)
	for _, b := range permission.Bundles() {
		bundles[b.ID] = b.Set
	}

	for _, tc := range []struct{ variable, bundle string }{
		{"PERM_HOST_METRICS", "host_metrics"},
		{"PERM_FULL", "full"},
	} {
		got := shellList(t, src, tc.variable)
		want, ok := bundles[tc.bundle]
		if !ok {
			t.Fatalf("protocol has no %q bundle for %s", tc.bundle, tc.variable)
		}
		// Compare as sets: the shell list is wrapped for readability, so only
		// its membership is meaningful.
		if len(got) != len(want) {
			t.Errorf("%s has %d ids, bundle %q has %d", tc.variable, len(got), tc.bundle, len(want))
		}
		have := make(map[string]bool, len(got))
		for _, id := range got {
			have[id] = true
			if !want.Has(permission.ID(id)) {
				t.Errorf("%s lists %q, which bundle %q does not grant", tc.variable, id, tc.bundle)
			}
		}
		for id := range want {
			if !have[string(id)] {
				t.Errorf("bundle %q grants %q, which %s omits", tc.bundle, id, tc.variable)
			}
		}
	}

	// Every value the settings page can store must have a branch in the shell.
	// A missing one falls through to "emit nothing", which reads as the agent's
	// default rather than as an error.
	for _, mode := range []string{"default", "recommended", "none", "host_metrics", "full", "custom"} {
		if !strings.Contains(src, mode+")") && !strings.Contains(src, mode+"|") {
			t.Errorf("genconfig.sh has no case for permission_mode %q", mode)
		}
	}
}

// shellList reads a `NAME="a b\nc"` assignment out of a shell script and returns
// its whitespace-separated items.
func shellList(t *testing.T, src, name string) []string {
	t.Helper()
	re := regexp.MustCompile(`(?s)` + name + `="([^"]*)"`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("%s: no `%s=\"...\"` assignment found", genconfigPath, name)
	}
	return strings.Fields(m[1])
}

// TestCatalogLabelsAreTranslated checks that every label the chooser renders has
// a Chinese msgid. The LuCI page passes labels through _(), so a missing entry
// is not an error anywhere — the string simply shows up in English inside an
// otherwise Chinese form.
func TestCatalogLabelsAreTranslated(t *testing.T) {
	entries, _ := loadCatalog(t)
	translated := poMsgids(t)

	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e.label == "" {
			t.Errorf("%s: empty label", e.id)
			continue
		}
		if seen[e.label] {
			t.Errorf("%s: label %q is used by more than one permission", e.id, e.label)
		}
		seen[e.label] = true
		if !translated[e.label] {
			t.Errorf("%s: no `msgid %q` in %s", e.id, e.label, poPath)
		}
	}
}

// TestViewStringsAreTranslated does the same for every literal the LuCI views
// wrap in _(). Nothing fails when one is missing, which is exactly the problem:
// the page renders with a stray English sentence in the middle of a Chinese
// form and no build, test or log says why.
func TestViewStringsAreTranslated(t *testing.T) {
	translated := poMsgids(t)

	for _, path := range []string{
		"luci-app-nettact/files/www/luci-static/resources/view/nettact/settings.js",
		"luci-app-nettact/files/www/luci-static/resources/view/nettact/status.js",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		for _, m := range jsLiteralRe.FindAllStringSubmatch(string(raw), -1) {
			lit := strings.NewReplacer(`\'`, `'`, `\\`, `\`).Replace(m[1])
			if !translated[lit] {
				t.Errorf("%s: no `msgid %q` in %s", path, lit, poPath)
			}
		}
	}
}

// jsLiteralRe matches a single-quoted string passed straight to _(). Calls with
// a variable — _(e.label), _(GROUP_LABELS[g.group]) — are covered by the catalog
// test above and by the group labels being literals elsewhere.
var jsLiteralRe = regexp.MustCompile(`_\('((?:[^'\\]|\\.)*)'\)`)

// poMsgids parses the catalog into the set of translated source strings. A real
// parse rather than a substring search: gettext wraps long entries across
// several quoted lines, and every long sentence on the settings page is one.
func poMsgids(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(poPath)
	if err != nil {
		t.Fatalf("reading %s: %v", poPath, err)
	}
	unescape := strings.NewReplacer(`\"`, `"`, `\n`, "\n", `\t`, "\t", `\\`, `\`)
	quoted := regexp.MustCompile(`"(.*)"`)

	out := make(map[string]bool)
	var cur string
	inID := false
	flush := func() {
		if inID && cur != "" {
			out[unescape.Replace(cur)] = true
		}
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(s, "msgid"):
			flush()
			inID, cur = true, firstQuoted(quoted, s)
		case strings.HasPrefix(s, "msgstr"):
			flush()
			inID, cur = false, ""
		case strings.HasPrefix(s, `"`) && inID:
			cur += firstQuoted(quoted, s)
		}
	}
	flush()
	return out
}

func firstQuoted(re *regexp.Regexp, line string) string {
	m := re.FindStringSubmatch(line)
	if m == nil {
		return ""
	}
	return m[1]
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
