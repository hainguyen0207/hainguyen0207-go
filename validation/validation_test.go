package validation

import (
	"reflect"
	"sort"
	"testing"
)

func TestReportEligibleOnlyPassed(t *testing.T) {
	cases := map[Verdict]bool{
		VerdictPassed:   true,
		VerdictPending:  false,
		VerdictRejected: false,
		VerdictEscalate: false,
	}
	for v, want := range cases {
		if got := v.ReportEligible(); got != want {
			t.Errorf("%s.ReportEligible() = %v; want %v", v, got, want)
		}
	}
}

func TestParseVerdictFailClosed(t *testing.T) {
	// Anything unrecognized must parse !ok and default to pending (never passed).
	for _, bad := range []string{"", "approved", "confirmed", "PASS", "true", "yes", "reproduced"} {
		v, ok := ParseVerdict(bad)
		if ok {
			t.Errorf("ParseVerdict(%q) ok=true; want false", bad)
		}
		if v != VerdictPending {
			t.Errorf("ParseVerdict(%q) = %q; want pending fallback", bad, v)
		}
		if v.ReportEligible() {
			t.Errorf("unrecognized verdict %q must not be report-eligible", bad)
		}
	}
	// Case/space tolerance for real verdicts.
	for in, want := range map[string]Verdict{
		"passed": VerdictPassed, "  Passed ": VerdictPassed, "ESCALATE": VerdictEscalate,
		"rejected": VerdictRejected, "pending": VerdictPending,
	} {
		v, ok := ParseVerdict(in)
		if !ok || v != want {
			t.Errorf("ParseVerdict(%q) = (%q,%v); want (%q,true)", in, v, ok, want)
		}
	}
}

func TestStatusAfter(t *testing.T) {
	tests := []struct {
		v      Verdict
		status string
		change bool
	}{
		{VerdictPassed, "confirmed", true},
		{VerdictRejected, "false_positive", true},
		{VerdictEscalate, "", false},
		{VerdictPending, "", false},
	}
	for _, tc := range tests {
		s, c := tc.v.StatusAfter()
		if s != tc.status || c != tc.change {
			t.Errorf("%s.StatusAfter() = (%q,%v); want (%q,%v)", tc.v, s, c, tc.status, tc.change)
		}
	}
}

func TestTerminal(t *testing.T) {
	for v, want := range map[Verdict]bool{
		VerdictPassed: true, VerdictRejected: true,
		VerdictEscalate: false, VerdictPending: false,
	} {
		if v.Terminal() != want {
			t.Errorf("%s.Terminal() = %v; want %v", v, v.Terminal(), want)
		}
	}
}

func TestGatePartitions(t *testing.T) {
	items := []Item{
		{1, VerdictPassed},
		{2, VerdictPending},
		{3, VerdictRejected},
		{4, VerdictEscalate},
		{5, VerdictPassed},
		{6, Verdict("garbage")}, // unrecognized → pending bucket
		{7, Verdict("")},        // empty → pending bucket
	}
	res := Gate(items)
	sort.Slice(res.Eligible, func(i, j int) bool { return res.Eligible[i] < res.Eligible[j] })
	if !reflect.DeepEqual(res.Eligible, []int64{1, 5}) {
		t.Fatalf("Eligible = %v; want [1 5]", res.Eligible)
	}
	pend := res.Withheld[VerdictPending]
	sort.Slice(pend, func(i, j int) bool { return pend[i] < pend[j] })
	if !reflect.DeepEqual(pend, []int64{2, 6, 7}) {
		t.Errorf("pending bucket = %v; want [2 6 7] (unrecognized verdicts fail closed to pending)", pend)
	}
	if !reflect.DeepEqual(res.Withheld[VerdictRejected], []int64{3}) {
		t.Errorf("rejected bucket = %v; want [3]", res.Withheld[VerdictRejected])
	}
	if !reflect.DeepEqual(res.Withheld[VerdictEscalate], []int64{4}) {
		t.Errorf("escalate bucket = %v; want [4]", res.Withheld[VerdictEscalate])
	}
}

func TestClassDefaultsToGadget(t *testing.T) {
	gadget := []string{"User enumeration", "Open Redirect", "account existence oracle", "Software version disclosure", "verbose error message"}
	for _, c := range gadget {
		if !ClassDefaultsToGadget(c) {
			t.Errorf("%q should default to gadget", c)
		}
	}
	notGadget := []string{"SQL Injection", "Reflected XSS", "IDOR", "SSRF", "Remote Code Execution", "Account takeover"}
	for _, c := range notGadget {
		if ClassDefaultsToGadget(c) {
			t.Errorf("%q must NOT default to gadget", c)
		}
	}
}

func TestPassRequiresClass(t *testing.T) {
	// A default-gadget class cannot pass unchained...
	if err := PassRequiresClass("Open Redirect", false); err == nil {
		t.Error("unchained open redirect must be blocked from passing")
	}
	// ...but passes when the validator asserts a demonstrated chain/exception.
	if err := PassRequiresClass("Open Redirect", true); err != nil {
		t.Errorf("chained open redirect should be allowed: %v", err)
	}
	// A real standalone class is unaffected by the chained flag.
	if err := PassRequiresClass("SQL Injection", false); err != nil {
		t.Errorf("sqli pass must not require chained: %v", err)
	}
}

func TestPassRequiresTierGate(t *testing.T) {
	ok := []struct {
		tier Tier
		sev  Severity
	}{
		{TierFinding, SevCritical},
		{TierFinding, SevHigh},
		{TierFinding, SevMedium},
		{TierFinding, SevLow},
	}
	for _, c := range ok {
		if err := PassRequires(c.tier, c.sev); err != nil {
			t.Errorf("PassRequires(%s,%s) = %v; want nil", c.tier, c.sev, err)
		}
	}
	bad := []struct {
		name string
		tier Tier
		sev  Severity
	}{
		{"gadget cannot pass", TierGadget, SevHigh},
		{"lead cannot pass", TierLead, SevHigh},
		{"note cannot pass", TierNote, SevHigh},
		{"finding but info-only", TierFinding, SevInfo},
		{"unknown tier", Tier("bug"), SevHigh},
		{"unknown severity", TierFinding, Severity("sev5")},
		{"empty tier", Tier(""), SevHigh},
	}
	for _, c := range bad {
		if err := PassRequires(c.tier, c.sev); err == nil {
			t.Errorf("%s: PassRequires(%q,%q) = nil; want error", c.name, c.tier, c.sev)
		}
	}
}

func TestParseTierAndSeverity(t *testing.T) {
	if _, ok := ParseTier("FINDING"); !ok {
		t.Error("ParseTier should be case-insensitive")
	}
	if _, ok := ParseTier("critical"); ok {
		t.Error("a severity is not a tier")
	}
	if s, ok := ParseSeverity("  High "); !ok || s != SevHigh {
		t.Errorf("ParseSeverity trim/case failed: %q %v", s, ok)
	}
	if SevInfo.Rewardable() {
		t.Error("info must not be rewardable")
	}
	if !TierFinding.ReportWorthy() || TierGadget.ReportWorthy() {
		t.Error("only finding tier is report-worthy")
	}
}

func TestEligibleFailClosedOnMissing(t *testing.T) {
	verdicts := map[int64]Verdict{10: VerdictPassed, 11: VerdictRejected}
	if !Eligible(verdicts, 10) {
		t.Error("id 10 (passed) must be eligible")
	}
	if Eligible(verdicts, 11) {
		t.Error("id 11 (rejected) must not be eligible")
	}
	// An id that was never validated is absent from the map → must fail closed.
	if Eligible(verdicts, 99) {
		t.Error("unvalidated id 99 must not be eligible (fail-closed)")
	}
	if Eligible(nil, 10) {
		t.Error("nil verdict map must deny everything")
	}
}
