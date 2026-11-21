// Ported from ScopeWeaver/bcpen (AGPL-3.0, an ARTEX derivative): the pre-report finding gate.
//
// Package validation is the finding-gate primitive: the deterministic rule that
// decides whether a candidate finding is allowed into a deliverable report.
//
// It encodes one invariant, fail-closed: a finding is report-ready only after an
// independent validation has reproduced it and confirmed its impact — a "passed"
// verdict. Everything else (never validated, rejected as a false positive, or
// escalated for more work) is withheld. Nothing here depends on the DB or the
// LLM: the gate is pure so it is total and testable, and so the same rule is
// shared by the report builder and any UI that shows what the gate held back.
//
// Two stances run against a finding (hackbot-style), and they are opposites on
// purpose:
//   - StanceValidator defaults to DISBELIEF. A finding is a claim, not a fact,
//     until reproduced cold from its written PoC alone. It is the false-positive
//     firewall.
//   - StanceEscalator defaults to BELIEF-AND-AMBITION. It takes a reproduced-but-
//     under-demonstrated primitive and tries to reach the true, higher impact.
//
// The validator emits one of three verdicts; the escalator only ever runs on a
// finding the validator marked Escalate.
package validation

import (
	"fmt"
	"strings"
)

// Verdict is the outcome of validating one candidate finding.
type Verdict string

const (
	// VerdictPending: no validation has concluded yet. The default, and NOT
	// report-ready — absence of a verdict is never a pass.
	VerdictPending Verdict = "pending"
	// VerdictPassed: independently reproduced AND impact confirmed within scope.
	// The only verdict that admits a finding to the report.
	VerdictPassed Verdict = "passed"
	// VerdictRejected: false positive, unreplayable PoC, no real impact,
	// out-of-scope, or public-by-design. Never enters the report.
	VerdictRejected Verdict = "rejected"
	// VerdictEscalate: reproduces and is non-trivial, but as written demonstrates
	// only an oracle/primitive, with a concrete, credible, unexercised path to
	// materially higher impact — blocked here by the destructive line or by
	// running out of session. Handed to the escalator; not yet report-ready.
	VerdictEscalate Verdict = "escalate"
)

// ParseVerdict normalizes a stored/tool-supplied string. ok is false for any
// value that is not one of the four verdicts — callers must treat !ok as
// "no valid verdict", which is fail-closed (not report-ready).
func ParseVerdict(s string) (Verdict, bool) {
	switch Verdict(strings.ToLower(strings.TrimSpace(s))) {
	case VerdictPending:
		return VerdictPending, true
	case VerdictPassed:
		return VerdictPassed, true
	case VerdictRejected:
		return VerdictRejected, true
	case VerdictEscalate:
		return VerdictEscalate, true
	default:
		return VerdictPending, false
	}
}

// ReportEligible reports whether a finding with this verdict may appear in a
// deliverable report. Only a passed validation qualifies.
func (v Verdict) ReportEligible() bool { return v == VerdictPassed }

// Terminal reports whether the verdict concludes the validation lifecycle.
// Escalate is non-terminal: it hands off to the escalator, which can still turn
// it into a pass or a reject. Pending is non-terminal by definition.
func (v Verdict) Terminal() bool { return v == VerdictPassed || v == VerdictRejected }

// StatusAfter maps a verdict to the finding handling status it implies, and
// whether the status should change. Values mirror ARTEX's FindingStatus strings
// (kept as literals so this package does not import db and create a cycle).
// A passed validation is the authority that marks a finding "confirmed"; a
// rejection marks it "false_positive". Pending and escalate leave the status
// untouched — escalate is still live work, not a conclusion.
func (v Verdict) StatusAfter() (status string, change bool) {
	switch v {
	case VerdictPassed:
		return "confirmed", true
	case VerdictRejected:
		return "false_positive", true
	default:
		return "", false
	}
}

// Tier classifies a candidate by whether it is independently report-worthy. Most
// misclassification is here, not in severity: a reproduced primitive with no
// standalone, demonstrable, independently-rewardable impact is a gadget, not a
// finding. The tier gate stops a gadget/lead/note from being laundered into the
// report as a passed finding.
type Tier string

const (
	TierNote    Tier = "note"    // an observation; context only
	TierLead    Tier = "lead"    // a direction worth chasing; not yet proven
	TierGadget  Tier = "gadget"  // a real, reproduced primitive with no standalone rewardable impact
	TierFinding Tier = "finding" // a confirmed vuln with standalone, demonstrable, rewardable impact
)

// ParseTier normalizes a tier string. ok is false for anything unrecognized.
func ParseTier(s string) (Tier, bool) {
	switch Tier(strings.ToLower(strings.TrimSpace(s))) {
	case TierNote:
		return TierNote, true
	case TierLead:
		return TierLead, true
	case TierGadget:
		return TierGadget, true
	case TierFinding:
		return TierFinding, true
	default:
		return "", false
	}
}

// ReportWorthy reports whether a tier can carry an independently rewardable
// finding. Only finding-tier qualifies.
func (t Tier) ReportWorthy() bool { return t == TierFinding }

// Severity is the demonstrated impact level. info is valid but not rewardable —
// a reproduced behavior with only info impact is not a passing finding.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// ParseSeverity normalizes a severity string. ok is false for anything else.
func ParseSeverity(s string) (Severity, bool) {
	switch Severity(strings.ToLower(strings.TrimSpace(s))) {
	case SevCritical, SevHigh, SevMedium, SevLow, SevInfo:
		return Severity(strings.ToLower(strings.TrimSpace(s))), true
	default:
		return "", false
	}
}

// Rewardable reports whether a severity represents demonstrated, rewardable
// impact (anything above info).
func (s Severity) Rewardable() bool {
	return s == SevCritical || s == SevHigh || s == SevMedium || s == SevLow
}

// PassRequires is the tier gate applied when a validator tries to pass a finding.
// A pass means demonstrated, rewardable impact, so it requires BOTH a finding-tier
// classification AND a rewardable (non-info) severity. A gadget/lead/note, or an
// info-only severity, must be rejected or escalated — never passed. Returns a
// descriptive error when the pass is not allowed, nil when it is.
func PassRequires(tier Tier, sev Severity) error {
	t, ok := ParseTier(string(tier))
	if !ok {
		return fmt.Errorf("tier must be one of note/lead/gadget/finding, got %q", tier)
	}
	s, ok := ParseSeverity(string(sev))
	if !ok {
		return fmt.Errorf("severity must be one of critical/high/medium/low/info, got %q", sev)
	}
	if !t.ReportWorthy() {
		return fmt.Errorf("a %q is not a finding: it has no standalone rewardable impact — reject it (salvage as a lead/gadget) or escalate; do not pass", t)
	}
	if !s.Rewardable() {
		return fmt.Errorf("severity %q is not rewardable impact: a reproduced behavior with only info impact is not a passing finding — reject or escalate", s)
	}
	return nil
}

// defaultGadgetKeywords mark a vulnclass that has NO standalone rewardable impact
// (CAL-001/002): existence/differential oracles, open redirect, and version/stack
// disclosure. These pass only as a demonstrated chain or a cited exception.
var defaultGadgetKeywords = []string{
	"enumeration", "enumerate", "existence oracle", "user existence", "username exist",
	"account exist", "email exist", "account oracle", "login oracle", "subscriber existence",
	"open redirect", "open-redirect",
	"version disclosure", "tech disclosure", "stack disclosure", "software version",
	"verbose error", "banner grab", "banner disclosure",
	"differential oracle", "timing oracle",
}

// ClassDefaultsToGadget reports whether a finding's vulnclass is a class that has
// no standalone rewardable impact and therefore defaults to a gadget — rewardable
// only when chained into demonstrated impact, or a cited CAL exception.
func ClassDefaultsToGadget(vulnclass string) bool {
	v := strings.ToLower(vulnclass)
	for _, kw := range defaultGadgetKeywords {
		if strings.Contains(v, kw) {
			return true
		}
	}
	return false
}

// PassRequiresClass is the class-aware half of the pass gate (CAL-001/002), the
// mechanical teeth behind the rubric: a default-gadget vulnclass may pass as a
// finding ONLY when chained is true — the validator has asserted a demonstrated
// chain to real impact, or a cited exception (returns sensitive PII / program
// policy rewards it / mass-bulk exposure). Without that assertion, such a class
// cannot be laundered into the report as a standalone finding, even if the agent
// mislabels its tier.
func PassRequiresClass(vulnclass string, chained bool) error {
	if ClassDefaultsToGadget(vulnclass) && !chained {
		return fmt.Errorf("vulnclass %q has no standalone rewardable impact (existence/differential oracle, open redirect, or version/stack disclosure): it passes ONLY as a demonstrated chain to real impact, or a cited exception (sensitive PII returned / program policy rewards it / mass-bulk exposure). If you demonstrated that, set chained=true with the chain evidence; otherwise reject it (keep the primitive as a gadget/lead) or escalate", vulnclass)
	}
	return nil
}

// Stance is which of the two opposing validation roles is running.
type Stance string

const (
	StanceValidator Stance = "validator" // default disbelief; the false-positive firewall
	StanceEscalator Stance = "escalator" // default belief; pushes a primitive to real impact
)

// Item is one finding's identity plus its current verdict, as seen by the gate.
type Item struct {
	ID      int64
	Verdict Verdict
}

// GateResult partitions findings by report-readiness. Eligible holds the ids the
// report may include (passed); Withheld buckets the rest by verdict so the
// report and the UI can show exactly what was held back and why — the gate is
// transparent, never a silent drop.
type GateResult struct {
	Eligible []int64
	Withheld map[Verdict][]int64
}

// Gate applies the report-eligibility rule to a set of findings. Fail-closed:
// an unrecognized or empty verdict counts as pending (withheld), never passed.
func Gate(items []Item) GateResult {
	res := GateResult{Withheld: map[Verdict][]int64{}}
	for _, it := range items {
		v := it.Verdict
		if _, ok := ParseVerdict(string(v)); !ok {
			v = VerdictPending
		}
		if v.ReportEligible() {
			res.Eligible = append(res.Eligible, it.ID)
		} else {
			res.Withheld[v] = append(res.Withheld[v], it.ID)
		}
	}
	return res
}

// Eligible answers the report builder's per-finding question, fail-closed: a
// finding node id absent from the verdict map (never validated) is NOT eligible.
func Eligible(verdicts map[int64]Verdict, id int64) bool {
	v, ok := verdicts[id]
	return ok && v.ReportEligible()
}
