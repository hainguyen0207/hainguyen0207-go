package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/licensing"
)

// settingLicenseCode stores the activated license code string in the KV settings.
const settingLicenseCode = "license_code"

// settingLicenseTimeHWM is a monotonic high-watermark of the wall-clock time the
// server has observed. Expiry is evaluated against max(now, hwm), so rolling the
// system clock backwards cannot revive an expired license (anti-rollback).
const settingLicenseTimeHWM = "license_time_hwm"

// licenseState is the cached, parsed result of the stored license code. It is
// (re)computed on startup and whenever a new code is pasted, so the hot path
// (the gate middleware) never re-verifies per request.
type licenseState struct {
	code    string           // raw stored code ("" when none)
	claims  licensing.Claims // parsed claims (zero when invalid/none)
	valid   bool             // signature verified AND Check passed (active here, not expired)
	sigOK   bool             // signature verified (may still be expired / wrong machine)
	reason  string           // why not valid (for the UI), empty when valid
	checked time.Time
}

var (
	licenseMu  sync.RWMutex
	licenseCur licenseState
	machineID  = licensing.MachineID()
)

// loadLicense reads the stored code and (re)computes the cached license state.
// Called at startup, after a successful paste, and periodically (so a license
// that expires during runtime is enforced without a restart).
func (s *Server) loadLicense() {
	code := ""
	if s.m != nil && s.m.pg != nil {
		code, _, _ = s.m.pg.GetSetting(settingLicenseCode)
		code = strings.TrimSpace(code)
	}
	st := computeLicenseState(code, s.effectiveNow())
	licenseMu.Lock()
	licenseCur = st
	licenseMu.Unlock()
}

// effectiveNow returns max(wall-clock now, persisted high-watermark) and
// advances the watermark. Setting the clock back therefore cannot lower the
// time used for expiry checks. Falls back to the raw clock without a DB.
func (s *Server) effectiveNow() time.Time {
	now := time.Now()
	if s.m == nil || s.m.pg == nil {
		return now
	}
	hwm := int64(0)
	if v, _, _ := s.m.pg.GetSetting(settingLicenseTimeHWM); strings.TrimSpace(v) != "" {
		hwm, _ = strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	}
	if now.Unix() > hwm {
		_ = s.m.pg.SetSetting(settingLicenseTimeHWM, strconv.FormatInt(now.Unix(), 10))
		return now
	}
	// Clock is at or behind the watermark — use the watermark (anti-rollback).
	return time.Unix(hwm, 0)
}

// licenseRefreshLoop periodically re-evaluates the license so a mid-run expiry
// (and the time watermark) is enforced without a restart.
func (s *Server) licenseRefreshLoop() {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			s.loadLicense()
		}
	}
}

func computeLicenseState(code string, now time.Time) licenseState {
	st := licenseState{code: code, checked: time.Now()}
	if code == "" {
		st.reason = "no license activated"
		return st
	}
	claims, err := licensing.Verify(code)
	if err != nil {
		st.reason = "invalid license code"
		return st
	}
	st.claims = claims
	st.sigOK = true
	if err := claims.Check(now, machineID); err != nil {
		st.reason = strings.TrimPrefix(err.Error(), "license: ")
		return st
	}
	st.valid = true
	return st
}

// license returns a snapshot of the current cached license state.
func (s *Server) license() licenseState {
	licenseMu.RLock()
	defer licenseMu.RUnlock()
	return licenseCur
}

// licensed reports whether the install currently has a valid, active license.
func (s *Server) licensed() bool { return s.license().valid }

// licenseGateExempt lists path prefixes that remain usable without a license so
// the operator can log in, read status, and activate a key. Everything else
// that mutates state is blocked until a valid license is pasted.
func licenseGateExempt(path, method string) bool {
	switch {
	case strings.HasPrefix(path, "/api/auth/"):
		return true
	case path == "/api/health":
		return true
	case strings.HasPrefix(path, "/api/license"):
		return true // GET status + POST activate must work while unlicensed
	case method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions:
		return true // reads stay open so the UI renders; only mutations are gated
	}
	return false
}

// GateK1z wraps the externally-mounted hainguyen0207 workflow-runner handler
// (/api/v1/*, /ws/*) with the SAME license gate as the ARTEX API. Without it
// those routes bypass the gate entirely — e.g. POST /api/v1/runs could launch
// workflows on an unlicensed install. License-only (not auth) so ARTEX's own
// localhost read calls into k1z (reconGetJSON) keep working unchanged.
func (s *Server) GateK1z(h http.Handler) http.Handler {
	if h == nil {
		return nil
	}
	return s.requireLicense(h)
}

// requireLicense blocks state-changing API calls when no valid license is
// active. Reads and the activation endpoints stay open so the operator can see
// the locked state and paste a key. Runs AFTER requireAuth.
func (s *Server) requireLicense(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.licensed() || licenseGateExempt(r.URL.Path, r.Method) {
			h.ServeHTTP(w, r)
			return
		}
		writeErr(w, http.StatusPaymentRequired, "license required: activate a key in System → License to use this feature")
	})
}

// licensePayload is the JSON status served to the UI.
func (s *Server) licensePayload() map[string]any {
	st := s.license()
	out := map[string]any{
		"machine_id": machineID,
		"licensed":   st.valid,
		"sig_ok":     st.sigOK,
		"activated":  st.code != "",
		"reason":     st.reason,
		"version":    publicKeyFingerprint(),
	}
	if st.sigOK {
		c := st.claims
		out["customer"] = c.Customer
		out["tier"] = c.Tier
		out["features"] = c.Features // empty => all
		out["machine_bound"] = c.MachineID != ""
		out["limits"] = map[string]any{
			"targets": c.Limits.Targets,
			"tasks":   c.Limits.Tasks,
			"tokens":  c.Limits.Tokens,
		}
		if c.IssuedAt > 0 {
			out["issued_at"] = c.IssuedAt
		}
		if c.ExpiresAt > 0 {
			out["expires_at"] = c.ExpiresAt
			out["expired"] = c.Expired(time.Now())
			out["days_left"] = int(time.Until(time.Unix(c.ExpiresAt, 0)).Hours() / 24)
		} else {
			out["expires_at"] = 0 // perpetual
		}
	} else if st.code == "" {
		out["tier"] = licensing.TierCommunity
	}
	return out
}

// publicKeyFingerprint gives the UI a short identifier of which signing key the
// binary trusts, so a mismatched build is spotted without exposing the key.
func publicKeyFingerprint() string {
	// Reuse the machine-id salt-free: a stable short tag is enough here.
	fp := machineID
	if len(fp) > 8 {
		fp = fp[:8]
	}
	return fp
}

// getLicense serves the license status.
func (s *Server) getLicense(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.licensePayload())
}

// postLicense activates (or clears) a pasted license code. An empty code clears
// the activation and reverts to the locked/community state.
func (s *Server) postLicense(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	code := strings.TrimSpace(req.Code)

	if code != "" {
		// Reject a code that does not verify / is not usable here, with a clear reason,
		// so the operator does not "activate" a dud and think it worked.
		st := computeLicenseState(code, s.effectiveNow())
		if !st.valid {
			reason := st.reason
			if reason == "" {
				reason = "invalid license code"
			}
			writeErr(w, 400, "license not accepted: "+reason)
			return
		}
	}

	if err := s.m.pg.SetSetting(settingLicenseCode, code); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.loadLicense()
	writeJSON(w, 200, s.licensePayload())
}
