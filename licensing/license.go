// Package licensing implements an offline, signed license-key scheme.
//
// The vendor holds an Ed25519 private key (never shipped) and issues a license
// "code" with the gen-license CLI. The product binary embeds only the matching
// public key (see pubkey.go) and verifies codes entirely offline — no network,
// no activation server — which suits air-gapped / authorized-engagement use.
//
// A code is  base64url(payloadJSON) + "." + base64url(signature) .
// The signature covers the raw payload JSON bytes.
package licensing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

// Tier names. Unlicensed installs run as TierCommunity (locked to read-only).
const (
	TierCommunity  = "community"
	TierPro        = "pro"
	TierEnterprise = "enterprise"
)

// Limits caps resource usage. Zero means unlimited for that dimension.
type Limits struct {
	Targets int   `json:"targets,omitempty"`
	Tasks   int   `json:"tasks,omitempty"`
	Tokens  int64 `json:"tokens,omitempty"`
}

// Claims is the signed license payload.
type Claims struct {
	Customer  string   `json:"customer"`             // who the license was issued to
	Tier      string   `json:"tier"`                 // community|pro|enterprise
	IssuedAt  int64    `json:"iat"`                  // unix seconds
	ExpiresAt int64    `json:"exp,omitempty"`        // unix seconds; 0 = perpetual
	Limits    Limits   `json:"limits,omitempty"`     // resource caps (0 = unlimited)
	Features  []string `json:"features,omitempty"`   // allowed feature keys; empty = ALL
	MachineID string   `json:"machine_id,omitempty"` // bind to one machine; empty = any machine
	Nonce     string   `json:"nonce,omitempty"`      // uniqueness, so two identical grants differ
}

var b64 = base64.RawURLEncoding

// Sign serializes the claims and signs them with the vendor private key,
// returning the license code string to hand to the customer.
func Sign(c Claims, priv ed25519.PrivateKey) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("license: invalid private key size")
	}
	if c.IssuedAt == 0 {
		c.IssuedAt = time.Now().Unix()
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, payload)
	return b64.EncodeToString(payload) + "." + b64.EncodeToString(sig), nil
}

// Verify checks a code's signature against the embedded public key and returns
// the claims. It does NOT check expiry or machine binding — use (Claims).Check
// for that, so callers can still display an expired license's details.
func Verify(code string) (Claims, error) {
	return VerifyWith(code, embeddedPublicKey())
}

// VerifyWith checks a code against a specific public key (used by tests / tools).
func VerifyWith(code string, pub ed25519.PublicKey) (Claims, error) {
	var c Claims
	code = strings.TrimSpace(code)
	if code == "" {
		return c, errors.New("license: empty code")
	}
	parts := strings.SplitN(code, ".", 2)
	if len(parts) != 2 {
		return c, errors.New("license: malformed code")
	}
	payload, err := b64.DecodeString(parts[0])
	if err != nil {
		return c, fmt.Errorf("license: bad payload encoding: %w", err)
	}
	sig, err := b64.DecodeString(parts[1])
	if err != nil {
		return c, fmt.Errorf("license: bad signature encoding: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return c, errors.New("license: no/invalid embedded public key")
	}
	if !ed25519.Verify(pub, payload, sig) {
		return c, errors.New("license: signature verification failed")
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, fmt.Errorf("license: bad payload: %w", err)
	}
	return c, nil
}

// Check validates a verified claim against the current time and this machine.
// Returns nil when the license is active and usable here.
func (c Claims) Check(now time.Time, machineID string) error {
	if c.Expired(now) {
		return fmt.Errorf("license: expired on %s", time.Unix(c.ExpiresAt, 0).UTC().Format("2006-01-02"))
	}
	if c.MachineID != "" && !strings.EqualFold(c.MachineID, machineID) {
		return errors.New("license: bound to a different machine")
	}
	return nil
}

// Expired reports whether the license has passed its expiry (0 = perpetual).
func (c Claims) Expired(now time.Time) bool {
	return c.ExpiresAt != 0 && now.Unix() >= c.ExpiresAt
}

// Allows reports whether a feature key is permitted. An empty Features list
// means every feature is allowed (full license).
func (c Claims) Allows(feature string) bool {
	if len(c.Features) == 0 {
		return true
	}
	for _, f := range c.Features {
		if strings.EqualFold(strings.TrimSpace(f), feature) {
			return true
		}
	}
	return false
}

// MachineID returns a stable, non-reversible identifier for this host. The
// vendor embeds it in a machine-bound code so the code only activates here.
func MachineID() string {
	var seed string
	// Prefer the OS machine-id (stable across reboots, not tied to NICs).
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				seed = s
				break
			}
		}
	}
	if seed == "" {
		// Fallback: hostname + first non-loopback hardware MAC.
		host, _ := os.Hostname()
		seed = host
		if ifaces, err := net.Interfaces(); err == nil {
			macs := make([]string, 0, len(ifaces))
			for _, ifc := range ifaces {
				if ifc.Flags&net.FlagLoopback != 0 || len(ifc.HardwareAddr) == 0 {
					continue
				}
				macs = append(macs, ifc.HardwareAddr.String())
			}
			sort.Strings(macs)
			seed += "|" + strings.Join(macs, ",")
		}
	}
	sum := sha256.Sum256([]byte("artex-machine-id/v1|" + seed))
	return hex.EncodeToString(sum[:])[:32]
}
