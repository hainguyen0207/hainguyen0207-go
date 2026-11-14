// Command gen-license is the VENDOR-SIDE tool for issuing offline license codes.
//
// It is never shipped to customers — it needs the private signing key, whose
// public half is embedded in the product binary (licensing/pubkey.go).
//
// Usage:
//
//	# one-time: create a new signing keypair
//	gen-license keygen
//	    -> prints PUBLIC (paste into licensing/pubkey.go) and PRIVATE (keep offline)
//
//	# issue a code (reads the private key from -key file or LICENSE_PRIVATE_KEY env)
//	gen-license -key scripts/license-private-key.b64 \
//	    -customer "ACME Corp" -tier pro -expires 2026-12-31 \
//	    -targets 10 -tasks 5 -machine <customer-machine-id>
//
// Omit -machine for a code that runs on any machine; omit -expires for a
// perpetual license; omit -targets/-tasks for unlimited.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Autumn-27/artex/licensing"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		keygen()
		return
	}

	var (
		keyFile  = flag.String("key", "", "path to base64 Ed25519 private key file (or set LICENSE_PRIVATE_KEY)")
		customer = flag.String("customer", "", "customer name (required)")
		tier     = flag.String("tier", licensing.TierPro, "tier: community|pro|enterprise")
		expires  = flag.String("expires", "", "expiry date YYYY-MM-DD (empty = perpetual)")
		targets  = flag.Int("targets", 0, "max targets (0 = unlimited)")
		tasks    = flag.Int("tasks", 0, "max concurrent tasks (0 = unlimited)")
		tokens   = flag.Int64("tokens", 0, "max LLM tokens (0 = unlimited)")
		features = flag.String("features", "", "comma-separated allowed feature keys (empty = ALL)")
		machine  = flag.String("machine", "", "bind to this machine-id (empty = any machine)")
	)
	flag.Parse()

	if strings.TrimSpace(*customer) == "" {
		fail("missing -customer")
	}
	priv, err := loadPrivateKey(*keyFile)
	if err != nil {
		fail(err.Error())
	}

	c := licensing.Claims{
		Customer:  strings.TrimSpace(*customer),
		Tier:      strings.TrimSpace(*tier),
		IssuedAt:  time.Now().Unix(),
		MachineID: strings.TrimSpace(*machine),
		Nonce:     randNonce(),
		Limits:    licensing.Limits{Targets: *targets, Tasks: *tasks, Tokens: *tokens},
	}
	if s := strings.TrimSpace(*expires); s != "" {
		t, err := time.Parse("2006-01-02", s)
		if err != nil {
			fail("bad -expires (want YYYY-MM-DD): " + err.Error())
		}
		// Expire at end of the given day, UTC.
		c.ExpiresAt = t.Add(24 * time.Hour).Unix()
	}
	if f := strings.TrimSpace(*features); f != "" {
		for _, p := range strings.Split(f, ",") {
			if p = strings.TrimSpace(p); p != "" {
				c.Features = append(c.Features, p)
			}
		}
	}

	code, err := licensing.Sign(c, priv)
	if err != nil {
		fail(err.Error())
	}

	fmt.Fprintln(os.Stderr, "── license issued ─────────────────────────────")
	fmt.Fprintf(os.Stderr, "customer : %s\n", c.Customer)
	fmt.Fprintf(os.Stderr, "tier     : %s\n", c.Tier)
	if c.ExpiresAt == 0 {
		fmt.Fprintln(os.Stderr, "expires  : never")
	} else {
		fmt.Fprintf(os.Stderr, "expires  : %s\n", time.Unix(c.ExpiresAt, 0).UTC().Format("2006-01-02"))
	}
	if c.MachineID == "" {
		fmt.Fprintln(os.Stderr, "machine  : any")
	} else {
		fmt.Fprintf(os.Stderr, "machine  : %s\n", c.MachineID)
	}
	fmt.Fprintf(os.Stderr, "limits   : targets=%d tasks=%d tokens=%d (0=unlimited)\n", c.Limits.Targets, c.Limits.Tasks, c.Limits.Tokens)
	fmt.Fprintln(os.Stderr, "── send the customer the code below ───────────")
	// The code itself goes to stdout so it pipes cleanly.
	fmt.Println(code)
}

func keygen() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fail(err.Error())
	}
	fmt.Println("# PUBLIC KEY — paste into licensing/pubkey.go publicKeyB64:")
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
	fmt.Println()
	fmt.Println("# PRIVATE KEY — keep OFFLINE, never commit (e.g. scripts/license-private-key.b64):")
	fmt.Println(base64.StdEncoding.EncodeToString(priv))
}

func loadPrivateKey(file string) (ed25519.PrivateKey, error) {
	raw := strings.TrimSpace(os.Getenv("LICENSE_PRIVATE_KEY"))
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		raw = strings.TrimSpace(string(b))
	}
	if raw == "" {
		return nil, fmt.Errorf("no private key (-key file or LICENSE_PRIVATE_KEY env)")
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key wrong size (%d, want %d)", len(b), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(b), nil
}

func randNonce() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "gen-license: "+msg)
	os.Exit(1)
}
