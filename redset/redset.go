// Package redset is the destructive-line classifier: given a shell command an
// agent is about to run, it decides whether the action is non-destructive (an
// autonomous agent may run it) or belongs to the "red set" that requires explicit
// operator sign-off.
//
// Ported from ScopeWeaver/bcpen (AGPL-3.0, an ARTEX derivative; taxonomy from
// hackbot's exploit_overseer) and tightened for precision after replaying a week
// of real agent commands (26,821): the original word-boundary patterns flagged
// ~27 false positives (local `rm -rf pages` cleanup, "sendEmail" inside a grep,
// `which hping3`, Ory "hydra/.well-known" paths) and only ~1 real red action.
// Here tool names count only in COMMAND POSITION (start of a command, after
// ; && || | $( ` or sudo/timeout/env/nohup/time), and `rm -rf` only when it
// deletes outside the task workspace / temp dirs.
//
// It is a command-string heuristic and defense-in-depth, not the sole control.
package redset

import (
	"regexp"
	"strings"
)

// Level is the classification outcome.
type Level int

const (
	// LevelAuto: non-destructive (reversible, self-scoped, read/scan/probe).
	LevelAuto Level = iota
	// LevelSignoff: the red set; requires explicit operator sign-off.
	LevelSignoff
)

func (l Level) String() string {
	if l == LevelSignoff {
		return "signoff"
	}
	return "auto"
}

// Decision is the verdict plus, for a red-set hit, which category and why.
type Decision struct {
	Level  Level
	Signal string // destructive | dos | exfil | bruteforce | sideeffect | persistence
	Reason string
}

// cmdPos matches the start of a shell command: line start or a separator,
// then optional wrappers (sudo, timeout N, env A=B, nohup, exec, time, python3
// for script tools) and an optional directory prefix.
const cmdPos = `(?:^|[;&|(` + "`" + `{]|\$\()\s*(?:(?:sudo(?:\s+-\S+)*|timeout(?:\s+-\S+)*\s+\S+|env(?:\s+\w+=\S*)*|nohup|exec|time|command)\s+)*(?:\S*/)?`

// atCmd matches a tool invoked in command position WITH at least one argument
// on the same line. Case-sensitive on purpose (shell commands are): a bare or
// capitalized word on its own line, e.g. "SendEmail" inside a heredoc list, is
// data, not an invocation.
func atCmd(names string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)` + cmdPos + `(?:` + names + `)[ \t]+\S`)
}

type rule struct {
	re     *regexp.Regexp
	signal string
	reason string
}

var rules = []rule{
	// --- mass / irreversible destruction ---
	{atCmd(`mkfs(?:\.\w+)?|shred|wipefs`), "destructive", "filesystem wipe / secure erase"},
	{regexp.MustCompile(`(?im)` + cmdPos + `dd\s[^\n]*\bof=/dev/`), "destructive", "dd writing to a raw device"},
	{regexp.MustCompile(`(?i)>\s*/dev/(sd|nvme|hd|mapper|vd|xvd)`), "destructive", "redirect onto a block device"},
	{regexp.MustCompile(`(?i)\b(drop|truncate)\s+(table|database|schema)\b`), "destructive", "SQL DROP/TRUNCATE of a table/database"},
	{regexp.MustCompile(`(?im)\bdelete\s+from\s+[\w."` + "`" + `\[\]]+\s*(;|--|#|'|"|$)`), "destructive", "SQL DELETE with no WHERE clause (mass delete)"},
	{regexp.MustCompile(`(?i)git\s+push\s[^\n]*(--force\b|--force-with-lease)|git\s+push\s+-[a-z]*f`), "destructive", "git force-push (rewrites remote history)"},
	{regexp.MustCompile(`:\(\)\s*\{\s*:\|:&\s*\}`), "destructive", "fork bomb"},

	// --- persistence / foothold ---
	{regexp.MustCompile(`(?i)>>?\s*\S*\.ssh/authorized_keys`), "persistence", "write to authorized_keys"},
	{regexp.MustCompile(`(?i)>>?\s*/etc/(cron|rc\.local|systemd/system)`), "persistence", "write a cron job / boot service"},
	{regexp.MustCompile(`(?im)` + cmdPos + `systemctl\s+enable\b`), "persistence", "enable a service at boot"},

	// --- denial-of-service volume ---
	{atCmd(`hping3|slowloris(?:\.py)?|goldeneye(?:\.py)?|t50|mhddos|torshammer|slowhttptest|siege|thc-ssl-dos`), "dos", "denial-of-service tool"},

	// --- credential brute force / spraying ---
	{atCmd(`hydra|medusa|ncrack|patator|crowbar`), "bruteforce", "online credential brute-force tool"},
	{regexp.MustCompile(`(?im)` + cmdPos + `(?:crackmapexec|nxc|netexec)\s[^\n]*(\s-p\s|--password|-H\s)`), "bruteforce", "credential spray via crackmapexec/nxc"},

	// --- data exfiltration at scale ---
	{atCmd(`mysqldump|pg_dump|pg_dumpall|mongodump`), "exfil", "full database dump"},
	{regexp.MustCompile(`(?im)` + cmdPos + `(?:python3?\s+\S*)?sqlmap(?:\.py)?\s[^\n]*(--dump-all|--dump\b|--os-shell|--os-pwn|--os-cmd|--file-write|--file-dest|--sql-shell)`), "exfil", "sqlmap bulk dump / OS or file interaction"},

	// --- real-world side effects on third parties ---
	{atCmd(`sendmail|swaks|sendemail|mailx|mutt`), "sideeffect", "sends email (real-world side effect)"},
	{regexp.MustCompile(`(?i)\b(api\.twilio\.com|api\.sendgrid\.com|api\.mailgun\.net|api\.postmarkapp\.com)\b`), "sideeffect", "calls an email/SMS delivery API"},
}

var (
	reCrontab = regexp.MustCompile(`(?im)` + cmdPos + `crontab\b([^\n;&|]*)`)
	reRm      = regexp.MustCompile(`(?im)` + cmdPos + `rm\s+([^\n;&|]*)`)
)

// safeRmPrefixes are places an agent may wipe without sign-off: its own task
// workspace and temp dirs.
var safeRmPrefixes = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/opt/hainguyen0207/data/tasks/", "/opt/hainguyen0207/runs/"}

// rmIsDangerous reports whether an `rm` argument string is a recursive+force
// delete reaching outside the task workspace / temp dirs.
func rmIsDangerous(args string) bool {
	fields := strings.Fields(args)
	recursive, force := false, false
	var targets []string
	for _, f := range fields {
		switch {
		case f == "--":
			continue
		case f == "--recursive":
			recursive = true
		case f == "--force":
			force = true
		case strings.HasPrefix(f, "--"):
		case strings.HasPrefix(f, "-") && len(f) > 1:
			if strings.ContainsAny(f, "rR") {
				recursive = true
			}
			if strings.Contains(f, "f") {
				force = true
			}
		default:
			targets = append(targets, strings.Trim(f, `"'`))
		}
	}
	if !recursive || !force {
		return false
	}
	for _, t := range targets {
		if t == "" {
			continue
		}
		switch {
		case t == "/" || t == "/*" || t == "." || t == ".." || t == "*" || t == "./*":
			return true
		case strings.HasPrefix(t, "~"), strings.HasPrefix(t, "$HOME"), strings.HasPrefix(t, "${HOME}"):
			return true
		case strings.HasPrefix(t, "../.."):
			return true
		case strings.HasPrefix(t, "/"):
			safe := false
			for _, p := range safeRmPrefixes {
				if strings.HasPrefix(t, p) && !strings.Contains(t, "..") {
					safe = true
					break
				}
			}
			if !safe {
				return true
			}
		}
		// Relative paths and $VARS stay Auto: they resolve inside the agent's
		// working directory in practice; a heuristic cannot evaluate variables.
	}
	return false
}

// Classify inspects a command and returns its destructive-line decision. The
// default is Auto; Signoff only on a specific red-set signal.
func Classify(command string) Decision {
	if strings.TrimSpace(command) == "" {
		return Decision{Level: LevelAuto}
	}
	for _, m := range reRm.FindAllStringSubmatch(command, -1) {
		if rmIsDangerous(m[1]) {
			return Decision{Level: LevelSignoff, Signal: "destructive", Reason: "recursive force delete (rm -rf) outside the task workspace/temp dirs"}
		}
	}
	for _, m := range reCrontab.FindAllStringSubmatch(command, -1) {
		if !strings.Contains(" "+m[1]+" ", " -l ") { // crontab -l only lists
			return Decision{Level: LevelSignoff, Signal: "persistence", Reason: "installs/edits a cron job (crontab)"}
		}
	}
	for _, r := range rules {
		if r.re.MatchString(command) {
			return Decision{Level: LevelSignoff, Signal: r.signal, Reason: r.reason}
		}
	}
	return Decision{Level: LevelAuto}
}

// RequiresSignoff reports whether the command is in the red set.
func RequiresSignoff(command string) bool { return Classify(command).Level == LevelSignoff }
