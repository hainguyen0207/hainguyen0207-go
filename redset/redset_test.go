package redset

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
)

func TestClassify(t *testing.T) {
	red := []string{
		"rm -rf /", "sudo rm -rf /etc/nginx", "rm -rf ~/.ssh", "cd x && rm -fr /opt/hainguyen0207/data", "rm -r -f ../../..",
		"hydra -l admin -P rockyou.txt ssh://t", "cd w; timeout 600 medusa -h t -u a -P p -M http",
		"sqlmap -u 'http://t/?id=1' --batch --dump", "python3 sqlmap.py -u x --os-shell",
		"mysqldump -h t -u root db > d.sql", "swaks --to a@b.c --server 1.2.3.4", "echo hi | sendmail a@b.c",
		"hping3 --flood -S t", "crontab -e", "echo '* * * * * x' >> /etc/crontab", "echo key >> ~/.ssh/authorized_keys",
		"curl 'http://t/x?id=1;DROP TABLE users--'", "mysql -e \"DELETE FROM users;\"", "git push --force origin main",
		"crackmapexec smb 10.0.0.0/24 -u u -p pass", "dd if=/dev/zero of=/dev/sda",
	}
	auto := []string{
		"cd /opt/hainguyen0207/data/tasks/13/i233 && rm -rf ok2 && mkdir -p ok2", "rm -rf __pycache__", "rm -rf /tmp/work",
		"rm -rf /opt/hainguyen0207/data/tasks/18/i1877/cprof", "rm -f out.txt", `rm -rf "$OUT"`,
		"which nmap nc ncat socat swaks", "for t in dig curl swaks python3; do command -v $t; done",
		`grep -o '"sendEmail","SendEmail"' app.js`, "which hping3 nping tcpdump", "cat > t50.py <<'EOF'",
		"curl -s https://t/hydra/.well-known/openid-configuration", `echo "=== hydra-ish paths ==="`,
		"crontab -l", "sqlmap -u 'http://t/?id=1' --batch --dbs", "nuclei -u https://t", "ffuf -w w.txt -u https://t/FUZZ",
		"curl -s 'https://t/api/user?filter=delete'", "",
	}
	for _, c := range red {
		if d := Classify(c); d.Level != LevelSignoff {
			t.Errorf("want SIGNOFF: %q", c)
		}
	}
	for _, c := range auto {
		if d := Classify(c); d.Level != LevelAuto {
			t.Errorf("want AUTO: %q (%s: %s)", c, d.Signal, d.Reason)
		}
	}
}

func TestReplayHistory(t *testing.T) {
	f := os.Getenv("REDSET_HISTORY")
	if f == "" {
		t.Skip("REDSET_HISTORY unset")
	}
	fh, err := os.Open(f)
	if err != nil {
		t.Skip(err)
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	total, hits := 0, 0
	for sc.Scan() {
		var in struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(sc.Bytes(), &in) != nil || in.Command == "" {
			continue
		}
		total++
		if d := Classify(in.Command); d.Level == LevelSignoff {
			hits++
			c := in.Command
			if len(c) > 220 {
				c = c[:220]
			}
			t.Logf("RED %s (%s): %s", d.Signal, d.Reason, c)
		}
	}
	t.Logf("replayed %d commands, %d flagged", total, hits)
}

func TestHeredocWords(t *testing.T) {
	for _, c := range []string{"cat > a.txt <<'EOF'\nSend\nSendEmail\nSms\nEOF", "cat <<EOF\nhydra\nmedusa\nEOF"} {
		if d := Classify(c); d.Level != LevelAuto {
			t.Errorf("heredoc word flagged: %q (%s)", c, d.Reason)
		}
	}
}
