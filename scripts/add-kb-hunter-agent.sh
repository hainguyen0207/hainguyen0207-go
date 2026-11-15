#!/usr/bin/env bash
# add-kb-hunter-agent.sh — seed the "KB Hunter" (vuln_kb_hunter) assistant agent.
#
# KB Hunter mines the local vuln knowledge base (~130k real reports + ExploitDB +
# Metasploit + nuclei + CISA KEV) via the query_vuln_kb tool and writes PRIORITIZED
# leads (graph_note tag='kb-lead' + record_fact 'KB-LEAD: ...') for the worker to
# verify. It fires on_finding (expand each finding) and every 30 min (proactive
# tech-surface sweep). Reference-only — it never report_finding itself.
#
# This re-creates the agent that otherwise lives only in Postgres, so a fresh
# deploy (new DB) still gets it. Idempotent: re-running UPDATES in place.
#
# Auth: mints a short-lived server-local JWT from the signing key (root-only),
# so no password/login is needed. Run it ON the server as root (like deploy.sh).
#
# Usage:
#   sudo ./scripts/add-kb-hunter-agent.sh
#   sudo BASE_URL=http://127.0.0.1:8000 LLM_PROFILE_ID=1 ./scripts/add-kb-hunter-agent.sh
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"
BASE_DIR="${HAINGUYEN0207_BASE:-/opt/hainguyen0207}"
JWT_KEY="${JWT_KEY:-$BASE_DIR/jwt.key}"
AGENT_KEY="vuln_kb_hunter"
AGENT_NAME="KB Hunter"
AGENT_DESC="Mines the vuln KB (query_vuln_kb) for variants/chains/known-issues and writes prioritized kb-lead notes for the worker to verify. Reference-only."
PGUSER="${PGUSER:-artex}"; PGPASSWORD="${PGPASSWORD:-artex}"; export PGPASSWORD
PGHOST="${PGHOST:-127.0.0.1}"; PGDB="${PGDB:-artex}"

# ── mint a server-local HS256 token from the signing key (no external deps) ──
if [ ! -r "$JWT_KEY" ]; then
  echo "error: cannot read JWT key at $JWT_KEY (run with sudo on the server)." >&2
  exit 1
fi
TOKEN=$(JWT_KEY="$JWT_KEY" python3 - <<'PY'
import hmac, hashlib, base64, json, time, os
key = open(os.environ["JWT_KEY"], "rb").read()
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=")
now = int(time.time())
h = b64(json.dumps({"alg":"HS256","typ":"JWT"}, separators=(",",":")).encode())
p = b64(json.dumps({"sub":"ARTEX","iat":now,"exp":now+3600}, separators=(",",":")).encode())
sig = b64(hmac.new(key, h + b"." + p, hashlib.sha256).digest())
print((h + b"." + p + b"." + sig).decode())
PY
)
[ -n "$TOKEN" ] || { echo "error: failed to mint token" >&2; exit 1; }
AUTH=(-H "Authorization: Bearer $TOKEN")

# ── resolve the Claude LLM profile (planner needs Claude for KB synthesis) ──
LLM_PROFILE_ID="${LLM_PROFILE_ID:-}"
if [ -z "$LLM_PROFILE_ID" ]; then
  LLM_PROFILE_ID=$(psql -h "$PGHOST" -U "$PGUSER" -d "$PGDB" -tAc \
    "select id from llm_profiles where format='claude-sub' or lower(coalesce(name,'')) like '%claude%' or lower(coalesce(model,'')) like '%claude%' order by is_default desc, id asc limit 1" 2>/dev/null || true)
fi
[ -n "$LLM_PROFILE_ID" ] || LLM_PROFILE_ID=1
echo "KB Hunter -> $BASE_URL  (LLM profile #$LLM_PROFILE_ID)"

req() { # METHOD PATH [JSON]  -> prints HTTP code
  local m="$1" path="$2" data="${3:-}"
  if [ -n "$data" ]; then
    curl -sS -o /dev/null -w '%{http_code}' -X "$m" "$BASE_URL$path" \
      -H 'Content-Type: application/json' "${AUTH[@]}" --data "$data" 2>/dev/null || echo 000
  else
    curl -sS -o /dev/null -w '%{http_code}' -X "$m" "$BASE_URL$path" "${AUTH[@]}" 2>/dev/null || echo 000
  fi
}

# ── 1) create the agent (409 = already exists, fine) ──
body=$(CK="$AGENT_KEY" CN="$AGENT_NAME" CD="$AGENT_DESC" python3 -c \
  'import json,os;print(json.dumps({"Key":os.environ["CK"],"Name":os.environ["CN"],"Description":os.environ["CD"]}))')
code=$(req POST /api/agents "$body")
case "$code" in
  200|201) echo "  agent    created" ;;
  409)     echo "  agent    exists (will update)" ;;
  401|403) echo "  FAIL     auth rejected (HTTP $code)"; exit 1 ;;
  *)       echo "  FAIL     create agent (HTTP $code)"; exit 1 ;;
esac

# ── 2) config: bind Claude, 600s run budget, serial trigger handling ──
cfg=$(ID="$LLM_PROFILE_ID" python3 -c \
  'import json,os;print(json.dumps({"llm_profile_id":int(os.environ["ID"]),"run_seconds":600,"trigger_run_mode":"serial"}))')
echo "  config   $(req PUT "/api/agents/$AGENT_KEY/config" "$cfg")"

# ── 3) prompt (the role/methodology, with diacritics) ──
read -r -d '' PROMPT <<'EOF' || true
Bạn là "KB Hunter" — agent khai thác KHO LỖ HỔNG (~130k report thật + ExploitDB + Metasploit + nuclei + CVE KEV) để MỞ RỘNG độ phủ cho pentest.

NHIỆM VỤ: dựa trên bề mặt THẬT của target (recon_assets / recon_findings / recon_graph) + finding vừa có, dùng query_vuln_kb tìm BIẾN THỂ / CHAIN / known-issue theo tech & bug-class, rồi GHI LẠI lead ưu tiên cho worker kiểm thử.

NGUYÊN TẮC (bắt buộc):
- Chỉ lead CÓ CƠ SỞ: khớp CẢ KB LẪN bề mặt thật của target (tech/endpoint/param có thật). TUYỆT ĐỐI không bịa.
- query_vuln_kb trả DỮ LIỆU THAM KHẢO, KHÔNG chạy mù payload; worker sẽ adapt + VERIFY độc lập.
- BỔ SUNG, không thay vuln-catalogue (worker vẫn soi đủ lớp). Tránh tunnel-vision.
- Mỗi lượt: tối đa 5-10 lead ACTIONABLE, ưu tiên theo severity + khả năng khai thác thực tế, dedup, rồi DỪNG (đừng lan man).
- Ghi lead: graph_note(target, node, tag='kb-lead', note='<cụ thể: test gì, ở đâu, dựa KB #id nào, vì sao reachable>') + record_fact 'KB-LEAD: ...'. Không report_finding (đó là việc của worker sau khi VERIFY).
EOF
pr=$(PT="$PROMPT" python3 -c 'import json,os;print(json.dumps({"Template":os.environ["PT"],"Note":"seed: add-kb-hunter-agent.sh"}))')
echo "  prompt   $(req PUT "/api/agents/$AGENT_KEY/prompt" "$pr")"

# ── 4) trigger: on_finding + every 1800s, each with its own message ──
read -r -d '' FIND_MSG <<'EOF' || true
Vừa có 1 finding. VỌC KB: đọc finding + tech host; query_vuln_kb cho (a) biến thể/bypass cùng bug-class, (b) tech/product host, (c) bug hay CHAIN; lead với-tới-được -> graph_note(tag='kb-lead') + record_fact 'KB-LEAD: ...'. Top 5-10, ưu tiên, dedup, dừng.
EOF
read -r -d '' INT_MSG <<'EOF' || true
Quét KB chủ động theo bề mặt hiện có của task:
1. Đọc tech/host/endpoint đã map (recon_assets / recon_findings kind=http|port / recon_graph).
2. Mỗi tech/sản phẩm/endpoint-type nổi bật CHƯA soi kỹ -> query_vuln_kb tìm lỗ đã biết + biến thể + exploit (nuclei/msf/CVE/report thật).
3. Lead với-tới-được -> graph_note(tag='kb-lead') + record_fact 'KB-LEAD: <test gì, ở đâu, KB #id>'. Top 5-10 ưu tiên, dedup, bỏ cái đã test, rồi dừng. KHÔNG lặp lead đã ghi.
EOF
trig=$(FM="$FIND_MSG" IM="$INT_MSG" python3 -c \
  'import json,os;print(json.dumps({"enabled":True,"on_finding":True,"finding_message":os.environ["FM"],"interval_sec":1800,"interval_message":os.environ["IM"]}))')

# find an existing trigger -> PATCH it; else POST a new one.
TID=$(curl -sS "${AUTH[@]}" "$BASE_URL/api/agents/$AGENT_KEY/triggers" 2>/dev/null \
  | python3 -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
arr=d.get("triggers") if isinstance(d,dict) else d
if isinstance(arr,list) and arr: print(arr[0].get("id") or arr[0].get("ID") or "")' 2>/dev/null || echo "")
if [ -n "$TID" ]; then
  echo "  trigger  $(req PATCH "/api/triggers/$TID" "$trig") (updated #$TID)"
else
  echo "  trigger  $(req POST "/api/agents/$AGENT_KEY/triggers" "$trig") (created)"
fi

echo "done. KB Hunter is enabled: fires on each finding + every 30 min; queries the vuln KB and writes kb-lead notes for the worker."
