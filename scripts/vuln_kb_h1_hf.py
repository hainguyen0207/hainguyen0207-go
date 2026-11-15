#!/usr/bin/env python3
# Convert the HuggingFace "Hacker0x01/hackerone_disclosed_reports" parquet splits
# (public, redistributed disclosed H1 reports) into the generic KB import shape.
# Deps: pip install pyarrow --break-system-packages
# Usage:
#   # download: data/{train,test,validation}-00000-of-00001.parquet from
#   #   https://huggingface.co/datasets/Hacker0x01/hackerone_disclosed_reports
#   python3 scripts/vuln_kb_h1_hf.py <dir_with_parquet> h1_generic.json
#   python3 scripts/vuln_kb_import.py --db <kb> --source generic --input h1_generic.json --project HackerOne
import pyarrow.parquet as pq, json, sys, glob
def cat(w):
    w=(w or "").lower()
    import re
    if any(k in w for k in ["authorization","access control","idor","direct object","privilege"]): return "Broken Access Control (BAC)"
    if "cross-site scripting" in w or "xss" in w: return "Cross-Site Scripting (XSS)"
    if any(k in w for k in ["sql injection","code injection","command injection","ssrf","server-side request","xxe","xml external","template injection","injection"]): return "Server-Side Injection"
    if any(k in w for k in ["authentication","session","credential","2fa","otp"]): return "Broken Authentication and Session Management"
    if any(k in w for k in ["information disclosure","information exposure","sensitive","data exposure"]): return "Sensitive Data Exposure"
    if "csrf" in w or "cross-site request" in w: return "Cross-Site Request Forgery (CSRF)"
    if "open redirect" in w or "redirect" in w: return "Unvalidated Redirects and Forwards"
    if "denial" in w or "dos" in w: return "Application-Level Denial-of-Service (DoS)"
    if "misconfiguration" in w: return "Server Security Misconfiguration"
    return "Other"
out=[]
for f in sorted(glob.glob(sys.argv[1]+"/h1_*.parquet")):
    t=pq.read_table(f)
    for r in t.to_pylist():
        w=(r.get("weakness") or {})
        wn=w.get("name") if isinstance(w,dict) else ""
        ss=(r.get("structured_scope") or {})
        sev=ss.get("max_severity") if isinstance(ss,dict) else ""
        team=(r.get("team") or {})
        prog=team.get("handle") if isinstance(team,dict) else ""
        out.append({
            "ext_id":"h1:"+str(r.get("id")),
            "name":r.get("title") or "",
            "category":cat(wn),
            "subcategory":wn or "",
            "severity":(sev or "").upper() or "VARIES",
            "description":(r.get("vulnerability_information") or "")[:4000],
            "reproduce":(r.get("vulnerability_information") or "")[:4000],
            "project":"HackerOne/"+(prog or "disclosed"),
        })
json.dump(out, open(sys.argv[2],"w"), ensure_ascii=False)
print("converted",len(out),"reports")
