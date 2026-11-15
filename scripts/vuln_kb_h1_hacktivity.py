#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Pull disclosed report METADATA from HackerOne's OFFICIAL hacktivity API
# (/v1/hackers/hacktivity) — authenticated, paginated, rate-limit aware. Metadata
# only (the API does not return bodies). Outputs the generic KB-import shape.
import json, sys, time, base64, urllib.request, urllib.error
CRED=open(sys.argv[1]).read().strip()           # "user:token"
OUT=sys.argv[2]
MAX=int(sys.argv[3]) if len(sys.argv)>3 else 100000
AUTH="Basic "+base64.b64encode(CRED.encode()).decode()
def cat(w):
    w=(w or "").lower()
    if any(k in w for k in ["authorization","access control","idor","direct object","privilege"]): return "Broken Access Control (BAC)"
    if "cross-site scripting" in w or "xss" in w: return "Cross-Site Scripting (XSS)"
    if any(k in w for k in ["injection","ssrf","server-side request","xxe","xml external"]): return "Server-Side Injection"
    if any(k in w for k in ["authentication","session","credential"]): return "Broken Authentication and Session Management"
    if any(k in w for k in ["information","sensitive","exposure","disclosure"]): return "Sensitive Data Exposure"
    if "csrf" in w: return "Cross-Site Request Forgery (CSRF)"
    if "redirect" in w: return "Unvalidated Redirects and Forwards"
    if any(k in w for k in ["denial","resource consumption"]): return "Application-Level Denial-of-Service (DoS)"
    return "Other"
url=("https://api.hackerone.com/v1/hackers/hacktivity?sortField=latest_disclosable_activity_at&sortDirection=DESC&page%5Bsize%5D=100")
out=[]; pages=0
while url and len(out)<MAX:
    req=urllib.request.Request(url, headers={"Accept":"application/json","Authorization":AUTH})
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            d=json.loads(r.read().decode("utf-8","ignore"))
    except urllib.error.HTTPError as e:
        if e.code==429:
            ra=int(e.headers.get("Retry-After","10")); print("429 backoff %ds"%ra,file=sys.stderr); time.sleep(ra); continue
        print("HTTP",e.code,file=sys.stderr); break
    for it in d.get("data",[]):
        a=it.get("attributes",{})
        if not a.get("disclosed"): continue
        rid=it.get("id") or (a.get("url","").rstrip("/").split("/")[-1])
        cwe=a.get("cwe") or ""
        out.append({"ext_id":"h1:"+str(rid),"name":a.get("title") or "",
                    "category":cat(cwe),"subcategory":cwe,
                    "severity":(a.get("severity_rating") or "VARIES").upper(),
                    "description":a.get("title") or "",
                    "reproduce":"cwe: %s | cve: %s | severity: %s | %s"%(cwe,a.get("cve_ids") or [],a.get("severity_rating") or "",a.get("url") or ""),
                    "project":"HackerOne-hacktivity"})
    pages+=1
    url=(d.get("links") or {}).get("next")
    if pages%10==0: print("  ...page %d, collected %d"%(pages,len(out)),file=sys.stderr)
    time.sleep(0.25)
json.dump(out, open(OUT,"w"), ensure_ascii=False)
print("pages=%d collected=%d -> %s"%(pages,len(out),OUT))
