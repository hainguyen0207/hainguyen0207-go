#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vuln_kb_h1_fetch.py — fetch SPECIFIC public HackerOne disclosed reports by id
(the per-report public .json endpoint) and emit the generic KB-import shape.

For reports you care about — pass the ids. This is NOT a bulk enumerator: it
only fetches ids you give it, one at a time with a polite delay, so you stay
within HackerOne's Terms (no mass crawling). For a large corpus use the public
dataset instead (scripts/vuln_kb_h1_hf.py).

Usage:
  python3 scripts/vuln_kb_h1_fetch.py --out h1_specific.json 4059744 123456 ...
  python3 scripts/vuln_kb_h1_fetch.py --out h1.json --ids ids.txt --delay 3
  python3 scripts/vuln_kb_import.py --db <kb> --source generic --input h1_specific.json
"""
import argparse, json, time, urllib.request, urllib.error, sys

def cat(w):
    w=(w or "").lower()
    if any(k in w for k in ["authorization","access control","idor","direct object","privilege"]): return "Broken Access Control (BAC)"
    if "cross-site scripting" in w or "xss" in w: return "Cross-Site Scripting (XSS)"
    if any(k in w for k in ["injection","ssrf","server-side request","xxe","xml external"]): return "Server-Side Injection"
    if any(k in w for k in ["authentication","session","credential"]): return "Broken Authentication and Session Management"
    if any(k in w for k in ["information","sensitive","exposure"]): return "Sensitive Data Exposure"
    if "csrf" in w: return "Cross-Site Request Forgery (CSRF)"
    if "redirect" in w: return "Unvalidated Redirects and Forwards"
    if any(k in w for k in ["denial","resource consumption","rate"]): return "Application-Level Denial-of-Service (DoS)"
    return "Other"

def fetch(rid):
    req=urllib.request.Request("https://hackerone.com/reports/%s.json"%rid,
        headers={"Accept":"application/json","User-Agent":"vuln-kb-research/1.0"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode("utf-8","ignore"))

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("ids", nargs="*")
    ap.add_argument("--ids", dest="idfile", default="")
    ap.add_argument("--out", required=True)
    ap.add_argument("--delay", type=float, default=2.0)
    a=ap.parse_args()
    ids=list(a.ids)
    if a.idfile:
        ids += [l.strip() for l in open(a.idfile) if l.strip() and l.strip().isdigit()]
    out=[]; ok=0; bad=0
    for i,rid in enumerate(ids):
        try:
            d=fetch(rid)
            if not d.get("vulnerability_information"): bad+=1; continue
            w=(d.get("weakness") or {}); wn=w.get("name") if isinstance(w,dict) else ""
            t=(d.get("team") or {}); prog=t.get("handle") if isinstance(t,dict) else ""
            vi=d.get("vulnerability_information") or ""
            out.append({"ext_id":"h1:"+str(d.get("id") or rid),"name":d.get("title") or "",
                        "category":cat(wn),"subcategory":wn or "",
                        "severity":(d.get("severity_rating") or "").upper() or "VARIES",
                        "description":vi[:4000],"reproduce":vi[:4000],
                        "project":"HackerOne/"+(prog or "disclosed")})
            ok+=1
        except urllib.error.HTTPError as e:
            bad+=1; print("  %s: HTTP %s" % (rid, e.code), file=sys.stderr)
        except Exception as e:
            bad+=1; print("  %s: %s" % (rid, e), file=sys.stderr)
        if i < len(ids)-1: time.sleep(a.delay)
    json.dump(out, open(a.out,"w"), ensure_ascii=False)
    print("fetched ok=%d bad=%d -> %s" % (ok, bad, a.out))

if __name__=="__main__":
    main()
