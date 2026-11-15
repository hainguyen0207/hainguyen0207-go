#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vuln_kb_import.py — normalize a vulnerability source into the shared vuln KB
(SQLite: projects / issues / issues_fts), matching the existing schema so
query_vuln_kb searches it. Re-runnable (dedup by external id). No scraping of
any platform — feed it exports/datasets you are allowed to use.

Sources:
  nuclei   --input <nuclei-templates dir>   (public, open-source detection rules)
  generic  --input <file.json>              (list of {name, category, severity,
                                              description, reproduce, subcategory?,
                                              ext_id?, project?, platform?})
           # map H1 / Bugcrowd / your own exports to this shape, then import.

Usage:
  python3 scripts/vuln_kb_import.py --db /opt/hainguyen0207/knowledge/issues.sqlite3 \
          --source nuclei --input /root/.local/nuclei-templates
  python3 scripts/vuln_kb_import.py --db <db> --source generic --input reports.json \
          --project "HackerOne (my export)" --platform WEB
"""
import argparse, json, os, sys, sqlite3, glob

SEV = {"critical":"CRITICAL","high":"HIGH","medium":"MEDIUM","low":"LOW",
       "info":"INFO","informational":"INFO","none":"INFO","unknown":"VARIES",
       "p1":"CRITICAL","p2":"HIGH","p3":"MEDIUM","p4":"LOW","p5":"INFO"}

CWE_CAT = {
    "79":"Cross-Site Scripting (XSS)", "80":"Cross-Site Scripting (XSS)",
    "89":"Server-Side Injection", "564":"Server-Side Injection",
    "78":"Server-Side Injection", "77":"Server-Side Injection",
    "94":"Server-Side Injection", "917":"Server-Side Injection",
    "90":"Server-Side Injection", "611":"Server-Side Injection",
    "918":"Server-Side Injection", "1336":"Server-Side Injection",
    "22":"Broken Access Control (BAC)", "23":"Broken Access Control (BAC)",
    "284":"Broken Access Control (BAC)", "285":"Broken Access Control (BAC)",
    "639":"Broken Access Control (BAC)", "862":"Broken Access Control (BAC)",
    "863":"Broken Access Control (BAC)", "425":"Broken Access Control (BAC)",
    "287":"Broken Authentication and Session Management",
    "384":"Broken Authentication and Session Management",
    "613":"Broken Authentication and Session Management",
    "798":"Broken Authentication and Session Management",
    "522":"Broken Authentication and Session Management",
    "200":"Sensitive Data Exposure", "538":"Sensitive Data Exposure",
    "209":"Sensitive Data Exposure", "532":"Sensitive Data Exposure",
    "352":"Cross-Site Request Forgery (CSRF)",
    "601":"Unvalidated Redirects and Forwards",
    "434":"Server-Side Injection", "502":"Server-Side Injection",
    "16":"Server Security Misconfiguration", "1021":"Server Security Misconfiguration",
    "400":"Application-Level Denial-of-Service (DoS)",
}
DIR_CAT = {
    "cves":"Using Components with Known Vulnerabilities",
    "vulnerabilities":"Other",
    "misconfiguration":"Server Security Misconfiguration",
    "exposures":"Sensitive Data Exposure",
    "exposed-panels":"Sensitive Data Exposure",
    "default-logins":"Broken Authentication and Session Management",
    "takeovers":"Broken Access Control (BAC)",
    "token-spray":"Sensitive Data Exposure",
}

def ensure_schema(db):
    db.executescript("""
    CREATE TABLE IF NOT EXISTS projects(
      id INTEGER PRIMARY KEY, name TEXT, main_language TEXT, status TEXT,
      platform TEXT, owner_id INTEGER, owner_username TEXT, owner_name TEXT,
      owner_email TEXT, raw_json TEXT, updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS issues(
      id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, name TEXT NOT NULL,
      status TEXT, category TEXT, subcategory TEXT, severity TEXT, priority TEXT,
      raw_json TEXT NOT NULL, updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE VIRTUAL TABLE IF NOT EXISTS issues_fts USING fts5(
      name, description, reproduce, tokenize='unicode61 remove_diacritics 2');
    """)

def get_project(db, name, platform="WEB", lang=""):
    r = db.execute("SELECT id FROM projects WHERE name=?", (name,)).fetchone()
    if r: return r[0]
    cur = db.execute(
      "INSERT INTO projects(name, main_language, status, platform, raw_json) VALUES(?,?,?,?,?)",
      (name, lang, "imported", platform, json.dumps({"source":name})))
    return cur.lastrowid

def existing_ext_ids(db):
    ids = set()
    for (rj,) in db.execute("SELECT raw_json FROM issues WHERE raw_json LIKE '%\"ext_id\"%'"):
        try: ids.add(json.loads(rj).get("ext_id"))
        except Exception: pass
    return ids

def insert_issue(db, pid, name, category, subcategory, severity, description, reproduce, ext_id, extra):
    raw = dict(extra or {}); raw["ext_id"] = ext_id
    cur = db.execute(
      "INSERT INTO issues(project_id,name,status,category,subcategory,severity,priority,raw_json) VALUES(?,?,?,?,?,?,?,?)",
      (pid, name[:500], "imported", category, subcategory, severity, severity, json.dumps(raw, ensure_ascii=False)))
    iid = cur.lastrowid
    db.execute("INSERT INTO issues_fts(rowid,name,description,reproduce) VALUES(?,?,?,?)",
               (iid, name, description or "", reproduce or ""))
    return iid

def import_nuclei(db, root):
    import yaml
    pid = get_project(db, "nuclei-templates", "WEB", "yaml")
    seen = existing_ext_ids(db)
    added = skipped = bad = 0
    files = glob.glob(os.path.join(root, "http", "**", "*.yaml"), recursive=True) \
          + glob.glob(os.path.join(root, "network", "**", "*.yaml"), recursive=True)
    for f in files:
        try:
            with open(f, "r", errors="ignore") as fh:
                doc = yaml.safe_load(fh)
            if not isinstance(doc, dict): bad += 1; continue
            tid = doc.get("id") or os.path.basename(f)
            ext = "nuclei:" + str(tid)
            if ext in seen: skipped += 1; continue
            info = doc.get("info") or {}
            name = str(info.get("name") or tid)
            sev = SEV.get(str(info.get("severity","")).lower(), "VARIES")
            cls = info.get("classification") or {}
            cwes = cls.get("cwe-id"); cwe = ""
            if isinstance(cwes, list) and cwes: cwe = str(cwes[0])
            elif isinstance(cwes, str): cwe = cwes
            cwe_num = cwe.replace("CWE-","").replace("cwe-","").strip()
            rel = os.path.relpath(f, root).split(os.sep)
            dcat = ""
            for seg in rel:
                if seg in DIR_CAT: dcat = DIR_CAT[seg]; break
            category = CWE_CAT.get(cwe_num, dcat or "Other")
            tags = info.get("tags") or ""
            if isinstance(tags, list): tags = ",".join(tags)
            subcategory = (cwe or (tags.split(",")[0] if tags else ""))[:200]
            desc = str(info.get("description") or "").strip()
            rp = []
            cveid = cls.get("cve-id")
            if cveid: rp.append("CVE: " + (",".join(cveid) if isinstance(cveid,list) else str(cveid)))
            if cwe: rp.append("CWE: " + cwe)
            if tags: rp.append("tags: " + tags)
            http = doc.get("http") or doc.get("requests") or []
            for blk in (http if isinstance(http, list) else []):
                if not isinstance(blk, dict): continue
                m = blk.get("method","")
                paths = blk.get("path") or []
                if isinstance(paths, str): paths = [paths]
                for p in paths[:6]:
                    rp.append(("%s %s" % (m, p)).strip())
                words = []
                for x in (blk.get("matchers") or []):
                    if isinstance(x, dict):
                        if x.get("type")=="status" and x.get("status"): words.append("status=%s" % x["status"])
                        if x.get("type")=="word" and x.get("words"): words.append("words=%s" % (x["words"][:3]))
                if words: rp.append("match: " + "; ".join(str(w) for w in words[:4]))
            ref = info.get("reference") or []
            if isinstance(ref, list) and ref: rp.append("ref: " + str(ref[0]))
            rem = info.get("remediation")
            if rem: rp.append("fix: " + str(rem).strip()[:300])
            reproduce = "\n".join(rp)[:2000]
            insert_issue(db, pid, name, category, subcategory, sev, desc, reproduce, ext,
                         {"src":"nuclei","id":tid,"cwe":cwe,"cve":cveid,"tags":tags})
            seen.add(ext); added += 1
            if added % 2000 == 0: db.commit(); print("  ...%d added" % added)
        except Exception:
            bad += 1
    db.commit()
    return added, skipped, bad

def import_generic(db, path, project, platform):
    data = json.load(open(path, "r", errors="ignore"))
    if isinstance(data, dict): data = data.get("issues") or data.get("reports") or data.get("data") or []
    seen = existing_ext_ids(db)
    added = skipped = bad = 0
    for i, it in enumerate(data):
        try:
            if not isinstance(it, dict): bad += 1; continue
            ext = "gen:" + str(it.get("ext_id") or it.get("id") or (project or "")+":"+str(i))
            if ext in seen: skipped += 1; continue
            name = str(it.get("name") or it.get("title") or "untitled")
            sev = SEV.get(str(it.get("severity") or it.get("priority") or "").lower().replace(" ",""), "VARIES")
            category = it.get("category") or "Other"
            subcategory = it.get("subcategory") or it.get("weakness") or ""
            desc = str(it.get("description") or it.get("summary") or it.get("content") or "")
            reproduce = str(it.get("reproduce") or it.get("steps") or it.get("poc") or "")
            pj = it.get("project") or project or "generic-import"
            ppid = get_project(db, pj, platform or "WEB")
            insert_issue(db, ppid, name, category, subcategory, sev, desc, reproduce, ext, {"src":"generic","orig":it.get("id")})
            seen.add(ext); added += 1
        except Exception:
            bad += 1
    db.commit()
    return added, skipped, bad

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--source", required=True, choices=["nuclei","generic"])
    ap.add_argument("--input", required=True)
    ap.add_argument("--project", default="")
    ap.add_argument("--platform", default="WEB")
    a = ap.parse_args()
    db = sqlite3.connect(a.db)
    ensure_schema(db)
    before = db.execute("SELECT count(*) FROM issues").fetchone()[0]
    if a.source == "nuclei":
        added, skipped, bad = import_nuclei(db, a.input)
    else:
        added, skipped, bad = import_generic(db, a.input, a.project, a.platform)
    total = db.execute("SELECT count(*) FROM issues").fetchone()[0]
    db.close()
    print("source=%s  added=%d  skipped(dup)=%d  bad=%d  | issues: %d -> %d"
          % (a.source, added, skipped, bad, before, total))

if __name__ == "__main__":
    main()
