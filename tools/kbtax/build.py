# -*- coding: utf-8 -*-
import sqlite3, sys, json, re, collections, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from taxonomy import CLASSES, BYPASS, IMPACT, TECH, CVE_RE, BODY_STRICT, fold

SRC, OUT = sys.argv[1], sys.argv[2]
t0 = time.time()
src = sqlite3.connect("file:" + SRC + "?mode=ro", uri=True)
if os.path.exists(OUT): os.remove(OUT)
out = sqlite3.connect(OUT)
out.executescript("""
CREATE TABLE tag_def(dim TEXT, tag TEXT, label TEXT, n INTEGER DEFAULT 0, PRIMARY KEY(dim, tag));
CREATE TABLE issue_meta(issue_id INTEGER PRIMARY KEY, source TEXT, scope TEXT, primary_class TEXT, quality TEXT, score INTEGER,
  has_steps INTEGER, severity TEXT, cves TEXT, kev INTEGER, title TEXT);
CREATE TABLE issue_tag(issue_id INTEGER, dim TEXT, tag TEXT, PRIMARY KEY(issue_id, dim, tag));
CREATE INDEX issue_tag_dt ON issue_tag(dim, tag);
CREATE TABLE tech_profile(tech TEXT, dim TEXT, tag TEXT, n INTEGER, share REAL, lift REAL, examples TEXT, PRIMARY KEY(tech, dim, tag));
CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);
""")
SEVW = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
STEPS = re.compile(r"(^|\s)(1[.)]|buoc 1|step 1|steps to reproduce|cac buoc|poc\b|proof of concept)", re.I)
CONCRETE = re.compile(r"\b(get|post|put|patch|delete) /|https?://|param(eter)?\s*`|tham so|payload|`[a-z_]+=|\{\{|<script|curl ", re.I)
CHAIN = re.compile(r"dan (den|toi)|leads? to|chain(ed|ing)?|ket hop|combin(ed|ing) with|escalat", re.I)
NONWEB = re.compile(r"\b(local|dos|hardware|windows|linux|macos|android|ios|multiple)\b", re.I)

def source_of(d):
    s = d.get("src")
    return {"exploitdb": "exploit", "msf": "exploit", "nuclei": "scanner", "kev": "kev", "generic": "bugbounty"}.get(s, "internal" if "project" in d else (s or "?"))

kev_cves = set()
for (raw,) in src.execute("select raw_json from issues where raw_json like '%\"src\": \"kev\"%'"):
    for c in CVE_RE.findall(json.loads(raw).get("cve") or ""): kev_cves.add("CVE-%s-%s" % c)

cnt = collections.defaultdict(collections.Counter)
meta_rows, tag_rows = [], []
rows = src.execute("""select i.id, i.name, coalesce(i.category,''), coalesce(i.subcategory,''), coalesce(i.severity,''), i.raw_json,
                      substr(coalesce(f.description,''),1,6000), substr(coalesce(f.reproduce,''),1,6000)
                      from issues i join issues_fts f on f.rowid=i.id""")
for rid, name, cat, sub, sev, raw, desc, rep in rows:
    try: d = json.loads(raw)
    except Exception: d = {}
    source = source_of(d)
    tags = " ".join(str(d.get(k) or "") for k in ("tags", "cwe", "codes", "file", "path"))
    head = fold(" ".join([name or "", cat, sub, tags]))
    body = fold(desc + " " + rep)
    full = head + " " + body
    labels = []
    # vuln classes: trust the title/category; fall back to the body only when the head says nothing
    hc = [k for k, _, r in CLASSES if r.search(head)]
    bc = [k for k, _, r in CLASSES if r.search(body)] if not hc else []
    classes = hc or bc[:3]
    if classes == ["xss"] and False: pass
    labels += [("class", c) for c in classes]
    def hit(dim, k, r, body_ok=True):
        if r.search(head): return True
        if not body_ok: return False
        sr = BODY_STRICT.get((dim, k), r)
        return bool(sr and sr.search(body))
    byp = [k for k, _, r in BYPASS if hit("bypass", k, r)]
    if len(byp) > 1 and "other_bypass" in byp: byp.remove("other_bypass")
    labels += [("bypass", b) for b in byp]
    imp = [k for k, _, r in IMPACT if hit("impact", k, r, source in ("internal", "bugbounty"))]
    labels += [("impact", i) for i in imp]
    techs = [t for t, r in TECH if r.search(full)]
    labels += [("tech", t) for t in techs[:6]]
    cves = sorted({"CVE-%s-%s" % c for c in CVE_RE.findall(full + " " + str(d.get("cve") or ""))})
    if cves: labels.append(("ref", "has_cve"))
    kev = int(any(c in kev_cves for c in cves))
    if kev: labels.append(("ref", "in_kev"))
    # scope
    fpath = str(d.get("file") or d.get("path") or "").lower()
    if "mobile" in classes or re.search(r"\b(android|ios|apk)\b", head): scope = "mobile"
    elif source == "exploit" and ("webapps" in fpath or "webapps" in sub.lower() or "/http/" in fpath or "webapp" in fpath): scope = "web"
    elif source == "exploit" and NONWEB.search(fpath + " " + sub): scope = "infra_local"
    elif "memory" in classes: scope = "infra_local"
    else: scope = "web"
    labels.append(("scope", scope))
    # quality: is it a good, reusable testcase?
    has_steps = int(len(rep) > 200 or bool(STEPS.search(body)))
    score = SEVW.get(sev.upper(), 1)
    score += 3 * has_steps + 2 * bool(CONCRETE.search(body)) + 2 * bool(CHAIN.search(body))
    score += 3 * bool({"ato", "rce", "admin_access", "mass_data"} & set(imp)) + 2 * bool(byp and byp != ["other_bypass"])
    score += 1 * (len(body) > 1500) + 2 * kev
    if source == "exploit" and len(body) < 200: score = min(score, 4)
    quality = "A" if score >= 12 else "B" if score >= 8 else "C"
    labels.append(("quality", quality))
    primary = classes[0] if classes else "unclassified"
    meta_rows.append((rid, source, scope, primary, quality, score, has_steps, sev.upper(), ",".join(cves), kev, (name or "")[:300]))
    labels.append(("source", source))
    for dim, tag in set(labels):
        tag_rows.append((rid, dim, tag)); cnt[dim][tag] += 1
    if not classes: cnt["class"]["unclassified"] += 1

out.executemany("insert into issue_meta values (?,?,?,?,?,?,?,?,?,?,?)", meta_rows)
out.executemany("insert or ignore into issue_tag values (?,?,?)", tag_rows)
LBL = {**{("class", k): l for k, l, _ in CLASSES}, **{("bypass", k): l for k, l, _ in BYPASS}, **{("impact", k): l for k, l, _ in IMPACT}}
for dim, c in cnt.items():
    for tag, n in c.items():
        out.execute("insert or replace into tag_def values (?,?,?,?)", (dim, tag, LBL.get((dim, tag), tag), n))
total = len(meta_rows)
# tech profiles: which classes / bypasses / impacts are characteristic for a tech (lift vs. whole KB)
gl = {(dim, t): n / total for dim in ("class", "bypass", "impact") for t, n in cnt[dim].items()}
by_tech = collections.defaultdict(set)
for rid, dim, tag in tag_rows:
    if dim == "tech": by_tech[tag].add(rid)
tags_of = collections.defaultdict(list)
for rid, dim, tag in tag_rows:
    if dim in ("class", "bypass", "impact"): tags_of[rid].append((dim, tag))
qual = {m[0]: m[5] for m in meta_rows}
for tech, ids in by_tech.items():
    n = len(ids)
    c = collections.Counter(); ex = collections.defaultdict(list)
    for rid in ids:
        for dt in tags_of[rid]:
            c[dt] += 1; ex[dt].append(rid)
    for (dim, tag), k in c.items():
        if k < 3: continue
        best = sorted(ex[(dim, tag)], key=lambda r: -qual[r])[:5]
        out.execute("insert into tech_profile values (?,?,?,?,?,?,?)", (tech, dim, tag, k, k / n, (k / n) / max(gl[(dim, tag)], 1e-9), json.dumps(best)))
out.execute("insert into meta values ('built_at', datetime('now'))")
out.execute("insert into meta values ('total', ?)", (str(total),))
out.commit()
print("done", total, "rows in %.0fs" % (time.time() - t0))
