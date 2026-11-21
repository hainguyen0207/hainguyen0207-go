# -*- coding: utf-8 -*-
"""Taxonomy for the vuln KB. Every rule is a regex over lowercased text
(name + category + subcategory + description + reproduce + tags), English and
Vietnamese-without-diacritics (the internal pentest reports)."""
import re, unicodedata

def fold(t):
    """lowercase + strip Vietnamese diacritics (titles are accented, bodies are not)."""
    t = unicodedata.normalize("NFD", t.replace("đ", "d").replace("Đ", "D"))
    return "".join(c for c in t if unicodedata.category(c) != "Mn").lower()

def R(*alts):
    return re.compile("|".join(alts), re.I)

# ── 1. Nhóm lỗi (vuln class) ─ label, rules. Multi-label; first match = primary
CLASSES = [
 ("rce",            "RCE / thực thi mã",           R(r"\brce\b", r"remote code exec", r"code execution", r"thuc thi (ma|lenh)", r"arbitrary code", r"webshell", r"reverse shell")),
 ("cmd_injection",  "OS command injection",       R(r"command injection", r"os command", r"cwe-78\b", r"cwe-77\b", r"chen lenh", r"shell injection")),
 ("sqli",           "SQL injection",              R(r"sql ?injection", r"\bsqli\b", r"cwe-89\b", r"blind sql", r"union select", r"sqlmap")),
 ("nosqli",         "NoSQL injection",            R(r"nosql", r"mongo(db)? injection", r"\$ne\b", r"\$where")),
 ("ssti",           "Template injection (SSTI)",  R(r"\bssti\b", r"template injection", r"cwe-1336", r"\{\{7\*7\}\}", r"ognl injection", r"expression language injection", r"\bel injection", r"spel")),
 ("xxe",            "XXE",                        R(r"\bxxe\b", r"xml external entit", r"cwe-611\b")),
 ("ldap_xpath",     "LDAP/XPath/khác injection",  R(r"ldap injection", r"xpath injection", r"crlf injection", r"header injection", r"host header injection", r"cwe-93\b", r"cwe-113\b", r"email injection", r"csv injection", r"formula injection")),
 ("xss",            "XSS",                        R(r"\bxss\b", r"cross[- ]site scripting", r"cwe-79\b", r"<script", r"onerror=", r"javascript:")),
 ("ssrf",           "SSRF",                       R(r"\bssrf\b", r"server[- ]side request forgery", r"cwe-918\b", r"169\.254\.169\.254", r"metadata\.google")),
 ("path_traversal", "Path traversal / LFI / RFI", R(r"path traversal", r"directory traversal", r"\btraversal\b", r"\blfi\b", r"\brfi\b", r"local file (inclusion|read)", r"file inclusion", r"arbitrary file (read|download|disclosure)", r"\.\./\.\./", r"cwe-22\b", r"cwe-98\b", r"doc file (tuy y|bat ky|bat ki)", r"/etc/passwd")),
 ("file_upload",    "Upload file nguy hiểm",      R(r"file upload", r"unrestricted upload", r"unsafe file upload", r"arbitrary file upload", r"upload (shell|file)", r"cwe-434\b", r"tai len file", r"upload tuy y")),
 ("deserialization","Deserialization",            R(r"deserializ", r"unserializ", r"cwe-502\b", r"ysoserial", r"gadget chain", r"pickle", r"viewstate")),
 ("idor",           "IDOR / BOLA",                R(r"\bidor\b", r"insecure direct object", r"\bbola\b", r"cwe-639\b", r"thong tin (cua )?nguoi dung khac", r"tai khoan khac", r"user khac", r"another user'?s", r"other users'?")),
 ("privesc",        "Leo quyền / BFLA",           R(r"privilege escalation", r"\bleo quyen\b", r"\bbfla\b", r"broken function level", r"vertical privilege", r"cwe-269\b", r"nang quyen", r"cap nhat quyen", r"escalat(e|ion) (to|of) (admin|root)")),
 ("access_control", "Thiếu kiểm soát truy cập",   R(r"missing (function level )?access control", r"lack of access control", r"improper access control", r"broken access control", r"khong kiem tra phan quyen", r"thieu kiem tra phan quyen", r"truy cap trai phep", r"unauthori[sz]ed access", r"cwe-284\b", r"cwe-285\b", r"cwe-862\b", r"cwe-863\b")),
 ("auth_bypass",    "Bypass xác thực",            R(r"auth(entication)? bypass", r"bypass (the )?(login|authentication|auth)", r"bypass xac thuc", r"bo qua xac thuc", r"unauthenticated access", r"cwe-287\b", r"cwe-306\b", r"missing authentication", r"khong (yeu cau|can) (dang nhap|xac thuc)")),
 ("mfa_otp",        "2FA / OTP",                  R(r"\b2fa\b", r"\bmfa\b", r"two[- ]factor", r"\botp\b", r"one[- ]time pass")),
 ("password_reset", "Quên / đặt lại mật khẩu",    R(r"password reset", r"reset password", r"forgot(ten)? password", r"quen mat khau", r"dat lai mat khau", r"reset token")),
 ("session",        "Session / cookie / token",   R(r"session fixation", r"failure to invalidate session", r"session (hijack|expir|timeout)", r"cookie flag", r"httponly", r"secure flag", r"phien (dang nhap|lam viec)", r"\bjwt\b", r"json web token", r"alg.{0,4}none")),
 ("oauth_sso",      "OAuth / SSO / SAML",         R(r"\boauth", r"\bsso\b", r"\bsaml", r"openid", r"redirect_uri", r"keycloak", r"\bcas\b login")),
 ("csrf",           "CSRF",                       R(r"\bcsrf\b", r"cross[- ]site request forgery", r"cwe-352\b", r"xsrf")),
 ("cors",           "CORS",                       R(r"\bcors\b", r"access-control-allow-origin", r"cross[- ]origin resource")),
 ("open_redirect",  "Open redirect",              R(r"open redirect", r"unvalidated redirect", r"cwe-601\b", r"chuyen huong (tuy y|sang trang)")),
 ("info_disclosure","Lộ thông tin / secret",      R(r"information disclosure", r"info(rmation)? leak", r"sensitive data", r"exposure", r"disclosure of secrets", r"api key", r"secret key", r"hardcoded", r"credential(s)? (leak|exposed|in)", r"\.git/", r"\.env\b", r"source map", r"stack trace", r"debug page", r"lo (lot )?thong tin", r"ro ri", r"cwe-200\b", r"cwe-532\b", r"cwe-798\b")),
 ("misconfig",      "Cấu hình sai / default",     R(r"misconfig", r"default (credential|password|login)", r"exposed (admin|panel|console|dashboard)", r"actuator", r"directory listing", r"phpinfo", r"debug mode", r"cau hinh (sai|khong an toan)", r"security header", r"x-frame-options", r"clickjacking", r"tls|ssl (version|cipher)", r"\bpanel\b")),
 ("business_logic", "Logic nghiệp vụ / thanh toán",R(r"business logic", r"logic (flaw|error|issue)", r"price manipulation", r"payment", r"coupon", r"voucher", r"discount", r"race condition", r"\btoctou\b", r"negative (amount|quantity|value)", r"thanh toan", r"gia tien", r"so tien", r"khuyen mai", r"ma giam gia", r"logic nghiep vu", r"(kiem soat|thao tung|chinh sua|thay doi) (gia|so tien|so luong)", r"gia (cua )?don hang", r"tien thuong", r"so luong .{0,20}(lon hon|am|vuot)", r"cwe-840\b", r"cwe-362\b")),
 ("rate_limit",     "Rate limit / brute force",   R(r"rate limit", r"brute[- ]?force", r"no rate limiting", r"captcha", r"cwe-307\b", r"do mat khau", r"spam (sms|otp|email)", r"gui (sms|otp) lien tuc")),
 ("enumeration",    "Dò tài khoản / enumeration", R(r"enumerat", r"username/email", r"user(name)? existence", r"do (tim )?tai khoan", r"liet ke (tai khoan|nguoi dung)", r"cwe-204\b")),
 ("dos",            "DoS",                        R(r"denial[- ]of[- ]service", r"\bdos\b", r"\bredos\b", r"resource consumption", r"crash", r"cwe-400\b", r"memory exhaustion", r"billion laughs")),
 ("smuggling_cache","Request smuggling / cache",  R(r"request smuggling", r"desync", r"cache poison", r"cache deception", r"web cache", r"http/2 downgrade")),
 ("takeover",       "Subdomain / resource takeover",R(r"subdomain takeover", r"bucket takeover", r"dangling (cname|dns)", r"unclaimed")),
 ("crypto",         "Mã hoá yếu",                 R(r"weak (crypto|cipher|encryption|hash)", r"broken crypto", r"\bmd5\b", r"\bsha1\b", r"padding oracle", r"cwe-327\b", r"cwe-326\b", r"ma hoa yeu", r"plain ?text", r"cleartext", r"luu .{0,20}(dang )?(ro|plain)")),
 ("mobile",         "Mobile",                     R(r"\bandroid\b", r"\bios\b", r"\bapk\b", r"mobile", r"deeplink", r"deep link", r"exported activity", r"webview", r"ssl pinning", r"root detection")),
 ("memory",         "Memory corruption",          R(r"buffer overflow", r"heap overflow", r"use[- ]after[- ]free", r"stack overflow", r"format string", r"out[- ]of[- ]bounds", r"integer overflow", r"cwe-787\b", r"cwe-416\b", r"cwe-125\b")),
 ("mass_assignment","Mass assignment",            R(r"mass assignment", r"parameter pollution", r"\bhpp\b", r"cwe-915\b", r"them truong")),
 ("prototype_poll", "Prototype pollution",        R(r"prototype pollution", r"__proto__")),
]

# ── 2. Kỹ thuật bypass (what was bypassed)
BYPASS = [
 ("waf_bypass",       "Bypass WAF / filter",          R(r"waf bypass", r"bypass(ing)? (the )?waf", r"bypass .{0,20}(filter|sanitiz|blacklist|blocklist)", r"filter bypass", r"(cloudflare|akamai|imperva|modsecurity).{0,30}bypass", r"bypass.{0,30}(cloudflare|akamai|imperva|modsecurity)")),
 ("acl_403_bypass",   "Bypass 403 / ACL / path",      R(r"403 bypass", r"bypass(ing)? 403", r"x-original-url", r"x-rewrite-url", r"x-forwarded-for.{0,40}bypass", r"path normali[sz]", r"\.\.;/", r"/%2e/", r"acl bypass", r"bypass.{0,20}(ip )?(whitelist|allowlist|restriction)")),
 ("auth_bypass",      "Bypass xác thực / login",      R(r"auth(entication)? bypass", r"bypass (the )?(login|authentication|auth\b)", r"login bypass", r"bypass xac thuc", r"bo qua (buoc )?(xac thuc|dang nhap)")),
 ("mfa_otp_bypass",   "Bypass 2FA / OTP",             R(r"(2fa|mfa|otp|two[- ]factor).{0,25}bypass", r"bypass.{0,25}(2fa|mfa|otp|two[- ]factor)", r"bo qua.{0,20}otp", r"otp.{0,30}(response|errorcode|reuse|khong het han)")),
 ("ratelimit_bypass", "Bypass rate limit / captcha",  R(r"rate[- ]limit.{0,25}bypass", r"bypass.{0,25}(rate[- ]limit|captcha|throttl)", r"captcha bypass", r"bo qua captcha")),
 ("authz_bypass",     "Bypass phân quyền",            R(r"authori[sz]ation bypass", r"bypass.{0,25}(authori[sz]ation|access control|permission|phan quyen)", r"access control bypass")),
 ("payment_bypass",   "Bypass thanh toán / giá",      R(r"payment bypass", r"bypass.{0,25}(payment|price|checkout|subscription|paywall)", r"(free|mien phi).{0,30}(premium|subscription|goi cuoc)", r"bo qua thanh toan")),
 ("csp_bypass",       "Bypass CSP / XSS filter",      R(r"csp bypass", r"bypass.{0,20}(csp|content security policy|xss (filter|auditor|protection))")),
 ("ssrf_bypass",      "Bypass SSRF filter",           R(r"ssrf.{0,40}bypass", r"bypass.{0,40}ssrf", r"dns rebinding", r"(decimal|octal|hex) ip", r"0x7f", r"2130706433")),
 ("upload_bypass",    "Bypass kiểm tra upload",       R(r"upload.{0,40}bypass", r"bypass.{0,40}(upload|extension|mime|content-type)", r"double extension", r"\.php\d", r"\.phtml", r"magic byte")),
 ("csrf_bypass",      "Bypass CSRF token / SameSite", R(r"csrf.{0,30}bypass", r"bypass.{0,30}(csrf|samesite)")),
 ("sso_bypass",       "Bypass OAuth / SSO / SAML",    R(r"(oauth|sso|saml|jwt|openid).{0,30}bypass", r"bypass.{0,30}(oauth|sso|saml|jwt|signature)", r"alg.{0,4}none", r"signature (wrapping|bypass|not verified)")),
 ("other_bypass",     "Bypass khác",                  R(r"\bbypass", r"\bbo qua\b")),
]

# ── 3. Tác động (impact)
IMPACT = [
 ("ato",            "Chiếm tài khoản (ATO)",      R(r"account takeover", r"\bato\b", r"take ?over (any|the victim|user|account)", r"chiem (quyen )?tai khoan", r"chiem doat tai khoan", r"chiem quyen (tai khoan|nguoi dung)", r"hijack (any )?(user )?account", r"full account")),
 ("rce",            "Chiếm máy chủ (RCE)",        R(r"\brce\b", r"remote code exec", r"code execution", r"thuc thi (ma|lenh)", r"webshell", r"reverse shell", r"command injection")),
 ("admin_access",   "Lên admin / leo quyền",      R(r"privilege escalation", r"leo quyen", r"admin (access|privilege|panel|account)", r"quyen (admin|quan tri)", r"super ?admin", r"escalat")),
 ("mass_data",      "Lộ dữ liệu hàng loạt / PII", R(r"\bpii\b", r"(all|every|toan bo|tat ca).{0,25}(user|customer|nguoi dung|khach hang|du lieu|record)", r"mass (data|exposure)", r"database dump", r"dump (the )?database", r"cccd|cmnd|so dien thoai|email.{0,10}(cua )?(toan bo|tat ca)", r"credit card", r"so the")),
 ("financial",      "Thiệt hại tài chính",        R(r"payment", r"price", r"free (premium|subscription)", r"refund", r"balance", r"wallet", r"thanh toan", r"so du", r"vi dien tu", r"hoan tien", r"so tien", r"tien thuong", r"gia (tien|ve|san pham|don hang)", r"don hang", r"voucher", r"coupon", r"khuyen mai")),
 ("dos",            "Từ chối dịch vụ",            R(r"denial[- ]of[- ]service", r"\bdos\b", r"crash", r"resource exhaustion")),
]

# ── 4. Công nghệ / sản phẩm (tech): label, regex
TECH = [
 # CMS / ecommerce
 ("WordPress", r"wordpress|\bwp-(admin|content|json|includes)|woocommerce"), ("Joomla", r"joomla"), ("Drupal", r"drupal"),
 ("Magento", r"magento"), ("PrestaShop", r"prestashop"), ("OpenCart", r"opencart"), ("Shopify", r"shopify"),
 ("Liferay", r"liferay"), ("Sitecore", r"sitecore"), ("Umbraco", r"umbraco"), ("DNN", r"dotnetnuke|\bdnn\b"),
 ("Moodle", r"moodle"), ("vBulletin", r"vbulletin"), ("phpBB", r"phpbb"), ("Ghost", r"ghost cms"), ("Strapi", r"strapi"),
 ("TYPO3", r"typo3"), ("Craft CMS", r"craft cms"), ("Concrete5", r"concrete5"), ("MediaWiki", r"mediawiki"),
 # Frameworks / languages
 ("Spring", r"spring( boot| framework| cloud| security|4shell)?\b|actuator"), ("Apache Struts", r"struts"), ("Java/J2EE", r"\bjsp\b|\bj2ee\b|servlet|jsf\b|primefaces"),
 ("Laravel", r"laravel"), ("Symfony", r"symfony"), ("CodeIgniter", r"codeigniter"), ("Yii", r"\byii\b"), ("ThinkPHP", r"thinkphp"), ("CakePHP", r"cakephp"), ("PHP", r"\bphp\b|\.php\b"),
 ("Django", r"django"), ("Flask", r"\bflask\b|werkzeug|jinja"), ("FastAPI", r"fastapi"), ("Python", r"\bpython\b|pickle"),
 ("Ruby on Rails", r"\brails\b|ruby on rails|\berb\b"), ("Node.js/Express", r"node\.?js|\bexpress(js)?\b|\bnpm\b"), ("Next.js", r"next\.?js"), ("Nuxt", r"nuxt"),
 ("React", r"\breact\b"), ("Angular", r"angular"), ("Vue", r"\bvue(\.?js)?\b"), ("jQuery", r"jquery"),
 ("ASP.NET", r"asp\.net|\.aspx\b|\.ashx\b|viewstate|\.net core|blazor"), ("Go", r"\bgolang\b"),
 ("GraphQL", r"graphql"), ("gRPC", r"\bgrpc\b"), ("SOAP/WSDL", r"\bsoap\b|wsdl"), ("WebSocket", r"websocket"),
 # Servers / middleware
 ("Apache HTTPD", r"apache (http|httpd|2\.\d)|\bhttpd\b"), ("Nginx", r"nginx"), ("IIS", r"\biis\b"), ("Tomcat", r"tomcat"), ("JBoss/WildFly", r"jboss|wildfly"),
 ("WebLogic", r"weblogic"), ("WebSphere", r"websphere"), ("GlassFish", r"glassfish"), ("Jetty", r"jetty"),
 ("Log4j", r"log4j|log4shell|jndi"), ("Fastjson/Jackson", r"fastjson|jackson"), ("Shiro", r"\bshiro\b"), ("Solr", r"\bsolr\b"), ("Elasticsearch/Kibana", r"elasticsearch|kibana"),
 ("Redis", r"\bredis\b"), ("MongoDB", r"mongo"), ("MySQL", r"mysql"), ("PostgreSQL", r"postgres"), ("MSSQL", r"mssql|sql server"), ("Oracle DB", r"oracle (db|database)"),
 ("RabbitMQ/Kafka", r"rabbitmq|kafka|activemq"), ("Hadoop/Spark", r"hadoop|\byarn\b|apache spark"), ("Airflow", r"airflow"), ("Nacos", r"nacos"),
 # DevOps / cloud
 ("Jenkins", r"jenkins"), ("GitLab", r"gitlab"), ("GitHub", r"github"), ("Bitbucket", r"bitbucket"), ("Jira/Confluence", r"\bjira\b|confluence|atlassian"),
 ("SonarQube", r"sonarqube"), ("Nexus/Artifactory", r"nexus repository|artifactory"), ("Grafana", r"grafana"), ("Prometheus", r"prometheus"), ("Zabbix", r"zabbix"), ("Nagios", r"nagios"),
 ("Docker", r"docker"), ("Kubernetes", r"kubernetes|\bk8s\b|kubelet|helm"), ("Terraform", r"terraform"), ("Ansible", r"ansible"),
 ("AWS", r"\baws\b|amazon web services|\bs3\b|cognito|lambda|cloudfront|\bec2\b"), ("GCP/Firebase", r"firebase|google cloud|\bgcp\b|storage\.googleapis"), ("Azure", r"\bazure\b"),
 ("Cloudflare", r"cloudflare"), ("Akamai", r"akamai"),
 # Enterprise / VPN / network
 ("Microsoft Exchange", r"exchange server|\bowa\b|proxyshell|proxylogon|\bexchange\b"), ("SharePoint", r"sharepoint"), ("Windows/AD", r"active directory|\bntlm\b|kerberos|\bsmb\b|windows server"),
 ("Citrix", r"citrix|netscaler"), ("Fortinet", r"fortinet|fortigate|fortios|fortiweb"), ("Pulse/Ivanti", r"pulse secure|ivanti"), ("Palo Alto", r"palo alto|pan-os|globalprotect"),
 ("Cisco", r"\bcisco\b"), ("F5 BIG-IP", r"big-?ip|\bf5\b"), ("SonicWall", r"sonicwall"), ("VMware", r"vmware|vcenter|esxi"), ("Zimbra", r"zimbra"),
 ("SAP", r"\bsap\b"), ("Oracle EBS/Fusion", r"oracle (e-business|ebs|fusion|weblogic)"), ("Salesforce", r"salesforce"), ("ServiceNow", r"servicenow"), ("Zoho", r"zoho|manageengine"),
 ("Keycloak", r"keycloak"), ("Okta", r"\bokta\b"), ("Auth0", r"auth0"), ("Moodle", r"moodle"),
 ("phpMyAdmin", r"phpmyadmin"), ("Webmin/cPanel", r"webmin|cpanel|plesk"), ("Roundcube", r"roundcube"),
 ("IoT/Router", r"router|\bnas\b|\bdvr\b|\bnvr\b|ip camera|hikvision|dahua|d-link|tp-link|netgear|zyxel|tenda"),
 # Mobile / payment / VN-specific
 ("Android", r"\bandroid\b|\bapk\b"), ("iOS", r"\bios\b|\bipa\b"), ("Payment gateway", r"vnpay|momo|zalopay|napas|stripe|paypal|payment gateway|cong thanh toan"),
 ("OpenKM/DMS", r"openkm|alfresco"), ("Odoo", r"\bodoo\b"),
]
TECH = [(t, re.compile(p, re.I)) for t, p in TECH]

CVE_RE = re.compile(r"\bcve-(\d{4})-(\d{4,7})\b", re.I)


# Rules that are noisy on long report bodies: in the BODY they only count via
# these stricter phrases (None = title/category/tags only).
BODY_STRICT = {
 ("impact", "financial"):  R(r"price manipulation", r"(change|modify|tamper).{0,20}(price|amount)", r"negative (amount|price|quantity)", r"(chinh sua|thay doi|sua).{0,20}(gia|so tien|gia tri giao dich)", r"so (tien )?am", r"mua .{0,20}(mien phi|0 ?d)", r"free (premium|subscription|order)"),
 ("impact", "mass_data"):  R(r"\bpii\b", r"dump (the )?(whole |entire )?database", r"database dump", r"toan bo (du lieu|thong tin) (cua )?(nguoi dung|khach hang|he thong)", r"(all|every) (users?|customers?)'? (data|records|pii|information|emails?)", r"millions? of (users|records)", r"(cccd|cmnd|can cuoc).{0,40}(toan bo|tat ca|hang loat)"),
 ("impact", "admin_access"): R(r"privilege escalation", r"leo quyen", r"(gain|obtain|get) admin", r"quyen (admin|quan tri)", r"super ?admin"),
 ("bypass", "waf_bypass"): R(r"waf bypass", r"bypass(ing|ed)? (the )?waf", r"(cloudflare|akamai|imperva|modsecurity|f5 asm|aws waf).{0,30}bypass", r"bypass.{0,30}(cloudflare|akamai|imperva|modsecurity|waf)"),
 ("bypass", "acl_403_bypass"): R(r"403 bypass", r"bypass(ing)? (the )?403", r"bypass.{0,20}(ip )?(whitelist|allowlist|restriction)", r"path normali[sz]ation.{0,40}(bypass|truy cap)"),
 ("bypass", "other_bypass"): None,
 ("bypass", "csp_bypass"): R(r"csp bypass", r"bypass(ing)? (the )?(csp|content security policy)"),
 ("bypass", "upload_bypass"): R(r"bypass.{0,30}(upload|extension|mime|content-type) (check|filter|validation|restriction)", r"upload.{0,30}bypass", r"double extension"),
}
