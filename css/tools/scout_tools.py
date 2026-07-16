import json
import re
import xml.etree.ElementTree as ET
import httpx
import tempfile
import os
from urllib.parse import urlparse
from css.tools.utils import _run, _check_tool


WORDLIST_CANDIDATES = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/opt/homebrew/share/dirb/wordlists/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
]

_FALLBACK_PATHS = [
    "/admin", "/login", "/wp-admin", "/administrator",
    "/backup", "/config", "/css", "/images", "/js",
    "/robots.txt", "/sitemap.xml", "/.htaccess",
    "/index.php", "/index.html", "/api", "/api/v1",
    "/phpinfo.php", "/test.php", "/dbadmin",
]


def _find_wordlist():
    for path in WORDLIST_CANDIDATES:
        if os.path.exists(path):
            return path
    return None


def _make_temp_wordlist():
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(_FALLBACK_PATHS))
    return path


def _http_get(url, verify=True, **kwargs):
    try:
        return httpx.get(url, verify=verify, **kwargs)
    except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError):
        if url.startswith("https://"):
            http_url = "http://" + url[8:]
            try:
                return httpx.get(http_url, verify=verify, **kwargs)
            except Exception:
                raise
        raise


def _ensure_scheme(target):
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def nmap(target, flags=""):
    if not _check_tool("nmap"):
        return {"success": False, "ports": [], "error": "nmap not found. Install nmap."}
    flags_list = flags.split() if flags else []
    fd, xml_path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    try:
        cmd = ["nmap", "-oX", xml_path] + flags_list + [target]
        result = _run(cmd, timeout=300)
        if result["success"] and os.path.getsize(xml_path) > 0:
            with open(xml_path) as f:
                xml_content = f.read()
            parser = ET.XMLParser(resolve_entities=False)
            root = ET.fromstring(xml_content, parser=parser)
            ports = []
            for port in root.iter("port"):
                port_info = {
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "state": None,
                    "service": None,
                    "version": None,
                }
                state_elem = port.find("state")
                if state_elem is not None:
                    port_info["state"] = state_elem.get("state")
                service_elem = port.find("service")
                if service_elem is not None:
                    port_info["service"] = service_elem.get("name")
                    port_info["version"] = " ".join(
                        filter(None, [
                            service_elem.get("product", ""),
                            service_elem.get("version", ""),
                            service_elem.get("extrainfo", ""),
                        ])
                    ).strip() or None
                ports.append(port_info)
            return {"success": True, "ports": ports, "raw": xml_content[:2000]}
        return {"success": result["success"], "ports": [], "error": result["stderr"]}
    except ET.ParseError:
        return {"success": False, "ports": [], "error": "XML parse failed"}
    finally:
        try:
            os.unlink(xml_path)
        except OSError:
            pass


def whatweb(target, verify=True):
    url = _ensure_scheme(target)
    if _check_tool("whatweb"):
        try:
            result = _run(["whatweb", "--log-verbose", "/dev/stdout", url], timeout=30)
            if result["success"] and result["stdout"].strip():
                techs = []
                for line in result["stdout"].split("\n"):
                    if not line.strip() or line.startswith("["):
                        continue
                    parts = line.split(",")
                    for part in parts:
                        part = part.strip()
                        tech_match = re.match(r"([^[]+)(?:\[([^\]]*)\])?", part)
                        if tech_match:
                            name = tech_match.group(1).strip()
                            version = tech_match.group(2) or ""
                            if name:
                                techs.append({"name": name, "version": version})
                if techs:
                    return {"success": True, "technologies": techs, "raw": result["stdout"][:2000]}
        except Exception:
            pass
    try:
        resp = _http_get(url, timeout=10, verify=verify, follow_redirects=True)
    except Exception as e:
        return {"success": False, "technologies": [], "error": str(e)[:100]}
    headers = dict(resp.headers)
    techs = []
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    if server:
        parts = server.split("/", 1)
        techs.append({"name": parts[0].strip(), "version": parts[1].strip() if len(parts) > 1 else ""})
    if powered:
        for t in powered.split(","):
            t = t.strip()
            if "/" in t:
                n, v = t.split("/", 1)
                techs.append({"name": n.strip(), "version": v.strip()})
            else:
                techs.append({"name": t})
    ct = resp.headers.get("content-type", "")
    if "php" in ct:
        techs.append({"name": "PHP"})
    return {"success": True, "technologies": techs, "headers": headers, "raw": resp.text[:500]}


def gobuster(target, wordlist="", extensions=""):
    if not _check_tool("gobuster"):
        return {"success": False, "paths": [], "error": "gobuster not found. Install gobuster."}
    wl_path = wordlist if wordlist and os.path.exists(wordlist) else _find_wordlist()
    cleanup = False
    if not wl_path:
        wl_path = _make_temp_wordlist()
        cleanup = True
    url = _ensure_scheme(target)
    cmd = ["gobuster", "dir", "-u", url, "-w", wl_path]
    if extensions:
        cmd.extend(["-x", extensions])
    cmd.extend(["-q", "-t", "20"])
    result = _run(cmd, timeout=120)
    paths = []
    if result["success"]:
        for line in result["stdout"].split("\n"):
            for m in re.finditer(r"(/\S+)\s+\(Status:\s*(\d+)\)", line):
                paths.append({"path": m.group(1), "status": int(m.group(2))})
    if cleanup:
        try:
            os.unlink(wl_path)
        except OSError:
            pass
    return {"success": result["success"], "paths": paths, "raw": result["stdout"][:2000], "error": result["stderr"]}


def dnsrecon(domain, type="std"):
    if not _check_tool("dnsrecon"):
        return {"success": False, "records": [], "error": "dnsrecon not found. Install dnsrecon."}
    result = _run(["dnsrecon", "-d", domain, "-t", type], timeout=60)
    records = []
    if result["success"]:
        for line in result["stdout"].split("\n"):
            line = line.strip()
            if not line or line.startswith("*") or "DNSSEC" in line or "Using" in line:
                continue
            match = re.match(r"\[([A-Z]+)\]\s+(.+)", line)
            if match:
                records.append({"type": match.group(1), "value": match.group(2).strip()})
    return {"success": result["success"], "records": records, "raw": result["stdout"][:2000]}


def whois(target):
    if not _check_tool("whois"):
        return {"success": False, "parsed": {}, "error": "whois not found. Install whois."}
    result = _run(["whois", target], timeout=30)
    parsed = {}
    keys_of_interest = [
        "domain name", "registrar", "registrar url", "creation date",
        "registry expiry date", "expiry date", "updated date",
        "name server", "registrant name", "registrant organization",
        "orgname", "org name", "admin organization", "tech organization",
        "registrant email", "admin email", "tech email",
        "dnssec", "status", "whois server", "refer",
    ]
    if result["success"]:
        raw = result["stdout"]
        lines = raw.split("\n")
        for line in lines:
            stripped = line.strip()
            if ":" not in stripped:
                continue
            key, _, val = stripped.partition(":")
            key = key.strip().lower()
            val = val.strip()
            if not key or not val:
                continue
            if key in keys_of_interest:
                normalized_key = {
                    "domain name": "domain",
                    "registrar": "registrar",
                    "registrar url": "registrar_url",
                    "creation date": "creation_date",
                    "registry expiry date": "expiry_date",
                    "expiry date": "expiry_date",
                    "name server": "name_servers",
                    "registrant organization": "org",
                    "orgname": "org",
                    "org name": "org",
                    "registrant name": "registrant",
                    "dnssec": "dnssec",
                    "whois server": "whois_server",
                    "refer": "whois_server",
                }.get(key, key.replace(" ", "_"))
                existing = parsed.get(normalized_key)
                if existing:
                    if isinstance(existing, list):
                        parsed[normalized_key].append(val)
                    else:
                        parsed[normalized_key] = [existing, val]
                else:
                    parsed[normalized_key] = val
        if "name_servers" in parsed and isinstance(parsed["name_servers"], str):
            parsed["name_servers"] = [parsed["name_servers"]]
    return {"success": result["success"], "parsed": parsed, "raw": result["stdout"][:2000]}


def http_probe(target, flags="", verify=True):
    url = _ensure_scheme(target)
    try:
        resp = _http_get(url, timeout=15, verify=verify, follow_redirects=True)
    except Exception as e:
        return {"success": False, "data": {}, "error": str(e)}
    data = {
        "status_code": resp.status_code,
        "title": "",
        "server": resp.headers.get("server", ""),
        "content_type": resp.headers.get("content-type", ""),
        "content_length": len(resp.content),
        "headers": dict(resp.headers),
        "location": str(resp.url),
    }
    m = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
    if m:
        data["title"] = m.group(1).strip()[:100]
    return {"success": True, "data": data, "raw": resp.text[:500]}


def shodan(query):
    if not _check_tool("shodan"):
        return {"success": False, "results": [], "error": "shodan CLI not found. Install shodan."}
    result = _run(["shodan", "search", "--fields", "ip_str,port,org,hostnames", query], timeout=30)
    results_list = []
    if result["success"]:
        for line in result["stdout"].split("\n")[1:]:
            if line.strip():
                results_list.append(line.strip())
    return {"success": result["success"], "results": results_list, "raw": result["stdout"][:2000]}


def ffuf(target, wordlist="", extensions=""):
    if not _check_tool("ffuf"):
        return {"success": False, "paths": [], "error": "ffuf not found. Install ffuf (brew install ffuf)."}
    wl_path = wordlist if wordlist and os.path.exists(wordlist) else _find_wordlist()
    cleanup = False
    if not wl_path:
        wl_path = _make_temp_wordlist()
        cleanup = True
    url = _ensure_scheme(target).rstrip("/") + "/FUZZ"
    cmd = ["ffuf", "-u", url, "-w", wl_path, "-ac", "-t", "40", "-s"]
    if extensions:
        cmd.extend(["-e", extensions])
    result = _run(cmd, timeout=120)
    paths = []
    seen = set()
    if result["success"]:
        for line in result["stdout"].split("\n"):
            line = line.strip()
            if not line:
                continue
            path = "/" + line.split("/FUZZ")[0].rsplit("/", 1)[-1] if "/FUZZ" in url else line
            try:
                from urllib.parse import urlparse
                parsed = urlparse(line)
                if parsed.path:
                    path = parsed.path
            except Exception:
                pass
            if path not in seen:
                seen.add(path)
                paths.append({"path": path, "status": 0})
        if not paths:
            for m in re.finditer(r"(/\S+)\s+\(Status:\s*(\d+)\)", result["stdout"]):
                p = m.group(1)
                if p not in seen:
                    seen.add(p)
                    paths.append({"path": p, "status": int(m.group(2))})
    if cleanup:
        try:
            os.unlink(wl_path)
        except OSError:
            pass
    return {"success": result["success"], "paths": paths, "raw": result["stdout"][:2000], "error": result["stderr"]}


def web_crawl(target, depth=1, verify=True):
    url = _ensure_scheme(target)
    try:
        resp = _http_get(url, timeout=15, verify=verify, follow_redirects=True)
    except Exception as e:
        return {"success": False, "urls": [], "forms": [], "error": str(e)}
    text = resp.text
    base = str(resp.url).rstrip("/")
    base_netloc = urlparse(base).netloc
    urls = set()
    forms = []
    for m in re.finditer(r'href=["\'](.*?)["\']', text, re.IGNORECASE | re.DOTALL):
        link = m.group(1).split("#")[0].split("?")[0]
        if not link or link.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        if link.startswith("/"):
            link = base + link
        elif not link.startswith("http"):
            link = base + "/" + link
        link_netloc = urlparse(link).netloc
        if link_netloc == base_netloc or link_netloc.endswith("." + base_netloc):
            urls.add(link.rstrip("/"))
    for m in re.finditer(
        r'<form(?:\s+[^>]*)?>',
        text,
        re.IGNORECASE | re.DOTALL,
    ):
        form_html = m.group(0)
        action = "GET"
        method = "GET"
        am = re.search(r'action=["\'](.*?)["\']', form_html, re.IGNORECASE | re.DOTALL)
        if am:
            action = am.group(1)
            if action.startswith("/"):
                action = base + action
            elif not action.startswith("http"):
                action = base + "/" + action
        mm = re.search(r'method=["\'](.*?)["\']', form_html, re.IGNORECASE | re.DOTALL)
        if mm:
            method = mm.group(1).upper()
        forms.append({"action": action, "method": method})
    for m in re.finditer(r'<input[^>]*name=["\'](.*?)["\']', text, re.IGNORECASE | re.DOTALL):
        if forms:
            fields = forms[-1].setdefault("fields", [])
            fields.append(m.group(1))
    title_match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    title = title_match.group(1).strip()[:100] if title_match else ""
    return {
        "success": True,
        "urls": sorted(urls)[:50],
        "forms": forms[:10],
        "title": title,
        "status": resp.status_code,
    }
