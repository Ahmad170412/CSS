import re
import httpx
import os
import time
from css.tools.utils import _run, _check_tool, get_proxy_url


def searchsploit(query):
    if not _check_tool("searchsploit"):
        return {"success": False, "exploits": [], "error": "searchsploit not found. Install exploitdb."}
    result = _run(["searchsploit", "--disable-colour", query], timeout=30)
    exploits = []
    if result["success"]:
        for line in result["stdout"].split("\n"):
            line = line.strip()
            if "|" not in line or line.startswith("-") or "Exploit Title" in line or "Shellcodes" in line:
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 2:
                title = parts[0]
                path = parts[1] if len(parts) > 1 else ""
                exploit_id = ""
                id_match = re.search(r"(\d+)\.", path)
                if id_match:
                    exploit_id = id_match.group(1)
                exploits.append({
                    "id": exploit_id,
                    "title": title,
                    "path": path,
                })
    return {"success": result["success"], "exploits": exploits, "raw": result["stdout"][:3000]}


CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


def nvd_query(cve_id):
    if not CVE_PATTERN.match(cve_id.strip()):
        return {"success": False, "error": f"Invalid CVE format: {cve_id}. Expected CVE-YYYY-NNNNN"}
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    api_key = os.environ.get("NVD_API_KEY", "")
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    
    # Initialize defaults
    descriptions = []
    cvss_data = {}
    
    proxy = get_proxy_url(url)
    proxy_param = proxy if proxy else None
    for attempt in range(3):
        try:
            resp = httpx.get(url, headers=headers, timeout=15, proxy=proxy_param)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                vuln = vulns[0].get("cve", {}) if vulns else {}
                metrics = vuln.get("metrics", {})
                cvss_list = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV3") or [{}]
                cvss_data = cvss_list[0].get("cvssData", {}) if cvss_list else {}
                descriptions = vuln.get("descriptions", [])
                description = ""
                for d in descriptions:
                    if d.get("lang") == "en":
                        description = d.get("value", "")
                        break
                return {
                    "success": True,
                    "cve_id": cve_id,
                    "cvss_score": cvss_data.get("baseScore"),
                    "cvss_severity": cvss_data.get("baseSeverity"),
                    "description": description[:500],
                }
            if resp.status_code == 403:
                if attempt < 2:
                    time.sleep(2 * (2 ** attempt))  # 2s, 4s
                    continue
                return {"success": False, "error": "NVD API rate limited. Set NVD_API_KEY env var for higher limits."}
            return {"success": False, "error": f"HTTP {resp.status_code}"}
        except httpx.HTTPError as e:
            if attempt < 2:
                time.sleep(2 * (2 ** attempt))
                continue
            return {"success": False, "error": f"HTTP error: {e}"}
        except Exception as e:
            if attempt < 2:
                time.sleep(2 * (2 ** attempt))
                continue
            return {"success": False, "error": str(e)}
    return {"success": False, "error": "Max retries exceeded"}


def nikto(target):
    if not _check_tool("nikto"):
        return {"success": False, "findings": [], "error": "nikto not found. Install nikto."}
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    cmd = ["nikto", "-h", target, "-Format", "txt", "-nointeractive"]
    if target.startswith("https://"):
        cmd.append("-ssl")
    result = _run(cmd, timeout=120)
    items = []
    if result["success"]:
        for line in result["stdout"].split("\n"):
            if "+" in line and ("OSVDB" in line or "CVE" in line or ":" in line):
                items.append(line.strip())
    return {"success": result["success"], "findings": items[:30], "raw": result["stdout"][:3000]}
