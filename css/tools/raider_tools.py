import tempfile
import os
import re
from css.tools.utils import _run, _check_tool


def _split_host_port(target: str) -> tuple[str, str | None]:
    if target.startswith("["):
        m = re.match(r"^\[([0-9a-fA-F:]+)\](?::(\d+))?$", target)
        if m:
            return m.group(1), m.group(2)
        return target, None
    if ":" in target:
        host, _, port = target.rpartition(":")
        if port.isdigit():
            return host, port
    return target, None


def sqlmap(target, flags="--batch --level=1 --risk=1"):
    if not _check_tool("sqlmap"):
        return {"success": False, "vulnerable": False, "error": "sqlmap not found. Install sqlmap."}
    cmd = ["sqlmap", "-u", target] + flags.split()
    result = _run(cmd, timeout=300)
    success_indicators = [
        "Parameter:",
        "GET parameter",
        "POST parameter",
        "Type:",
        "Title:",
        "injectable",
        "vulnerable",
    ]
    is_vulnerable = any(ind in result["stdout"] for ind in success_indicators)
    return {
        "success": result["success"],
        "vulnerable": is_vulnerable and result["success"],
        "output": result["stdout"][:3000],
        "error": result["stderr"],
    }


def hydra(target, service, username, password):
    if not _check_tool("hydra"):
        return {"success": False, "credentials_found": False, "error": "hydra not found. Install hydra."}
    host, port = _split_host_port(target)
    cmd = ["hydra", "-l", username, "-p", password, host]
    if port:
        cmd.extend(["-s", port])
    cmd.append(service)
    result = _run(cmd, timeout=120)
    stdout = result["stdout"]
    # More specific success indicators to avoid false positives
    # Look for hydra's actual success format: [SUCCESS] or [80][http-post-form] etc.
    success_patterns = [
        r"\[\s*SUCCESS\s*\]",
        r"\[\s*\d+\]\[.*?\].*?login:.*?password:",
        r"1 valid password found",
        r"\[.*?\]\s+host:.*?login:.*?password:",
    ]
    found = any(re.search(p, stdout, re.IGNORECASE) for p in success_patterns)
    return {
        "success": result["success"] or found,
        "credentials_found": found,
        "output": stdout[:3000],
    }


def metasploit(module, options, payload=""):
    if not _check_tool("msfconsole"):
        return {"success": False, "exploit_success": False, "error": "msfconsole not found. Install metasploit-framework."}
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".rc", delete=False
    ) as f:
        f.write(f"use {module}\n")
        # Parse options as key=value pairs, respecting quoted values
        if options:
            # Split on semicolon or newline, but not inside quotes
            opt_parts = re.split(r"(?:;|\n)\s*", options.strip())
            for opt in opt_parts:
                opt = opt.strip()
                if not opt:
                    continue
                # Find first = to split key=value
                eq_idx = opt.find("=")
                if eq_idx > 0:
                    key = opt[:eq_idx].strip()
                    val = opt[eq_idx+1:].strip()
                    # Strip surrounding quotes if present
                    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                        val = val[1:-1]
                    f.write(f"set {key} {val}\n")
        if payload:
            f.write(f"set PAYLOAD {payload}\n")
        f.write("run\n")
        f.write("exit\n")
        rc_path = f.name

    try:
        result = _run(
            ["msfconsole", "-q", "-r", rc_path], timeout=300
        )
        success_indicators = [
            "Meterpreter session",
            "Command shell session",
            "SESSION",
            "succeeded",
        ]
        succeeded = any(ind in result["stdout"] for ind in success_indicators)
        return {
            "success": result["success"],
            "exploit_success": succeeded,
            "output": result["stdout"][:3000],
        }
    finally:
        try:
            os.unlink(rc_path)
        except OSError:
            pass


def nmap_vuln(target, script="vuln"):
    import xml.etree.ElementTree as ET
    if not _check_tool("nmap"):
        return {"success": False, "vulnerabilities": [], "error": "nmap not found. Install nmap."}
    fd, xml_path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    try:
        cmd = ["nmap", "-sV", "--script", script, "-oX", xml_path, target]
        result = _run(cmd, timeout=300)
        vulns = []
        if result["success"] and os.path.getsize(xml_path) > 0:
            with open(xml_path) as f:
                xml_content = f.read()
            parser = ET.XMLParser(resolve_entities=False)
            root = ET.fromstring(xml_content, parser=parser)
            for script_elem in root.iter("script"):
                vulns.append({
                    "id": script_elem.get("id", ""),
                    "output": script_elem.get("output", "")[:200],
                })
        return {"success": result["success"], "vulnerabilities": vulns}
    except ET.ParseError:
        return {"success": False, "vulnerabilities": [], "error": "XML parse failed"}
    finally:
        try:
            os.unlink(xml_path)
        except OSError:
            pass
