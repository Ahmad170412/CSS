import json
from datetime import datetime


def generate_report(state) -> str:
    lines = []
    lines.append("=" * 60)
    lines.append("  CYBER SULTANATE SYSTEM - FINAL REPORT")
    lines.append(f"  Target: {state.target}")
    lines.append(f"  Date:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 60)

    lines.append("")
    lines.append("[SCOUT RECONNAISSANCE]")
    if state.scout_report:
        report = state.scout_report
        lines.append(f"  Target: {report.get('target', 'N/A')}")

        ports = report.get("open_ports", [])
        if ports:
            port_strs = []
            for p in ports:
                if isinstance(p, dict):
                    pid = p.get("port", p.get("portid", "?"))
                    proto = p.get("protocol", "tcp")
                    port_strs.append(f"{pid}/{proto}")
                else:
                    port_strs.append(str(p))
            lines.append(f"  Open Ports: {', '.join(port_strs)}")

        services = report.get("services", [])
        if services:
            lines.append("  Services:")
            for s in services:
                lines.append(f"    - {s.get('port', '?')}/{s.get('protocol', 'tcp')}  {s.get('name', '?')}  {s.get('version', '?')}")

        web = report.get("web_technologies", [])
        if web:
            lines.append("  Web Technologies:")
            for w in web:
                lines.append(f"    - {w.get('name', '?')} {w.get('version', '?')}")

        subdomains = report.get("subdomains", [])
        if subdomains:
            lines.append(f"  Subdomains: {', '.join(subdomains)}")

        directories = report.get("directories_found", [])
        if directories:
            lines.append(f"  Directories: {', '.join(directories)}")
    else:
        lines.append("  (No scout data)")

    lines.append("")
    lines.append("[PLANNER VULNERABILITY ASSESSMENT]")
    if state.planner_report:
        findings = state.planner_report.get("findings", [])
        if findings:
            for f in findings:
                lines.append(f"  - {f.get('service', '?')} {f.get('version', '?')}")
                lines.append(f"    CVE: {f.get('cve_id', 'N/A')}  CVSS: {f.get('cvss_score', '?')}")
                lines.append(f"    Exploit: {f.get('exploit_available', False)}")
                lines.append(f"    Summary: {f.get('summary', '')}")
                lines.append("")
        else:
            lines.append("  No vulnerabilities identified.")
    else:
        lines.append("  (No planner data)")

    lines.append("")
    lines.append("[RAIDER EXPLOITATION]")
    if state.raider_report:
        actions = state.raider_report.get("actions", [])
        if actions:
            for a in actions:
                status = "SUCCESS" if a.get("success") else "FAILED"
                lines.append(f"  - {a.get('vulnerability', '?')}: {status}")
                lines.append(f"    Method: {a.get('method', '?')}")
                lines.append(f"    Result: {a.get('result', '?')}")
                lines.append("")
        else:
            lines.append("  No exploitation attempted.")
    elif state.planner_report and state.planner_report.get("findings", []):
        lines.append("  Raider phase was not executed (disabled or skipped).")
    else:
        lines.append("  No vulnerabilities to exploit.")

    lines.append("=" * 60)
    lines.append("  END OF REPORT")
    lines.append("=" * 60)

    return "\n".join(lines)


def generate_json_report(state) -> str:
    return json.dumps({
        "target": state.target,
        "timestamp": datetime.now().isoformat(),
        "scout": state.scout_report,
        "planner": state.planner_report,
        "raider": state.raider_report,
    }, indent=2, default=str)
