import json
import re
import concurrent.futures
import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule

from css.config import Config, Target
from css.models.state import SultanateState, PhaseState
from css.models.report import generate_report, generate_json_report
from css.prompts.scout import SCOUT_SYSTEM_PROMPT
from css.prompts.planner import PLANNER_SYSTEM_PROMPT
from css.prompts.raider import RAIDER_SYSTEM_PROMPT
from css.tools.registry import TOOL_REGISTRY
from css.tools.utils import set_proxy_env

console = Console()


class Sultanate:
    def __init__(self, target: str, model: str = "llama3.2:3b", verbose: bool = False, skip_raider: bool = False, proxy: str = "", tor: bool = False, proxy_dns: bool = False):
        self.config = Config(model=model, verbose=verbose, skip_raider=skip_raider, proxy=proxy, tor=tor, proxy_dns=proxy_dns)
        self.target_obj = Target(target)
        self.state = SultanateState(target=target)
        self.state.config = self.config
        env = self.config.proxy_env()
        if env:
            set_proxy_env(env)

    def _ollama_chat(self, messages: list[dict], retries: int = 2) -> str:
        url = f"{self.config.ollama_host}/api/chat"
        payload = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            },
        }
        last_error = None
        for attempt in range(retries + 1):
            try:
                resp = httpx.post(url, json=payload, timeout=300, proxies=None)
                resp.raise_for_status()
                data = resp.json()
                content = data.get("message", {}).get("content", "")
                if self.config.verbose:
                    phase_name = self.state.phase.upper() if self.state.phase else "UNKNOWN"
                    console.print(Panel(content[:500], title=f"[bold cyan]{phase_name} LLM Response (truncated)[/]"))
                return content
            except httpx.ConnectError:
                console.print("[bold red]Error:[/] Cannot connect to Ollama. Is it running?")
                console.print("  Start it with: [bold]ollama serve[/]")
                raise
            except httpx.ReadTimeout:
                last_error = f"Read timeout (attempt {attempt + 1}/{retries + 1})"
                console.print(f"[yellow]⚠ Ollama {last_error}. Retrying...[/]")
                continue
            except httpx.HTTPStatusError as e:
                last_error = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
                if attempt < retries:
                    console.print(f"[yellow]⚠ Ollama error: {last_error}. Retrying...[/]")
                    continue
                break
            except Exception as e:
                if isinstance(e, (KeyboardInterrupt, SystemExit)):
                    raise
                last_error = str(e)
                if attempt < retries:
                    console.print(f"[yellow]⚠ Ollama error: {e}. Retrying...[/]")
                    continue
                break
        console.print(f"[bold red]Ollama API error:[/] {last_error}")
        raise Exception(last_error)

    def _parse_tool_calls(self, text: str) -> list[dict]:
        if not text:
            return []
        text = text.strip()
        calls = []

        concluded = re.search(r"^\s*(?:DONE|CONCLUDE|FINISH)\s*[.!]?\s*$", text, re.IGNORECASE | re.MULTILINE)

        for pat in [r"```(?:tool|json)\n(.*?)```"]:
            for m in re.finditer(pat, text, re.DOTALL):
                try:
                    parsed = json.loads(m.group(1))
                    if isinstance(parsed, dict) and "tool" in parsed:
                        calls.append(parsed)
                except (json.JSONDecodeError, TypeError):
                    continue

        clean = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
        lines = clean.split("\n")
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if not line:
                i += 1
                continue
            fm = re.search(r"(?:^|\b)(?:TOOL|CMD|ACTION)[:\s]+(\w+)", line, re.IGNORECASE)
            if not fm:
                i += 1
                continue
            name = fm.group(1).lower()
            if name in ("conclude", "done", "finish", "stop"):
                report = {}
                for rl in lines[i + 1:]:
                    rs = rl.strip()
                    if not rs or rs.startswith(("```", "TOOL", "CMD", "ACTION")):
                        break
                    kv = re.match(r"(\w[\w_]*)\s*[=:]\s*(.+)", rs)
                    if kv:
                        report[kv.group(1)] = kv.group(2).strip("\"'")
                calls.append({"tool": "conclude", "report": report})
                i += 1
                continue
            args = {}
            rest = line[fm.end():].strip()
            for kv in re.finditer(r'(\w[\w_]*)\s*=\s*("[^"]*"|\'[^\']*\'|\S+)', rest):
                args[kv.group(1)] = kv.group(2).strip("\"'")
            j = i + 1
            while j < len(lines):
                rl = lines[j].strip()
                nf = re.search(r"(?:^|\b)(?:TOOL|CMD|ACTION|DONE|CONCLUDE)[:\s]", rl, re.IGNORECASE)
                if nf or not rl:
                    break
                kv = re.match(r"(\w[\w_]*)\s*[=:]\s*(.+)", rl)
                if kv:
                    args[kv.group(1)] = kv.group(2).strip("\"'")
                j += 1
            calls.append({"tool": name, "args": args})
            i = j

        if concluded and not any(c.get("tool") == "conclude" for c in calls):
            calls.append({"tool": "conclude", "report": {}})
        elif not calls:
            for j in range(len(clean)):
                if clean[j] != "{":
                    continue
                depth = 0
                for k in range(j, len(clean)):
                    if clean[k] == "{":
                        depth += 1
                    elif clean[k] == "}":
                        depth -= 1
                        if depth == 0:
                            try:
                                parsed = json.loads(clean[j:k + 1])
                                if isinstance(parsed, dict) and "tool" in parsed:
                                    calls.append(parsed)
                            except (json.JSONDecodeError, TypeError):
                                pass
                            break

        return calls

    def _condense_result(self, tool_name: str, result: dict) -> str:
        if tool_name == "nmap":
            ports = result.get("ports", [])
            open_ports = [p for p in ports if p.get("state") == "open"]
            if open_ports:
                lines = [f"Open ports ({len(open_ports)}):"]
                for p in open_ports[:15]:
                    v = f" {p['version']}" if p.get("version") else ""
                    lines.append(f"  {p['port']}/{p['protocol']}  {p['service']}{v}")
                if len(open_ports) > 15:
                    lines.append(f"  ... and {len(open_ports) - 15} more")
                return "\n".join(lines)
            return f"No open ports found (scanned {len(ports)} ports)"
        if tool_name == "whatweb":
            if not result.get("success", True):
                err = result.get("error", "") or result.get("stderr", "")
                return f"whatweb failed: {err[:200]}"
            techs = result.get("technologies", [])
            if techs:
                return f"Technologies ({len(techs)}): {', '.join(t['name'] for t in techs[:10])}"
            return "No technologies detected"
        if tool_name == "whois":
            parsed = result.get("parsed", {})
            parts = []
            for k in ["org", "registrar", "creation_date", "expiry_date"]:
                if k in parsed:
                    parts.append(f"{k}={parsed[k]}")
            servers = parsed.get("name_servers", [])
            if servers:
                parts.append(f"ns={', '.join(servers[:3])}")
            return "; ".join(parts) if parts else "No whois data parsed"
        if tool_name == "dnsrecon":
            records = result.get("records", [])
            if records:
                parts = []
                for r in records[:5]:
                    if isinstance(r, dict):
                        parts.append(f"{r.get('type', '?')}: {r.get('value', '')}")
                    else:
                        parts.append(str(r))
                return f"DNS ({len(records)}): {'; '.join(parts)}"
            return "No DNS records found"
        if tool_name == "gobuster":
            if not result.get("success", True):
                err = result.get("error", "") or result.get("stderr", "")
                return f"gobuster failed: {err[:200]}. Try whatweb or httpx instead."
            paths = result.get("paths", [])
            if paths:
                return f"Discovered paths: {[p['path'] for p in paths[:10]]}"
            return "No paths discovered"
        if tool_name == "httpx":
            data = result.get("data", {})
            keys = ["status_code", "title", "server", "content_type", "content_length"]
            return json.dumps({k: data[k] for k in keys if k in data}, default=str)
        if tool_name == "shodan":
            results = result.get("results", [])
            return f"Shodan: {len(results)} results" if results else "No Shodan data"
        if tool_name == "ffuf":
            paths = result.get("paths", [])
            if paths:
                return f"ffuf found: {[p['path'] for p in paths[:10]]}"
            return "No paths found via ffuf"
        if tool_name == "web_crawl":
            urls = result.get("urls", [])
            forms = result.get("forms", [])
            parts = [f"Status: {result.get('status', '?')}"]
            if result.get("title"):
                parts.append(f"Title: {result['title']}")
            if urls:
                parts.append(f"URLs ({len(urls)}): {', '.join(urls[:8])}")
            if forms:
                parts.append(f"Forms: {len(forms)}")
            return " | ".join(parts)
        if tool_name == "searchsploit":
            exploits = result.get("exploits", [])
            if exploits:
                lines = [f"Exploits ({len(exploits)}):"]
                for e in exploits[:5]:
                    lines.append(f"  {e.get('id', '?')}: {e.get('title', '')[:80]}")
                return "\n".join(lines)
            return "No exploits found"
        if tool_name == "nvd_query":
            keys = ["cve_id", "cvss_score", "cvss_severity", "description"]
            return json.dumps({k: result[k] for k in keys if k in result}, default=str)[:300]
        if tool_name == "nikto":
            findings = result.get("findings", [])
            return f"Nikto: {len(findings)} findings" if findings else "No nikto findings"
        if tool_name == "sqlmap":
            vuln = result.get("vulnerable", False)
            return f"SQLMap: {'VULNERABLE' if vuln else 'Not vulnerable'}"
        if tool_name == "hydra":
            found = result.get("credentials_found", False)
            return f"Hydra: {'Credentials found!' if found else 'No credentials found'}"
        if tool_name == "metasploit":
            success = result.get("exploit_success", False)
            return f"Metasploit: {'Exploit succeeded' if success else 'Exploit failed'}"
        if tool_name == "nmap_vuln":
            vulns = result.get("vulnerabilities", [])
            return f"NSE vulns: {len(vulns)} findings" if vulns else "No NSE vulnerabilities"
        if not result.get("success", True):
            err = result.get("error", "") or result.get("stderr", "")
            return f"{tool_name} failed: {err[:200]}"
        return json.dumps(result, default=str)[:500]

    def _execute_tool(self, phase: str, tool_name: str, args: dict) -> dict:
        # Check for pre-validation errors from _inject_default_args
        if isinstance(args, dict) and args.get("_validated") is False:
            return {"success": False, "error": args.get("error", "Target validation failed")}
        
        tools = TOOL_REGISTRY.get(phase, {})
        tool_info = tools.get(tool_name)
        if not tool_info:
            available = ", ".join(sorted(tools.keys()))
            return {"success": False, "error": f"Unknown tool: {tool_name}. Available: {available}"}
        try:
            result = tool_info["fn"](**args)
            if self.config.verbose:
                console.print(Panel(
                    json.dumps(result, indent=2, default=str)[:1000],
                    title=f"[bold]{tool_name} result[/]"
                ))
            return result
        except TypeError as e:
            return {"success": False, "error": f"Invalid arguments for {tool_name}: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _display_tool_result(self, tool_name: str, result: dict):
        if tool_name == "nmap":
            open_ports = [p for p in result.get("ports", []) if p.get("state") == "open"]
            if open_ports:
                t = Table(title=f"Open Ports ({len(open_ports)})")
                t.add_column("Port", style="cyan")
                t.add_column("Protocol", style="green")
                t.add_column("Service", style="yellow")
                t.add_column("Version", style="white")
                for p in open_ports[:25]:
                    t.add_row(p.get("port", "?"), p.get("protocol", "tcp"), p.get("service", "?"), p.get("version", "") or "")
                console.print(t)
        elif tool_name == "searchsploit":
            exploits = result.get("exploits", [])
            if exploits:
                t = Table(title=f"Exploits Found ({len(exploits)})")
                t.add_column("ID", style="cyan")
                t.add_column("Title", style="white")
                for e in exploits[:10]:
                    t.add_row(e.get("id", "?") or "?", (e.get("title", "") or "")[:80])
                console.print(t)
        elif tool_name == "nvd_query":
            if result.get("cve_id"):
                t = Table(title="CVE Details", show_header=False, box=None)
                t.add_column("Field", style="cyan")
                t.add_column("Value", style="white")
                for k in ["cve_id", "cvss_score", "cvss_severity", "description"]:
                    if k in result:
                        t.add_row(k.replace("_", " ").title(), str(result[k])[:150])
                console.print(t)
        elif tool_name == "nikto":
            findings = result.get("findings", [])
            if findings:
                t = Table(title=f"Nikto Findings ({len(findings)})")
                t.add_column("Finding", style="yellow")
                for f in findings[:10]:
                    t.add_row(str(f)[:100])
                console.print(t)
        elif tool_name == "web_crawl":
            urls = result.get("urls", [])
            forms = result.get("forms", [])
            if urls or forms:
                console.print(f"[bold]Web crawl:[/] {len(urls)} URLs, {len(forms)} forms")
        elif tool_name == "ffuf":
            paths = result.get("paths", [])
            if paths:
                t = Table(title=f"ffuf Found ({len(paths)})")
                t.add_column("Path", style="cyan")
                for p in paths[:15]:
                    t.add_row(p.get("path", "?"))
                console.print(t)
        elif tool_name == "nmap_vuln":
            vulns = result.get("vulnerabilities", [])
            if vulns:
                t = Table(title=f"NSE Vulnerabilities ({len(vulns)})")
                t.add_column("Script", style="yellow")
                t.add_column("Output", style="white")
                for v in vulns[:10]:
                    t.add_row(v.get("id", "?"), v.get("output", "")[:80])
                console.print(t)

    def _validate_target(self, target: str, tool_name: str) -> str:
        """Validate that an LLM-provided target is within scope of the original target."""
        try:
            parsed = Target(target)
        except ValueError as e:
            raise ValueError(f"{tool_name}: invalid target format: {e}")
        
        original = self.target_obj
        
        # If both are IPs, must match exactly
        if parsed.is_ip and original.is_ip:
            if parsed.ip != original.ip:
                raise ValueError(
                    f"{tool_name}: target IP {parsed.ip} outside scope (allowed: {original.ip})"
                )
            return target
        
        # If both are domains, allow exact match or subdomain of original
        if parsed.domain and original.domain:
            if parsed.domain == original.domain:
                return target
            if parsed.domain.endswith("." + original.domain):
                return target
            raise ValueError(
                f"{tool_name}: target domain {parsed.domain} outside scope "
                f"(allowed: {original.domain} and subdomains)"
            )
        
        # Mixed IP/domain - reject to be safe
        raise ValueError(
            f"{tool_name}: target type mismatch with original scope"
        )

    def _inject_default_args(self, tool_name: str, args: dict) -> dict:
        target_tools = {"nmap", "whatweb", "gobuster", "ffuf", "whois", "httpx", "web_crawl", "nikto", "sqlmap", "nmap_vuln", "hydra"}
        if tool_name in target_tools:
            raw = args.get("target", "")
            if not raw or re.search(r"<[^>]+>", raw) or raw.strip() in ("target", "ip", "host"):
                args["target"] = self.target_obj.target_for_tools()
            else:
                try:
                    args["target"] = self._validate_target(raw, tool_name)
                except ValueError as e:
                    return {"success": False, "error": str(e), "_validated": False}
        if tool_name == "dnsrecon":
            raw = args.get("domain", "")
            if not raw or re.search(r"<[^>]+>", raw):
                args["domain"] = self.target_obj.domain
            else:
                try:
                    args["domain"] = self._validate_target(raw, tool_name)
                except ValueError as e:
                    return {"success": False, "error": str(e), "_validated": False}
        if tool_name in {"whatweb", "httpx", "web_crawl"} and "verify" not in args:
            args["verify"] = getattr(self.config, "verify_ssl", True)
        return args

    def _auto_scout_report(self, phase_state) -> dict:
        report = {
            "target": self.target_obj.original,
            "open_ports": [],
            "services": [],
            "web_technologies": [],
            "subdomains": [],
            "whois": {},
            "dns_records": [],
            "directories_found": [],
            "crawled_urls": [],
            "crawled_forms": [],
            "nse_vulns": [],
            "summary": "",
        }
        seen_techs = set()
        for tc in phase_state.tool_results:
            t = tc["tool"]
            r = tc.get("result", {})
            if not r.get("success", True) and t != "whois":
                continue
            if t == "nmap":
                for p in r.get("ports", []):
                    if p.get("state") == "open":
                        report["open_ports"].append(p)
                        report["services"].append({
                            "port": p["port"],
                            "protocol": p.get("protocol", "tcp"),
                            "name": p.get("service", ""),
                            "version": p.get("version", ""),
                        })
            elif t == "whatweb":
                for tech in r.get("technologies", []):
                    n = tech.get("name", "")
                    if n and n not in seen_techs:
                        seen_techs.add(n)
                        report["web_technologies"].append(tech)
            elif t == "gobuster":
                report["directories_found"].extend(p["path"] for p in r.get("paths", []))
            elif t == "dnsrecon":
                report["dns_records"] = r.get("records", [])
            elif t == "ffuf":
                report["directories_found"].extend(p["path"] for p in r.get("paths", []))
            elif t == "web_crawl":
                report["crawled_urls"] = r.get("urls", [])
                report["crawled_forms"] = r.get("forms", [])
            elif t == "nmap_vuln":
                report["nse_vulns"] = r.get("vulnerabilities", [])
            elif t == "whois":
                report["whois"] = r.get("parsed", {})
        n_ports = len(report["open_ports"])
        n_tech = len(report["web_technologies"])
        n_dirs = len(report["directories_found"])
        n_urls = len(report["crawled_urls"])
        n_vulns = len(report["nse_vulns"])
        summary_parts = [f"{n_ports} open ports", f"{n_tech} technologies"]
        if n_dirs:
            summary_parts.append(f"{n_dirs} dirs")
        if n_urls:
            summary_parts.append(f"{n_urls} URLs")
        if n_vulns:
            summary_parts.append(f"{n_vulns} NSE vulns")
        report["summary"] = ", ".join(summary_parts)
        return report

    def _auto_planner_report(self, phase_state) -> dict:
        findings = []
        has_exploitable = False
        seen_titles: set[str] = set()
        seen_cves: set[str] = set()
        for tc in phase_state.tool_results:
            t = tc["tool"]
            r = tc.get("result", {})
            if not r.get("success", True):
                continue
            if t == "searchsploit":
                for e in r.get("exploits", []):
                    title = (e.get("title", "") or "").strip()
                    dedup_key = title[:80] or e.get("id", "")
                    if dedup_key in seen_titles:
                        continue
                    seen_titles.add(dedup_key)
                    findings.append({
                        "service": title[:50] if title else "?",
                        "cve_id": "",
                        "cvss_score": None,
                        "exploit_available": True,
                        "exploit_db_id": e.get("id", ""),
                        "summary": title[:100],
                    })
                    has_exploitable = True
            elif t == "nvd_query":
                cve = r.get("cve_id", "")
                if cve and cve not in seen_cves:
                    seen_cves.add(cve)
                    findings.append({
                        "service": "",
                        "cve_id": cve,
                        "cvss_score": r.get("cvss_score"),
                        "cvss_severity": r.get("cvss_severity"),
                        "exploit_available": False,
                        "summary": (r.get("description", "") or "")[:100],
                    })
            elif t == "nikto":
                for f_item in r.get("findings", []):
                    summary = str(f_item)[:100]
                    if summary in seen_titles:
                        continue
                    seen_titles.add(summary)
                    findings.append({"service": "web", "summary": summary})
        return {
            "findings": findings,
            "has_exploitable_vulnerabilities": has_exploitable,
            "summary": f"{len(findings)} issues found",
        }

    def _auto_raider_report(self, phase_state) -> dict:
        actions = []
        for tc in phase_state.tool_results:
            t = tc["tool"]
            r = tc.get("result", {})
            if t == "sqlmap":
                actions.append({
                    "vulnerability": "SQL Injection",
                    "method": "sqlmap",
                    "success": r.get("vulnerable", False),
                    "result": "Vulnerable" if r.get("vulnerable") else "Not vulnerable",
                })
            elif t == "hydra":
                actions.append({
                    "vulnerability": "Brute Force",
                    "method": "hydra",
                    "success": r.get("credentials_found", False),
                    "result": "Credentials found" if r.get("credentials_found") else "No credentials",
                })
            elif t == "metasploit":
                actions.append({
                    "vulnerability": "Remote Exploit",
                    "method": "metasploit",
                    "success": r.get("exploit_success", False),
                    "result": "Session gained" if r.get("exploit_success") else "Failed",
                })
            elif t == "nmap_vuln":
                n = len(r.get("vulnerabilities", []))
                actions.append({
                    "vulnerability": "NSE Scan",
                    "method": "nmap_vuln",
                    "success": n > 0,
                    "result": f"{n} vulns found",
                })
        return {"actions": actions, "summary": f"{len(actions)} exploits attempted"}

    def _auto_generate_report(self, phase: str, phase_state) -> dict:
        if phase == "scout":
            return self._auto_scout_report(phase_state)
        if phase == "planner":
            return self._auto_planner_report(phase_state)
        if phase == "raider":
            return self._auto_raider_report(phase_state)
        return {"summary": f"{phase} phase completed", "target": self.target_obj.original}

    def _trim_messages(self, messages: list[dict], max_pairs: int = 6) -> list[dict]:
        system = [m for m in messages if m.get("role") == "system"]
        exchanges = [m for m in messages if m.get("role") != "system"]
        total_rounds = len(exchanges) // 2
        if total_rounds <= max_pairs:
            return messages
        keep = exchanges[-(max_pairs * 2):]
        removed = total_rounds - max_pairs
        return system + [{"role": "user", "content": f"[{removed} previous round(s) summarized]"}] + keep

    def _run_phase(self, phase: str, system_prompt: str, initial_message: str, max_rounds: int) -> dict | None:
        self.state.phase = phase
        phase_state = PhaseState()

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": initial_message},
        ]

        bad = 0

        for round_num in range(max_rounds):
            phase_state.round = round_num + 1
            console.print(f"[cyan]▸ {phase.upper()}[/] round {round_num + 1}/{max_rounds}")

            messages = self._trim_messages(messages)

            try:
                response = self._ollama_chat(messages)
            except SystemExit:
                raise
            except Exception as e:
                console.print(f"[bold red]Error in {phase} phase:[/] {e}")
                break

            messages.append({"role": "assistant", "content": response})
            calls = self._parse_tool_calls(response)

            if not calls:
                bad += 1
                if bad >= 3:
                    console.print(f"[yellow]⚠ {phase.upper()}[/] stopped after {bad} bad responses")
                    break
                messages.append({
                    "role": "user",
                    "content": "Use: TOOL name\\nkey=value\\nOr: DONE",
                })
                continue

            bad = 0

            conclude_calls = [c for c in calls if c.get("tool") == "conclude"]
            tool_calls = [c for c in calls if c.get("tool") != "conclude"]

            if conclude_calls and not tool_calls:
                phase_state.completed = True
                console.print(f"[green]✓ {phase.upper()}[/] done in {round_num + 1} rounds")
                break

            if not tool_calls:
                bad += 1
                if bad >= 3:
                    console.print(f"[yellow]⚠ {phase.upper()}[/] stopped after {bad} bad responses")
                    break
                messages.append({
                    "role": "user",
                    "content": "Use: TOOL name\\nkey=value\\nOr: DONE",
                })
                continue

            for call in tool_calls:
                call["args"] = self._inject_default_args(call.get("tool", ""), call.get("args") or {})

            unique_calls = []
            seen_this_round = set()
            for call in tool_calls:
                tn = call.get("tool", "")
                ta = call.get("args", {})
                round_key = (tn, tuple(sorted(ta.items())))
                if round_key in seen_this_round:
                    continue
                is_dup = any(
                    prev["tool"] == tn and prev["args"] == ta
                    for prev in phase_state.tool_results
                )
                if not is_dup:
                    unique_calls.append(call)
                    seen_this_round.add(round_key)

            if not unique_calls:
                bad += 1
                if bad >= 3:
                    console.print(f"[yellow]⚠ {phase.upper()}[/] stopped after duplicates {bad} times")
                    break
                messages.append({
                    "role": "user",
                    "content": "All tools already ran. Try different tools or DONE.",
                })
                continue

            n = len(unique_calls)
            if n > 1:
                console.print(f"[bold]Running {n} tools in parallel...[/]")

            results = {}
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_workers) as pool:
                fut_map = {}
                for call in unique_calls:
                    tn = call["tool"]
                    ta = call["args"]
                    console.print(f"[yellow]⚡ {phase.upper()}[/] [bold]{tn}[/]({ta})")
                    future = pool.submit(self._execute_tool, phase, tn, ta)
                    fut_map[future] = (tn, ta)

                for future in concurrent.futures.as_completed(fut_map):
                    tn, ta = fut_map[future]
                    result = future.result()
                    elapsed_parts = []
                    results[(tn, repr(ta))] = result
                    phase_state.tool_results.append({"tool": tn, "args": ta, "result": result})
                    status = "[green]✔[/]" if result.get("success", True) else "[red]✘[/]"
                    console.print(f"  {status} [bold]{tn}[/] done")
                    self._display_tool_result(tn, result)

            all_failed = all(
                not results.get((c["tool"], repr(c["args"])), {}).get("success", True)
                for c in unique_calls
            )

            combined_parts = []
            for call in unique_calls:
                tn = call["tool"]
                ta = call["args"]
                result = results.get((tn, repr(ta)), {"success": False, "error": "Unknown"})
                condensed = self._condense_result(tn, result)
                combined_parts.append(f"[{tn}]\n{condensed}")

            combined_msg = "\n\n".join(combined_parts)

            if all_failed:
                bad += 1
                if bad >= 3:
                    console.print(f"[yellow]⚠ {phase.upper()}[/] stopped after {bad} rounds of failures")
                    break
                messages.append({
                    "role": "user",
                    "content": combined_msg + "\n\nAll tools failed. Try different tools or DONE.",
                })
            else:
                bad = 0
                suffix = "\n\nYou can list multiple tools (blank-line separated). Next:" if n > 1 else "\n\nNext (TOOL name or DONE):"
                messages.append({
                    "role": "user",
                    "content": combined_msg + suffix,
                })

            partial_report = self._auto_generate_report(phase, phase_state)
            setattr(self.state, f"{phase}_report", partial_report)

            if conclude_calls:
                phase_state.completed = True
                console.print(f"[green]✓ {phase.upper()}[/] done in {round_num + 1} rounds")
                break
        else:
            console.print(f"[yellow]⚠ {phase.upper()}[/] reached max rounds ({max_rounds})")

        phase_state.messages = messages
        report = self._auto_generate_report(phase, phase_state)

        setattr(self.state, f"{phase}_phase", phase_state)
        setattr(self.state, f"{phase}_report", report)
        return report

    def _has_vulnerabilities(self) -> bool:
        if not self.state.planner_report:
            return False
        return bool(self.state.planner_report.get("has_exploitable_vulnerabilities", False))

    def _scout_summary(self) -> str:
        r = self.state.scout_report or {}
        parts = [f"Target: {self.target_obj.original}"]
        if self.target_obj.ip:
            parts.append(f"IP: {self.target_obj.ip}")
        if self.target_obj.domain:
            parts.append(f"Domain: {self.target_obj.domain}")
        if r.get("open_ports"):
            parts.append(f"Open ports ({len(r['open_ports'])}):")
            for p in r["open_ports"][:5]:
                v = f" {p.get('version', '')}" if p.get("version") else ""
                parts.append(f"  {p.get('port', '?')}/{p.get('protocol', 'tcp')}  {p.get('service', '?')}{v}")
        if r.get("web_technologies"):
            names = ", ".join(t.get("name", "?") for t in r["web_technologies"][:5])
            parts.append(f"Web tech: {names}")
        if r.get("directories_found"):
            parts.append(f"Dirs: {', '.join(r['directories_found'][:5])}")
        return "\n".join(parts) if parts else "No findings."

    def _planner_summary(self) -> str:
        r = self.state.planner_report or {}
        findings = r.get("findings", [])
        if not findings:
            return f"Target: {self.target_obj.original}\nNo vulnerabilities."
        parts = [f"Target: {self.target_obj.original}", f"Vulnerabilities ({len(findings)}):"]
        for f in findings[:5]:
            cve = f.get("cve_id", "") or ""
            score = f.get("cvss_score", "") or ""
            parts.append(f"  {f.get('service', '?')} {cve} CVSS:{score}")
        return "\n".join(parts)

    def _phase_scout(self):
        parts = [f"Target: {self.target_obj.original}"]
        if self.target_obj.domain and self.target_obj.domain != self.target_obj.original:
            parts.append(f"Domain: {self.target_obj.domain}")
        if self.target_obj.ip:
            parts.append(f"IP: {self.target_obj.ip}")
        if self.target_obj.port:
            parts.append(f"Port: {self.target_obj.port}")
        initial = "\n".join(parts)
        console.print(Panel(f"[bold]Target: {self.target_obj.original}[/]\n[bold]Phase: SCOUT[/]", title="Cyber Sultanate System"))
        return self._run_phase("scout", SCOUT_SYSTEM_PROMPT, initial, self.config.scout_max_rounds)

    def _phase_planner(self):
        initial = f"Scout findings:\n{self._scout_summary()}"
        console.print(Panel("[bold]Phase: PLANNER[/]", title="Cyber Sultanate System"))
        return self._run_phase("planner", PLANNER_SYSTEM_PROMPT, initial, self.config.planner_max_rounds)

    def _phase_raider(self):
        initial = f"Vulnerabilities to exploit:\n{self._planner_summary()}"
        console.print(Panel("[bold]Phase: RAIDER[/]", title="Cyber Sultanate System"))
        return self._run_phase("raider", RAIDER_SYSTEM_PROMPT, initial, self.config.raider_max_rounds)

    def execute(self):
        console.print("[bold green]⚔ Cyber Sultanate System ⚔[/]")
        console.print(f"[dim]Model: {self.config.model} | Target: {self.target_obj.original}[/]\n")

        try:
            console.print(Rule(style="blue"))
            self._phase_scout()
        except Exception as e:
            console.print(f"[bold red]Scout phase failed:[/] {e}")
            self._generate_final_report()
            return

        try:
            console.print(Rule(style="green"))
            self._phase_planner()
        except Exception as e:
            console.print(f"[bold red]Planner phase failed:[/] {e}")
            self._generate_final_report()
            return

        if self.config.skip_raider:
            console.print("[yellow]Raider phase skipped (--skip-raider)[/]")
        elif self._has_vulnerabilities():
            n = len(self.state.planner_report.get("findings", []))
            console.print(f"[bold red]! {n} exploitable vulnerabilities found. Engaging Raider...[/]")
            try:
                console.print(Rule(style="red"))
                self._phase_raider()
            except Exception as e:
                console.print(f"[bold red]Raider phase failed:[/] {e}")
        else:
            console.print("[yellow]No exploitable vulnerabilities. Skipping Raider.[/]")

        self._generate_final_report()

    def _generate_final_report(self):
        report_text = generate_report(self.state)
        console.print("\n")
        console.print(Panel(report_text, title="[bold]Final Report[/]"))
        self.state.final_report = report_text
        return report_text

    def get_json_report(self):
        return generate_json_report(self.state)
