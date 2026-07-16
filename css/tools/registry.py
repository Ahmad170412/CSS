from . import scout_tools
from . import planner_tools
from . import raider_tools

SCOUT_TOOLS = {
    "nmap": {"fn": scout_tools.nmap, "params": {"target": "", "flags": ""}},
    "whatweb": {"fn": scout_tools.whatweb, "params": {"target": ""}},
    "gobuster": {"fn": scout_tools.gobuster, "params": {"target": "", "wordlist": "/usr/share/wordlists/dirb/common.txt", "extensions": ""}},
    "ffuf": {"fn": scout_tools.ffuf, "params": {"target": "", "wordlist": "", "extensions": ""}},
    "dnsrecon": {"fn": scout_tools.dnsrecon, "params": {"domain": "", "type": "std"}},
    "whois": {"fn": scout_tools.whois, "params": {"target": ""}},
    "httpx": {"fn": scout_tools.http_probe, "params": {"target": "", "flags": ""}},
    "shodan": {"fn": scout_tools.shodan, "params": {"query": ""}},
    "web_crawl": {"fn": scout_tools.web_crawl, "params": {"target": "", "depth": "1", "verify": True}},
    "nmap_vuln": {"fn": raider_tools.nmap_vuln, "params": {"target": "", "script": "vuln"}},
}

PLANNER_TOOLS = {
    "searchsploit": {"fn": planner_tools.searchsploit, "params": {"query": ""}},
    "nvd_query": {"fn": planner_tools.nvd_query, "params": {"cve_id": ""}},
    "nikto": {"fn": planner_tools.nikto, "params": {"target": ""}},
}

RAIDER_TOOLS = {
    "sqlmap": {"fn": raider_tools.sqlmap, "params": {"target": "", "flags": "--batch --level=1 --risk=1"}},
    "hydra": {"fn": raider_tools.hydra, "params": {"target": "", "service": "", "username": "", "password": ""}},
    "metasploit": {"fn": raider_tools.metasploit, "params": {"module": "", "options": "", "payload": ""}},
    "nmap_vuln": {"fn": raider_tools.nmap_vuln, "params": {"target": "", "script": "vuln"}},
}

TOOL_REGISTRY = {
    "scout": SCOUT_TOOLS,
    "planner": PLANNER_TOOLS,
    "raider": RAIDER_TOOLS,
}
