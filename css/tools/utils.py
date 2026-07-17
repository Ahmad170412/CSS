import os
import subprocess
import shutil
from urllib.parse import urlparse


_proxy_env: dict[str, str] = {}
_no_proxy_hosts: set[str] = set()


def set_proxy_env(env: dict[str, str]):
    _proxy_env.clear()
    _proxy_env.update(env)
    _no_proxy_hosts.clear()
    no_proxy = env.get("NO_PROXY", "")
    for h in no_proxy.split(","):
        h = h.strip()
        if h:
            _no_proxy_hosts.add(h)


def get_proxy_url(target_url: str = "") -> str:
    if not _proxy_env:
        return ""
    if target_url:
        parsed = urlparse(target_url)
        host = parsed.hostname or ""
        if host in _no_proxy_hosts:
            return ""
        for np in _no_proxy_hosts:
            if np.startswith(".") and host.endswith(np[1:]):
                return ""
            if host == np or host.endswith("." + np):
                return ""
    return _proxy_env.get("HTTPS_PROXY") or _proxy_env.get("HTTP_PROXY") or _proxy_env.get("ALL_PROXY", "")


def _run(cmd, timeout=120):
    try:
        env = os.environ.copy()
        env.update(_proxy_env)
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, env=env
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout[:100000],
            "stderr": result.stderr[:10000],
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "stdout": "", "stderr": "Command timed out", "returncode": -1}
    except FileNotFoundError:
        return {"success": False, "stdout": "", "stderr": f"Command not found: {cmd[0]}", "returncode": -1}
    except Exception as e:
        return {"success": False, "stdout": "", "stderr": str(e), "returncode": -1}


def _check_tool(name: str) -> bool:
    return shutil.which(name) is not None
