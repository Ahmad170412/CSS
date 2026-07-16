import subprocess
import shutil


def _run(cmd, timeout=120):
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
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
