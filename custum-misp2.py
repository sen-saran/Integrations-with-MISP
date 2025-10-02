#!/var/ossec/framework/python/bin/python3
# custom-misp2.py - simplified integration with Wazuh and MISP

import sys
import os
import json
import re
import ipaddress
import requests
from socket import socket, AF_UNIX, SOCK_DGRAM
from requests.exceptions import ConnectionError

# --- Wazuh queue socket ---
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = f"{pwd}/queue/sockets/queue"

# --- MISP Config ---
MISP_URL = "https://172.17.1.227/attributes/restSearch"
MISP_KEY = "5FXYU6Hy2Db3iDsg5wTI35WlMN6424JpchSF38AO"
MISP_HEADERS = {
    "Content-Type": "application/json",
    "Authorization": MISP_KEY,
    "Accept": "application/json"
}

# --- Send alert back into Wazuh ---
def send_event(msg, agent=None):
    if not agent or agent.get("id") == "000":
        message = f"1:misp:{json.dumps(msg)}"
    else:
        agent_id = agent["id"]
        agent_name = agent.get("name", "unknown")
        agent_ip = agent.get("ip", "any")
        message = f"1:[{agent_id}] ({agent_name}) {agent_ip}->misp:{json.dumps(msg)}"
    with socket(AF_UNIX, SOCK_DGRAM) as sock:
        sock.connect(socket_addr)
        sock.send(message.encode())

# --- Extract IoC from alert ---
def extract_ioc(alert):
    try:
        groups = alert["rule"]["groups"]
        if "sysmon_event_22" in groups:
            return alert["data"]["win"]["eventdata"]["queryName"]
        elif "sysmon_event3" in groups:
            ip_val = alert["data"]["win"]["eventdata"]["destinationIp"]
            if ipaddress.ip_address(ip_val).is_global:
                return ip_val
        elif "sysmon_event1" in groups or "sysmon_event6" in groups or "sysmon_event7" in groups:
            return re.search(r"\b[A-Fa-f0-9]{64}\b", alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        elif "sysmon_event_15" in groups:
            return alert["data"]["win"]["eventdata"]["hash"]
        elif alert["rule"]["groups"][0] == "ossec" and alert["rule"]["groups"][2] == "syscheck_entry_added":
            return alert["syscheck"]["sha256_after"]
    except Exception:
        return None
    return None

# --- Query MISP ---
def query_misp(value):
    try:
        payload = {"value": value, "limit": 1}
        r = requests.post(MISP_URL, headers=MISP_HEADERS, json=payload, verify=False, timeout=10)
        if r.status_code == 200:
            return r.json()
        else:
            return {"error": f"MISP HTTP {r.status_code}"}
    except ConnectionError:
        return {"error": "Connection Error to MISP API"}

# --- Main ---
def main():
    if len(sys.argv) < 2:
        sys.exit(1)

    with open(sys.argv[1]) as f:
        alert = json.load(f)

    ioc = extract_ioc(alert)
    if not ioc:
        sys.exit(0)

    misp_resp = query_misp(ioc)

    if "error" in misp_resp:
        output = {"integration": "misp", "misp": {"error": misp_resp["error"]}}
        send_event(output, alert.get("agent"))
    else:
        attrs = misp_resp.get("response", {}).get("Attribute", [])
        if attrs:
            attr = attrs[0]
            output = {
                "integration": "misp",
                "misp": {
                    "event_id": attr.get("event_id"),
                    "category": attr.get("category"),
                    "value": attr.get("value"),
                    "type": attr.get("type"),
                },
                "rule_description": alert["rule"].get("description", "")
            }
            send_event(output, alert.get("agent"))

if __name__ == "__main__":
    main()
