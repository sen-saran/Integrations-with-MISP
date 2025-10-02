#!/var/ossec/framework/python/bin/python3
import sys, os, json, re, ipaddress, requests
from socket import socket, AF_UNIX, SOCK_DGRAM
from requests.exceptions import ConnectionError

# Wazuh queue socket
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = f"{pwd}/queue/sockets/queue"

# MISP config
MISP_BASE_URL = "https://172.17.1.227/attributes/restSearch/"
MISP_API_KEY = "5FXYU6Hy2Db3iDsg5wTI35WlMN6424JpchSF38AO"
MISP_HEADERS = {
    "Content-Type": "application/json",
    "Authorization": MISP_API_KEY,
    "Accept": "application/json"
}

def send_event(msg, agent=None):
    if not agent or agent.get("id") == "000":
        string = f'1:misp:{json.dumps(msg)}'
    else:
        string = f'1:[{agent["id"]}] ({agent["name"]}) {agent.get("ip","any")}->misp:{json.dumps(msg)}'
    with socket(AF_UNIX, SOCK_DGRAM) as sock:
        sock.connect(socket_addr)
        sock.send(string.encode())

# Read alert file
with open(sys.argv[1]) as f:
    alert = json.load(f)

alert_output = {}
groups = alert["rule"].get("groups", [])
event_source = groups[0] if len(groups) > 0 else ""
event_type   = groups[2] if len(groups) > 2 else ""

regex_sha256 = re.compile(r"\b[A-Fa-f0-9]{64}\b")
wazuh_event_param = None

try:
    if event_source == "windows":
        if event_type in ("sysmon_event1","sysmon_event6","sysmon_event7","sysmon_event_23","sysmon_event_24","sysmon_event_25"):
            hashes_str = alert["data"]["win"]["eventdata"].get("hashes","")
            m = regex_sha256.search(hashes_str)
            if m: wazuh_event_param = m.group(0)

        elif event_type == "sysmon_event_15":
            h = alert["data"]["win"]["eventdata"].get("hash","")
            m = regex_sha256.search(h)
            if m: wazuh_event_param = m.group(0)

        elif event_type == "sysmon_event3":
            if alert["data"]["win"]["eventdata"].get("destinationIsIpv6") == "false":
                dst_ip = alert["data"]["win"]["eventdata"].get("destinationIp")
                if dst_ip and ipaddress.ip_address(dst_ip).is_global:
                    wazuh_event_param = dst_ip

        elif event_type == "sysmon_event_22":
            wazuh_event_param = alert["data"]["win"]["eventdata"].get("queryName")

    elif event_source == "linux" and event_type == "sysmon_event3":
        if alert["data"]["eventdata"].get("destinationIsIpv6") == "false":
            dst_ip = alert["data"]["eventdata"].get("DestinationIp")
            if dst_ip and ipaddress.ip_address(dst_ip).is_global:
                wazuh_event_param = dst_ip

    elif event_source == "ossec" and event_type == "syscheck_entry_added":
        wazuh_event_param = alert["syscheck"].get("sha256_after")

except Exception as e:
    sys.exit(0)

if not wazuh_event_param:
    sys.exit(0)

# Query MISP
try:
    misp_api_response = requests.get(
        f"{MISP_BASE_URL}value:{wazuh_event_param}",
        headers=MISP_HEADERS,
        verify=False
    ).json()
except ConnectionError:
    alert_output["misp"] = {"error":"Connection Error to MISP API"}
    alert_output["integration"] = "misp"
    send_event(alert_output, alert.get("agent",{}))
    sys.exit(0)

attributes = misp_api_response.get("response",{}).get("Attribute", [])
if attributes:
    attr = attributes[0]
    alert_output["misp"] = {
        "event_id": attr["event_id"],
        "category": attr["category"],
        "value": attr["value"],
        "type": attr["type"],
        "source": {"description": alert["rule"].get("description","")}
    }
    alert_output["integration"] = "misp"
else:
    alert_output["misp"] = {"status":"no_match","value":wazuh_event_param}
    alert_output["integration"] = "misp"

send_event(alert_output, alert.get("agent",{}))
