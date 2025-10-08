[<img src="../Images/MISP.png" align="right" width="200" height="200" />](https://www.dms.go.th)

# MISP Integration [![Awesome](https://img.shields.io/badge/SOCFortress-Worlds%20First%20Free%20Cloud%20SOC-orange)](https://www.dms.go.th)
> Interacting With MISP’s API to detect IoCs within our Wazuh Alerts.
>> ⚙️ Threat Intelligence กับ Wazuh และ MISP
>> ตัวอย่าง Flow
>> 🟩 Sysmon → 🟦 Wazuh → 🟥 MISP → 🟧 Alert on Dashboard
>> # 🧠 Threat Intelligence Flow — Wazuh + MISP + Sysmon

## 📁 องค์ประกอบระบบ

| องค์ประกอบ | ไฟล์ | หน้าที่ |
|--------------|------------------------------|----------------------------------------------|
| **MISP Ruleset** | `/var/ossec/etc/rules/misp.xml` | จับ IoC จาก MISP และสร้างกลุ่ม **misp_alert** |
| **Local Rules** | `/var/ossec/etc/rules/local_rules.xml` | เพิ่ม mapping กับ Sysmon (Event 1, 3, 22) |
| **Integration Script** | `/var/ossec/integrations/custom-misp.py` | ติดต่อกับ MISP REST API (`/attributes/restSearch`) |
| **Main Config** | `/var/ossec/etc/ossec.conf` | เรียกใช้ integration ผ่าน block `<integration name="custom-misp">` |
| **Alert Output** | `/var/ossec/logs/alerts/alerts.json` | บันทึก Alert สุดท้ายที่ตรวจจับได้ |

---

## 🧾 Troubleshooting Checklist

| อาการ | วิธีตรวจสอบ | วิธีแก้ |
|--------|---------------|----------|
| ไม่เจอ IoC | `tail -f /var/ossec/logs/misp-debug.log` | ตรวจสอบ API key / Attribute / IP ของ MISP |
| ไม่มี Alert | `/var/ossec/bin/wazuh-logtest` | ตรวจดูว่า group **misp_alert** ถูกตั้งค่าใน rule หรือไม่ |
| Rule ไม่โหลด | `grep loaded /var/ossec/logs/ossec.log` | ตรวจ path `/etc/rules/misp.xml` ว่าถูกต้องหรือไม่ |
| Sysmon Event ไม่เข้า | ตรวจ log agent ที่ `C:\Program Files (x86)\ossec-agent\ossec.log` | ตรวจ config `<localfile>` ของ EventChannel |

---

## ⚙️ Threat Intelligence Flow

| ลำดับ | ขั้นตอน | รายละเอียด |
|-------|----------|-------------|
| 1️⃣ | Sysmon Event (จาก Windows Agent) | เครื่อง Windows ส่ง Event เช่น DNS Query, Process Creation |
| 2️⃣ | Wazuh Manager รับ Log | Log ถูกส่งมาที่ `/var/ossec/logs/ossec.log` |
| 3️⃣ | Integration Trigger | บล็อก `<integration name="custom-misp">` ถูกเรียกใช้ |
| 4️⃣ | custom-misp.py ทำงาน | อ่าน log และดึงค่า IoC (เช่น domain, hash, IP) |
| 5️⃣ | Query MISP API | ส่ง HTTP POST ไปยัง `/attributes/restSearch` |
| 6️⃣ | MISP Response | หากเจอ IoC ตรงกัน จะได้ค่า **value**, **category**, **event_id** กลับมา |
| 7️⃣ | ส่งข้อมูลกลับเข้า Wazuh Queue | สคริปต์ส่ง JSON เช่น `{"integration":"misp","misp":{"value":"gamma.app"}}` |
| 8️⃣ | Ruleset ทำงาน | Rule IDs (100620 → 100622 → 920100 → 920101) จับและแปลงเป็น Alert |
| 9️⃣ | Alert แสดงผล | แสดงใน Dashboard, Telegram หรือส่งต่อไป SIEM |

---

## 💡 Threat Intel ช่วย Wazuh อย่างไร

| ด้าน | ประโยชน์ |
|------|-----------|
| 🧱 **Prevention** | รู้ล่วงหน้า IP/Domain อันตราย — block ก่อนโดนจริง |
| 🕵️ **Detection** | Wazuh ตรวจพบกิจกรรมที่ตรงกับ IoC จาก MISP |
| ⚡ **Response** | แจ้งเตือนผ่าน Telegram / isolate เครื่องอัตโนมัติ |
| 📊 **Visibility** | เห็นภาพรวมภัยที่ตรวจพบและแหล่งที่มา |

---

## 🧾 ตัวอย่างข้อมูล Threat Intel (จาก MISP)

| Category | Type | Example | หมายเหตุ |
|-----------|------|----------|------------|
| Network Activity | domain | gamma.app | โดเมนอันตราย |
| Payload Delivery | md5 | a9d0f2b3... | Hash ของไฟล์มัลแวร์ |
| External Analysis | url | http://bad-actor.com/phish | Phishing URL |
| Payload Installation | sha256 | ccd069e20c59... | ไฟล์ติดไวรัส |
| Attribution | threat-actor | APT28 | กลุ่มผู้โจมตี |

---

## 🔄 Data Flow Diagram

```
Sysmon Event (จาก Windows Agent)
        ↓
Wazuh Manager รับ log
        ↓
<integration name="custom-misp"> ใน ossec.conf ถูกเรียก
        ↓
/var/ossec/integrations/custom-misp.py รันขึ้น
        ↓
custom-misp.py ใช้ MISP REST API → /attributes/restSearch
        ↓
ถ้าเจอ IoC ที่ตรงกัน → ส่ง JSON กลับเข้า Wazuh queue
        ↓
ruleset (100620 / 100621 / 100622 / 920100 / 920101) ทำงาน
        ↓
Wazuh สร้าง Alert และส่งต่อให้ Dashboard / Telegram / SIEM อื่น ๆ
>>
[ Windows Agent ]
     ↓
 Sysmon Event (DNS Query)
     ↓
[ Wazuh Manager ]
     ↓
 custom-misp.py → Query IoC (เช่น domain: gamma.app)
     ↓
 MISP → ตรวจสอบว่าตรงกับ IoC ที่มีหรือไม่
     ↓
 หากเจอ: Wazuh rule 100622 → ตั้ง group "misp_alert"
     ↓
 Wazuh rule 920100 → "MISP IoC match detected"

                │
                ▼
        ┌───────────────┐
        │ Wazuh Manager │
        └───────────────┘
                │
                ▼
   [ Decoder windows_eventchannel ]
                │
                ▼
        ┌───────────────────────────┐
        │ Rule 61650 (Sysmon Event) │
        └───────────────────────────┘
                │
                ▼
        [ Integration: custom-misp2.py ]
                │
                ├── Extract IoC (gamma.app)
                ├── Query MISP API (/attributes/restSearch)
                └── ถ้า HIT → ส่ง JSON:
                     {"integration":"misp",
                      "misp":{"value":"gamma.app", ...},
                      "rule":{"groups":["misp_alert"]}}
                │
                ▼
        ┌───────────────────────┐
        │ Wazuh JSON Decoder    │
        └───────────────────────┘
                │
                ▼
        ┌─────────────────────────────┐
        │ local_rules.xml             │
        │ Rule 920100 (if_group=misp_alert)
        └─────────────────────────────┘
                │
                ▼
        [ Alert generated:  
          "MISP IoC match detected: gamma.app 
           [Category: Network activity]" ]

จากนั้นเชื่อมต่อกับ MISP และ Telegram Alert Pipeline
Sysmon (Event 22)
   ↓
Wazuh Agent
   ↓
Wazuh Manager
   ↓
custom-misp.py → MISP REST API → match IoC
   ↓
Rule 920100 → Trigger alert
   ↓
custom-telegram.py → ส่ง Telegram Alert
```

<table>
  <tr>
   	<td>องค์ประกอบ</td>
   	<td>หน้าที่</td>
 	<td>การทำงาน</td>
  </tr>
  <tr>
   <td>MISP (Malware Information Sharing Platform)</td>
   <td>แหล่งจัดเก็บและแชร์ Threat Intelligence เช่น IP, Domain, Hash, Email, URL ฯลฯ</td>
   <td>ใช้ REST API /attributes/restSearch และ Key สำหรับ Authentication</td> 	  
  </tr>	  
	<tr>
   <td>Wazuh (SIEM/EDR)</td>
   <td>เครื่องมือตรวจจับเหตุการณ์ (Sysmon, Agent logs, OSSEC) แล้วนำมาวิเคราะห์เทียบกับ IoC จาก MISP</td>
	<td>ใช้ Integration (custom-misp.py) เชื่อมระหว่างเหตุการณ์ และ Ruleset แปลงผลการตรวจจับเป็น Alert พร้อม</td>
	</tr>
  <table>


## Intro

Wazuh manager integration with MISP for Threat Intel.


## Requirements.



* MISP instance up and running.
* MISP API AuthKey (Read-only account).
* Root CA used to sign MISP’s digital certificate. 


## Wazuh capability.

Custom integration.


## Event types / Rule groups to trigger MISP API calls.


<table>
  <tr>
   <td>Event Type
   </td>
   <td>Metadata (Win / Linux)
   </td>
   <td>Rationale
   </td>
  </tr>
  <tr>
   <td>Sysmon event 1
   </td>
   <td>win.eventdata.hashes
   </td>
   <td>Check existing IoCs in  process image file hash 
   </td>
  </tr>
  <tr>
   <td>Sysmon event 3
   </td>
   <td>win.eventdata.destinationIp / 
<p>
eventdata.destinationIp
   </td>
   <td>Check existing IoCs in  destination IP (if public IPv4)
   </td>
  </tr>
  <tr>
   <td>Sysmon event 6
   </td>
   <td>win.eventdata.hashes
   </td>
   <td>Check existing IoCs in  loaded driver file hash 
   </td>
  </tr>
  <tr>
   <td>Sysmon event 7
   </td>
   <td>win.eventdata.hashes
   </td>
   <td>Check existing IoCs in  loaded DLL file hash 
   </td>
  </tr>
  <tr>
   <td>Sysmon event 15
   </td>
   <td>win.eventdata.hashes
   </td>
   <td>Check existing IoCs in  downloaded file hash 
   </td>
  </tr>
  <tr>
   <td>Sysmon event 22
   </td>
   <td>win.eventdata.queryName
   </td>
   <td>Check existing IoCs in  queried hostname
   </td>
  </tr>
  <tr>
   <td>Wazuh Syscheck (Files)
   </td>
   <td>syscheck.sha256_after
   </td>
   <td>Check existing IoCs in  files added/modified/removed (file hash)
   </td>
  </tr>
</table>



## Wazuh Manager - Custom Integration

File “custom-misp”:nano /var/ossec/integrations/custom-misp


```
#!/bin/sh
WPYTHON_BIN="framework/python/bin/python3"

SCRIPT_PATH_NAME="$0"

DIR_NAME="$(cd $(dirname ${SCRIPT_PATH_NAME}); pwd -P)"
SCRIPT_NAME="$(basename ${SCRIPT_PATH_NAME})"

case ${DIR_NAME} in
    */active-response/bin | */wodles*)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/../..; pwd)"
        fi

        PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
    */bin)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi

        PYTHON_SCRIPT="${WAZUH_PATH}/framework/scripts/${SCRIPT_NAME}.py"
    ;;
     */integrations)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi

        PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
esac


${WAZUH_PATH}/${WPYTHON_BIN} ${PYTHON_SCRIPT} "$@"
```


File “custom-misp.py”:nano /var/ossec/integrations/custom-misp.py


```
#!/usr/bin/env python
# SOCFortress
# https://www.socfortress.co
# info@socfortress.co
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import date, datetime, timedelta
import time
import requests
from requests.exceptions import ConnectionError
import json
import ipaddress
import hashlib
import re
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = '{0}/queue/sockets/queue'.format(pwd)
def send_event(msg, agent = None):
    if not agent or agent["id"] == "000":
        string = '1:misp:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->misp:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()
false = False
# Read configuration parameters
alert_file = open(sys.argv[1])
# Read the alert file
alert = json.loads(alert_file.read())
alert_file.close()
# New Alert Output if MISP Alert or Error calling the API
alert_output = {}
# MISP Server Base URL
misp_base_url = "https://your_misp_instance/attributes/restSearch/"
# MISP Server API AUTH KEY
misp_api_auth_key = "your_api_authkey"
# API - HTTP Headers
misp_apicall_headers = {"Content-Type":"application/json", "Authorization":f"{misp_api_auth_key}", "Accept":"application/json"}
## Extract Sysmon for Windows/Sysmon for Linux and Sysmon Event ID
event_source = alert["rule"]["groups"][0]
event_type = alert["rule"]["groups"][2]
## Regex Pattern used based on SHA256 lenght (64 characters)
regex_file_hash = re.compile('\w{64}')
if event_source == 'windows':
    if event_type == 'sysmon_event1':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event3' and alert["data"]["win"]["eventdata"]["destinationIsIpv6"] == 'false':
        try:
            dst_ip = alert["data"]["win"]["eventdata"]["destinationIp"]
            if ipaddress.ip_address(dst_ip).is_global:
                wazuh_event_param = dst_ip
            else:
                sys.exit()
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event3' and alert_output["data"]["win"]["eventdata"]["destinationIsIpv6"] == 'true':
        sys.exit()
    elif event_type == 'sysmon_event6':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event7':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event_15':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event_22':
        try:
            wazuh_event_param = alert["data"]["win"]["eventdata"]["queryName"]
        except IndexError:
            sys.exit()
    else:
        sys.exit()
    misp_search_value = "value:"f"{wazuh_event_param}"
    misp_search_url = ''.join([misp_base_url, misp_search_value])
    try:
        misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify='/yourpath/to/rootCA.pem')
    except ConnectionError:
        alert_output["misp"] = {}
        alert_output["integration"] = "misp"
        alert_output["misp"]["error"] = 'Connection Error to MISP API'
        send_event(alert_output, alert["agent"])
    else:
        misp_api_response = misp_api_response.json()
    # Check if response includes Attributes (IoCs)
        if (misp_api_response["response"]["Attribute"]):
    # Generate Alert Output from MISP Response
            alert_output["misp"] = {}
            alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
            alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
            alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
            alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
            send_event(alert_output, alert["agent"])
elif event_source == 'linux':
    if event_type == 'sysmon_event3' and alert["data"]["eventdata"]["destinationIsIpv6"] == 'false':
        try:
            dst_ip = alert["data"]["eventdata"]["DestinationIp"]
            if ipaddress.ip_address(dst_ip).is_global:
                wazuh_event_param = dst_ip
                misp_search_value = "value:"f"{wazuh_event_param}"
                misp_search_url = ''.join([misp_base_url, misp_search_value])
                try:
                    misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify='/yourpath/to/rootCA.pem')
                except ConnectionError:
                    alert_output["misp"] = {}
                    alert_output["integration"] = "misp"
                    alert_output["misp"]["error"] = 'Connection Error to MISP API'
                    send_event(alert_output, alert["agent"])
                else:
                    misp_api_response = misp_api_response.json()
        # Check if response includes Attributes (IoCs)
                    if (misp_api_response["response"]["Attribute"]):
                # Generate Alert Output from MISP Response
                        alert_output["misp"] = {}
                        alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
                        alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
                        alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
                        alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
                        send_event(alert_output, alert["agent"])
            else:
                sys.exit()
        except IndexError:
            sys.exit()
    else:
        sys.exit()
elif event_source == 'ossec' and event_type == "syscheck_entry_added":
    try:
        wazuh_event_param = alert["syscheck"]["sha256_after"]
    except IndexError:
        sys.exit()
    misp_search_value = "value:"f"{wazuh_event_param}"
    misp_search_url = ''.join([misp_base_url, misp_search_value])
    try:
        misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify='/yourpath/to/rootCA.pem')
    except ConnectionError:
        alert_output["misp"] = {}
        alert_output["integration"] = "misp"
        alert_output["misp"]["error"] = 'Connection Error to MISP API'
        send_event(alert_output, alert["agent"])
    else:
        misp_api_response = misp_api_response.json()
    # Check if response includes Attributes (IoCs)
        if (misp_api_response["response"]["Attribute"]):
    # Generate Alert Output from MISP Response
            alert_output["misp"] = {}
            alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
            alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
            alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
            alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
            send_event(alert_output, alert["agent"])
else:
    sys.exit()
```



```
# ls -lrt /var/ossec/integrations/
total 64
-rwxr-x--- 1 root ossec  844 Jan 11 04:12 custom-misp
-rwxr-x--- 1 root ossec 8646 Jan 13 21:28 custom-misp.py
```

Replace:

* “your_misp_instance”
* “your_api_authkey”
* “/yourpath/to/rootCA.pem”

With right values for your MISP instance. The root CA used to sign the digital certificate for the MISP instance needs to be placed in the Wazuh manager and referenced in the python script with the “verify” option in the request.

Wazuh manager config for this integration </global> Paste : nano /var/ossec/etc/ossec.conf

```
<integration>
 <name>custom-misp</name>  
 <group>sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event_15,sysmon_event_22,syscheck</group>
 <alert_format>json</alert_format>
</integration>
```

Detection rules: nano /var/ossec/etc/rules/100620-misp.xml

```
<group name="misp,">
 <rule id="100620" level="10">
    <field name="integration">misp</field>
    <description>MISP Events</description>
    <options>no_full_log</options>
  </rule>
<rule id="100621" level="5">
    <if_sid>100620</if_sid>
    <field name="misp.error">\.+</field>
    <description>MISP - Error connecting to API</description>
    <options>no_full_log</options>
    <group>misp_error,</group>
  </rule>
<rule id="100622" level="12">
    <field name="misp.category">\.+</field>
    <description>MISP - IoC found in Threat Intel - Category: $(misp.category), Attribute: $(misp.value)</description>
    <options>no_full_log</options>
    <group>misp_alert,</group>
  </rule>
</group>
```
Detection rules: nano /var/ossec/etc/rules/misp.xml
```
<group name="misp,sysmon,windows,">
  <!-- Define base group for misp_alert -->
  <rule id="920000" level="0">
    <field name="integration">^misp$</field>
    <description>Base group for MISP alerts</description>
    <options>no_full_log</options>
    <group>misp_alert</group>
  </rule>
  <!-- Custom MISP IoC detection -->
  <rule id="920100" level="12">
    <if_group>misp_alert</if_group>
    <description>MISP IoC match detected: $(misp.value) [Category: $(misp.category)]</description>
    <options>no_full_log</options>
    <group>misp,alert,sysmon,misp_alert</group>
  </rule>
  <!-- Sysmon Event 22 mapping -->
  <rule id="920101" level="12">
    <if_group>misp_alert</if_group>
    <field name="misp.value">.+</field>
    <description>MISP IoC match detected: $(misp.value) in DNS query $(win.eventdata.queryName)</description>
    <options>no_full_log</options>
    <group>misp_alert,sysmon,windows</group>
  </rule>
</group>
```

เปลี่ยน Permission ของไฟล์ :
```
sudo chown root:wazuh /var/ossec/etc/rules/*
sudo chmod 750 /var/ossec/etc/rules/*
```

## ขั้นตอนทดสอบการทำงานของ Threat Intelligence (Wazuh + MISP)
# ขั้นตอนที่ 1: เตรียม MISP
1. เข้าระบบ MISP Web UI → ไปที่ Events → Add Event
2. สร้าง Event ใหม่ เช่น
```
Event Name: bing.com
Threat Level: Medium
Distribution: Your Organization Only
```
3. เพิ่ม Attribute (IoC) ตัวอย่าง:
```
Type: domain
Category: Network activity
Value: gamma.app
```
4. ตรวจสอบว่า Event ถูก “Published” แล้ว (คลิกปุ่ม Publish)
   
# ขั้นตอนที่ 2: ตรวจสอบการเชื่อมต่อ MISP API
บน Wazuh Manager:
```
curl -k -X POST "https://172.17.1.227/attributes/restSearch" \
  -H "Authorization: 5FXYU6Hy2Db3iDsg5wTI35WlMN6424JpchSF38AO" \
  -H "Content-Type: application/json" \
  -d '{"value": "gamma.app", "limit": 1}'
```
OUTPUT แปลว่า MISP พร้อมใช้งานแล้ว:
```
{"response": {"Attribute": [{"category": "Network activity", "value": "gamma.app"}]}}
```

# ขั้นตอนที่ 3: ตรวจสอบ Integration กับ Wazuh
บน Wazuh Manager:
```
sudo systemctl restart wazuh-manager
```
ทดสอบ Logtest:
```
sudo /var/ossec/bin/wazuh-logtest
```
วาง JSON เพื่อทดสอบ:
```
{"integration":"misp","misp":{"event_id":"5","category":"Network activity","value":"gamma.app","type":"domain"}}
```
OUTPUT แปลว่า MISP IoC Detected:
```
Starting wazuh-logtest v4.12.0
Type one log per line

{"integration":"misp","misp":{"event_id":"5","category":"Network activity","value":"gamma.app","type":"domain"}}

** Wazuh-Logtest: WARNING: (7613): Rule ID '61650' does not exist but 'overwrite' is set to 'yes'. Still, the rule will be loaded.

**Phase 1: Completed pre-decoding.

**Phase 2: Completed decoding.
        name: 'json'
        integration: 'misp'
        misp.category: 'Network activity'
        misp.event_id: '5'
        misp.type: 'domain'
        misp.value: 'gamma.app'

**Phase 3: Completed filtering (rules).
        id: '920100'
        level: '12'
        description: 'MISP IoC match detected: gamma.app [Category: Network activity]'
        groups: '['misp', 'sysmon', 'windows', 'misp', 'alert', 'sysmon', 'misp_alert']'
        firedtimes: '1'
        mail: 'True'
**Alert to be generated.
```
# ขั้นตอนที่ 4: ตรวจสอบว่า Sysmon ติดตั้งแล้วหรือยัง ที่ติดตั้ง Agent
เปิด PowerShell (Run as Administrator) แล้วพิมพ์ :
```
Get-Service wazuh
```
Output: 
```
PS C:\Windows\system32> Get-Service wazuh

Status   Name               DisplayName
------   ----               -----------
Running  WazuhSvc           wazuh
```
เปิด Notepad (Run as Administrator) ไปที่ C:\Program Files (x86)\ossec-agent\ossec.conf ตรวจสอบว่ามี Config นี้:
```
<!-- Sysmon Event Channel -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
หรือ ossec.log ตรวจสอบว่ามี Connected :
```
2025/10/06 13:17:59 wazuh-agent: INFO: (4102): Connected to the server ([172.17.1.225]:1514/tcp).
2025/10/06 13:17:59 wazuh-agent: INFO: Server responded. Releasing lock.
2025/10/06 13:18:02 wazuh-agent: INFO: Agent is now online. Process unlocked, continuing...
2025/10/06 14:10:27 wazuh-modulesd:syscollector: INFO: Starting evaluation.
2025/10/06 14:11:04 wazuh-modulesd:syscollector: INFO: Evaluation finished.
```

# ขั้นตอนที่ 5: ทดสอบจาก Windows Agent
บนเครื่อง Windows :
```
ping gamma.app
```
กลับมาที่ Wazuh Manager ดูผล Alert : 
```
tail -f /var/ossec/logs/misp-debug.log | grep gamma.app
```
Output: 
```
wazuh@wazuh:/var/ossec/etc/rules$ tail -f /var/ossec/logs/misp-debug.log | grep gamma.app
2025-09-30 12:30:51,190 [DEBUG] Extracted IoC value = gamma.app
2025-09-30 12:30:51,190 [DEBUG] POST https://172.17.1.227/attributes/restSearch with payload={'value': 'gamma.app', 'limit': 1}
2025-09-30 12:30:51,288 [DEBUG] Raw response text={"response": {"Attribute": [{"id":"9","event_id":"5","object_id":"0","object_relation":null,"category":"Network activity","type":"domain","to_ids":false,"uuid":"05a7f8b1-646c-4c70-a989-416b55553e34","timestamp":"1759221781","distribution":"5","sharing_group_id":"0","comment":"","deleted":false,"disable_correlation":false,"first_seen":null,"last_seen":null,"value":"gamma.app","Event":{"id":"5","info":"bing.com","org_id":"1","orgc_id":"1","uuid":"230513a0-c1d9-47ea-8b0f-80e4b1e0a94e","user_id":"3"
```
หรือ Wazuh Manager ดูผล Alert ที่ถูกจับได้: 
```
tail -f /var/ossec/logs/alerts/alerts.json | grep misp
```
Output: 
```
wazuh@wazuh:/var/ossec/etc/rules$ tail -f /var/ossec/logs/alerts/alerts.json | grep misp
{"timestamp":"2025-10-06T06:46:26.316+0000","rule":{"level":12,"description":"MISP IoC match detected: gamma.app [Category: Network activity]","id":"920100","firedtimes":6,"mail":true,"groups":["misp","sysmon","windows","misp","alert","sysmon","misp_alert"]},"agent":{"id":"005","name":"PC01","ip":"10.6.35.107"},"manager":{"name":"wazuh"},"id":"1759733186.3060535635","decoder":{"name":"json"},"data":{"integration":"misp","misp":{"event_id":"5","category":"Network activity","value":"gamma.app","type":"domain"},"rule":{"groups":["misp_alert"]},"rule_description":"Sysmon - Event ID 22: DNSEvent (DNS query)"},"location":"misp"}
```

# ขั้นตอนที่ 6: ทดสอบจาก Alert Telegrams
ตรวจสอบไฟล์ และ Permission :
```
ls -l /var/ossec/integrations/ | grep telegram
```
Output :
```
wazuh@wazuh:/var/ossec/etc/rules$ ls -l /var/ossec/integrations/ | grep telegram
-rwxr-x--- 1 root wazuh   845 Sep 30 08:12 custom-telegram
-rwxr-x--- 1 root wazuh  2563 Sep 30 08:11 custom-telegram.py
```
ตรวจสอบ Config :
```
cat /var/ossec/etc/ossec.conf | grep custom-telegram
```
Output :
```
wazuh@wazuh:/var/ossec/etc/rules$ cat /var/ossec/etc/ossec.conf | grep custom-telegram
     <name>custom-telegram</name>
```

บนเครื่อง Windows:
```
ping gamma.app
```
กลับมาที่ Wazuh Manager ดูผล Alert : 
```
tail -f /var/ossec/logs/integrations.log
```
Output: 
```
wazuh@wazuh:/var/ossec/etc/rules$ tail -f /var/ossec/logs/integrations.log
MSG: {'chat_id': '-4827186989', 'text': '*MISP IoC match detected: bing.com [Category: Network activity]*\n\n*Groups:* misp, sysmon, windows, misp, alert, sysmon, misp alert\n*Rule:* 920100 (Level 12)\n\n*Agent:* PC01 (005)\n*Agent IP:* 10.6.35.107', 'parse_mode': 'markdown'}
```
หรือ ผล Response : 
```
grep telegram /var/ossec/logs/integrations.log
```
Output: 
```
wazuh@wazuh:/var/ossec/etc/rules$ grep telegram /var/ossec/logs/integrations.log
telegram response: <Response [200]>
```



## Alerts (examples):

Sysmon Event 22 (Windows):


```
{
   "timestamp":"2022-01-12T09:12:49.276+0000",
   "rule":{
      "level":12,
      "description":"MISP - IoC found in Threat Intel - Category: Network activity, Attribute: detail43.myfirewall.org",
      "id":"100622",
      "firedtimes":2,
      "mail":true,
      "groups":[
         "misp",
         "misp_alert"
      ]
   },
   "agent":{
      "id":"020",
      "name":"WIN-7FK8M79Q5R6",
      "ip":"192.168.252.105",
      "labels":{
         "customer":"d827"
      }
   },
   "manager":{
      "name":"ASHWZH01"
   },
   "id":"1641978769.281770800",
   "decoder":{
      "name":"json"
   },
   "data":{
      "misp":{
         "event_id":"25",
         "category":"Network activity",
         "value":"detail43.myfirewall.org",
         "type":"hostname"
      }
   },
   "location":"misp"
}
```


Sysmon Event 3 (Linux):


```
{
  "timestamp":"2022-01-12T09:29:24.925+0000",
  "rule":{
     "level":12,
     "description":"MISP - IoC found in Threat Intel - Category: Network activity, Attribute: 95.154.195.159",
     "id":"100622",
     "firedtimes":1,
     "mail":true,
     "groups":[
        "misp",
        "misp_alert"
     ]
  },
  "agent":{
     "id":"017",
     "name":"ubunutu2004vm",
     "ip":"192.168.252.191",
     "labels":{
        "customer":"d827"
     }
  },
  "manager":{
     "name":"ASHWZH01"
  },
  "id":"1641979764.292099908",
  "decoder":{
     "name":"json"
  },
  "data":{
     "misp":{
        "event_id":"25",
        "category":"Network activity",
        "value":"95.154.195.159",
        "type":"ip-dst"
     }
  },
  "location":"misp"
}
```

<!-- CONTACT -->
