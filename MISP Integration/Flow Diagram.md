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
