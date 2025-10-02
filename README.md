# วิธีการติดตั้ง MISP บน Wazuh-Single-node
### 1.ตั้งค่า custom-misp.py
---
ให้ทำการสร้าง/แก้ไข custom-misp.py ของท่านดังนี้ 
```
nano /var/ossec/integrations/custom-misp.py
```
ให้ทำกำหนดสิทธิ custom-misp.py ของท่านดังนี้ 
```
chown root:wazuh /var/ossec/integrations/custom-misp.py && chmod 750 /var/ossec/integrations/custom-misp.py
```
ตรวจสอบสิทธิ custom-misp.py ของท่านดังนี้ 
```
ls -l /var/ossec/integrations/
```
ลบ custom-misp.py ของท่านดังนี้ 
```
rm /var/ossec/integrations/custom-misp.py
```
### 2.การตั้งค่าบน ossec.conf
เพื่อแก้ไข/เพิ่ม การตั้งค่าบน ossec.conf
```
sudo nano /var/ossec/etc/ossec.conf
```
โค้ดด้านล่างไว้ใต้แท็ก </global> เพื่อเชื่อมต่อกับ MISP
```
<integration> 
    <name>custom-misp.py</name> 
    <group>sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event_15,sysmon_event_22,syscheck</group> 
    <alert_format>json</alert_format> 
</integration> 
```
ตรวจสอบว่ามี localfile monitoring
```
<!-- localfile monitoring -->
  <localfile>
    <log_format>journald</log_format>
    <location>journald</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
```
### 2.การตั้งค่าบน agent.conf
เพื่อแก้ไข/เพิ่ม การตั้งค่าบน agent.conf
```
sudo nano /var/ossec/etc/shared/default/agent.conf
```
วางโค้ดด้านล่างเพื่อเก็บ Log จาก Sysmon
```
<agent_config>
  <!-- เก็บ Log จาก Sysmon -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</agent_config>
```
ให้ทำกำหนดสิทธิ agent.conf ของท่านดังนี้ 
```
sudo chown root:wazuh /var/ossec/etc/shared/default/agent.conf
sudo chmod 640 /var/ossec/etc/shared/default/agent.conf
```
### 3.การตั้งค่า Rules ของ MISP 
ให้ทำการสร้าง/แก้ไข misp.xml ของท่านดังนี้ 
```
nano /var/ossec/etc/rules/misp.xml
```
เพิ่ม rule ดังนี้ จากนั้นกด Save เพื่อบันทึก rule
```
<group name="misp,"> 
  <rule id="100620" level="10"> 
    <field name="integration">misp</field> 
    <match>misp</match> 
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
ให้ทำกำหนดสิทธิ misp.xml ของท่านดังนี้ 

```
chmod 640 /var/ossec/etc/rules/misp.xml
chown root:wazuh /var/ossec/etc/rules/misp.xml
```
### 4.แก้ไขไฟล์ rules หลักเพื่อให้ Alert Log ของ Sysmon
ให้ทำการแก้ไขของ Wazuh Rules  0595-win-sysmon_rules.xml  ของท่านดังนี้ 
```
nano /var/ossec/ruleset/rules/0595-win-sysmon_rules.xml 
```
เปลี่ยน rule ที่ 61650 เป็นรูปแบบที่คู่มือนี้จัดทำให้
```
<rule id="61650" level="8" overwrite="yes"> 
  <if_sid>61600</if_sid> 
  <field name="win.system.eventID">^22$</field> 
  <description>Sysmon - Event ID 22: DNSEvent (DNS query)</description> 
  <options>no_full_log</options> 
  <group>sysmon_event_22,</group> 
</rule>
```
### 5.ใช้คำสั่ง restart Wazuh manager เพื่อรับค่า Integration สำหรับเชื่อมต่อ MISP 
```
systemctl restart wazuh-manager 
```
### 6.การติดตั้ง Sysmon ลงบนเครื่อง Endpoint ก่อนติดตั้ง Agent
1. ดาวน์โหลด Sysmon จาก https://download.sysinternals.com/files/Sysmon.zip
2. ดาวน์โหลดไฟล์ config.xml ได้ที่ https://github.com/SwiftOnSecurity/sysmon-config.git
3. Copy ไฟล์ sysmonconfig-export.xml ไป Folder เดียวกันกับ Sysmon
   - Sysmon.exe
   - Sysmon64.exe
   - Sysmon64a.exe
   - Eula.txt
   - sysmonconfig-export.xml
4. เปิด Windows PowerShell ในโหมด Run as Administrator
5. ใช้คำสั่ง cd เพื่อไปยัง path ที่มีตัวติดตั้ง Sysmon อยู่
```
cd C:\Users\admin\Downloads\Sysmon
ls
```
6. ใช้คำสั่งในการติดตั้ง Sysmon พร้อม config ลงบนเครื่อง Endpoint
```
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```
7. ติดตั้ง Sysmon เสร็จสิ้น สามารถตรวจสอบได้ที่ Event Viewer -> Applicationd and Services Logs -> Microsoft -> Windows -> Sysmon 

### 7. การ Deploy Agent ลงบน Endpoint Agent Wazuh
https://172.17.1.225/app/endpoints-summary#/agents-preview/deploy
1. Install on your system เลือก OS ที่จะนำไปติดตั้ง
2. Server address ระบุ IP หรือ Domain  Wazuh ของท่าน
3. ตั้งชื่อ Agents ควรเป็นชื่อแผนกหรือกลุ่มงานเพื่อให้ตามได้ให้สื่อความหมาย
4. Copy Run install the agent  เปิด Windows PowerShell ในโหมด Run as Administrator 
```
# ตัวอย่าง
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.12.0-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='172.17.1.225' WAZUH_AGENT_NAME='DMB-VLAN17' 
```
5. Start the agent 
```
# ตัวอย่าง
NET START WazuhSvc
```
6. เช็ค service ของ agent ต้อง Running
```
Get-Service wazuh
```
7. ตรวจสอบ log config ของ เปิด Noteped ในโหมด Run as Administrator
8. C:\Program Files (x86)\ossec-agent\ossec.log
9. Confirm ossec.conf และ connect ไปหา Manager (IP/port 1514)
```
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
ทดสอบผลการเชื่อมต่อ 
1. ค้นหา IOC ที่เป็น Domain หรือ IP Address บน MISP 
2. ทดสอบด้วยการ Ping หา IOC 
3. ตรวจสอบที่ Alert ของ Wazuh
4. rule-description จะแสดง MISP - IoC found in Threat Intel - Category : ....

Test api
curl  --header "Authorization: 5FXYU6Hy2Db3iDsg5wTI35WlMN6424JpchSF38AO" \
      --header "Accept: application/json" \
      --header "Content-Type: application/json" https://172.17.1.227/ 

      
> ท่านสามารถทดสอบการติดตั้ง ssl certificate ของท่านได้ที่ https://www.ssllabs.com/ssltest/
> บน Wazuh Manager
> ตรวจสอบว่า agent online
จะแสดงว่า Active : /var/ossec/bin/agent_control -lc
tail agent log : tail -f /var/ossec/logs/ossec.log | grep <agent_id>

> ตรวจสอบว่า agent online
จะแสดงว่า Active : /var/ossec/bin/agent_control -lc
tail agent log : tail -f /var/ossec/logs/ossec.log | grep <agent_id>

