https://groups.google.com/g/wazuh
# ตรวจสอบตัวอย่างโครงสร้าง decoders and rules. Example Fortigate event: 
## Custom Decoder
1. https://documentation.wazuh.com/4.6/user-manual/ruleset/custom.html
2. https://wazuh.com/blog/creating-decoders-and-rules-from-scratch/
3. https://documentation.wazuh.com/current/user-manual/ruleset/decoders/custom.html#modify-default-decoders
4. https://github.com/wazuh/wazuh-dashboard-plugins/issues/1884#issuecomment-557104742
5. https://github.com/wazuh/wazuh/issues/10538
6. https://groups.google.com/g/wazuh/c/fjcGL8PDCWA/m/jeUpn3shAQAJ
7. https://groups.google.com/g/wazuh/c/EosdAhnZRzU/m/rxN_PUPNAwAJ
8. https://groups.google.com/g/wazuh/c/ZKqJSIRr5oc/m/wEr-xeMTAwAJ


decoder
regex
Copy the default decoder file to the custom decoder folder

cp /var/ossec/ruleset/decoders/0100-fortigate_decoders.xml /var/ossec/etc/decoders/local_fortigate_decoders.xml

Open the file with the text editor

vi /var/ossec/etc/decoders/local_fortigate_decoders.xml

Add this additional decoder at the end of the file.

<decoder name="fortigate-firewall-v6">

  <parent>fortigate-firewall-v6</parent>

  <regex>devid="(\.*)"|devid=(\.*)\s|devid=(\.*)$</regex>

  <order>devid</order>

</decoder>



Change file permission.

chmod 660 /var/ossec/etc/decoders/local_fortigate_decoders.xml

chown wazuh:wazuh /var/ossec/etc/decoders/local_fortigate_decoders.xml




Go to manager’s ossec.conf

vi /var/ossec/etc/ossec.conf

Under the
<ruleset>

Add this line
<decoder_exclude>ruleset/decoders/0100-fortigate_decoders.xml</decoder_exclude>




Now restart the wazuh manager.

systemctl restart wazuh-manager
