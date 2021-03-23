# Splunk Security Content Analytic Stories
![security_content](static/logo.png)
=====
All the Analytic Stories shipped to different Splunk products. Below is a breakdown by kind.


## Abuse
<details>
  <summary>details</summary>

### Brand Monitoring
Detect and investigate activity that may indicate that an adversary is using faux domains to mislead users into interacting with malicious infrastructure. Monitor DNS, email, and web traffic for permutations of your brand name.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Email, Network_Resolution, Web
- **ATT&CK**: 
- **Last Updated**: 2017-12-19

<details>
  <summary>details</summary>

#### Detection Profile

* [Monitor DNS For Brand Abuse](detections.md#monitor-dns-for-brand-abuse)

* [Monitor Email For Brand Abuse](detections.md#monitor-email-for-brand-abuse)

* [Monitor Web Traffic For Brand Abuse](detections.md#monitor-web-traffic-for-brand-abuse)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|

#### Kill Chain Phase

* Actions on Objectives

* Delivery


#### Reference

* https://www.zerofox.com/blog/what-is-digital-risk-monitoring/

* https://securingtomorrow.mcafee.com/consumer/family-safety/what-is-typosquatting/

* https://blog.malwarebytes.com/cybercrime/2016/06/explained-typosquatting/


_version_: 1
</details>

---

### DNS Amplification Attacks
DNS poses a serious threat as a Denial of Service (DOS) amplifier, if it responds to `ANY` queries. This Analytic Story can help you detect attackers who may be abusing your company's DNS infrastructure to launch amplification attacks, causing Denial of Service to other victims.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Network_Resolution
- **ATT&CK**: [T1498.002](https://attack.mitre.org/techniques/T1498.002/)
- **Last Updated**: 2016-09-13

<details>
  <summary>details</summary>

#### Detection Profile

* [Large Volume of DNS ANY Queries](detections.md#large-volume-of-dns-any-queries)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1498.002 | Reflection Amplification | Impact |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://www.us-cert.gov/ncas/alerts/TA13-088A

* https://www.imperva.com/learn/application-security/dns-amplification/


_version_: 1
</details>

---

### Data Protection
Fortify your data-protection arsenal--while continuing to ensure data confidentiality and integrity--with searches that monitor for and help you investigate possible signs of data exfiltration.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Change_Analysis, Network_Resolution
- **ATT&CK**: [T1048.003](https://attack.mitre.org/techniques/T1048.003/), [T1189](https://attack.mitre.org/techniques/T1189/)
- **Last Updated**: 2017-09-14

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect USB device insertion](detections.md#detect-usb-device-insertion)

* [Detect hosts connecting to dynamic domain providers](detections.md#detect-hosts-connecting-to-dynamic-domain-providers)

* [Detection of DNS Tunnels](detections.md#detection-of-dns-tunnels)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1189 | Drive-by Compromise | Initial Access |
| T1071.001 | Web Protocols | Command and Control |
| T1048.003 | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Installation


#### Reference

* https://www.cisecurity.org/controls/data-protection/

* https://www.sans.org/reading-room/whitepapers/dns/splunk-detect-dns-tunneling-37022

* https://umbrella.cisco.com/blog/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/


_version_: 1
</details>

---

### Host Redirection
Detect evidence of tactics used to redirect traffic from a host to a destination other than the one intended--potentially one that is part of an adversary's attack infrastructure. An example is redirecting communications regarding patches and updates or misleading users into visiting a malicious website.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Network_Resolution
- **ATT&CK**: [T1048.003](https://attack.mitre.org/techniques/T1048.003/), [T1071.004](https://attack.mitre.org/techniques/T1071.004/)
- **Last Updated**: 2017-09-14

<details>
  <summary>details</summary>

#### Detection Profile

* [Clients Connecting to Multiple DNS Servers](detections.md#clients-connecting-to-multiple-dns-servers)

* [DNS Query Requests Resolved by Unauthorized DNS Servers](detections.md#dns-query-requests-resolved-by-unauthorized-dns-servers)

* [Windows hosts file modification](detections.md#windows-hosts-file-modification)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1048.003 | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |
| T1071.004 | DNS | Command and Control |
| T1095 | Non-Application Layer Protocol | Command and Control |
| T1189 | Drive-by Compromise | Initial Access |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |
| T1071.001 | Web Protocols | Command and Control |

#### Kill Chain Phase

* Command and Control


#### Reference

* https://blog.malwarebytes.com/cybercrime/2016/09/hosts-file-hijacks/


_version_: 1
</details>

---

### Netsh Abuse
Detect activities and various techniques associated with the abuse of `netsh.exe`, which can disable local firewall settings or set up a remote connection to a host from an infected system.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1562.004](https://attack.mitre.org/techniques/T1562.004/)
- **Last Updated**: 2017-01-05

<details>
  <summary>details</summary>

#### Detection Profile

* [Processes created by netsh](detections.md#processes-created-by-netsh)

* [Processes launching netsh](detections.md#processes-launching-netsh)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1562.004 | Disable or Modify System Firewall | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://docs.microsoft.com/en-us/previous-versions/tn-archive/bb490939(v=technet.10)

* https://htmlpreview.github.io/?https://github.com/MatthewDemaske/blogbackup/blob/master/netshell.html

* http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html


_version_: 1
</details>

---

### Web Fraud Detection
Monitor your environment for activity consistent with common attack techniques bad actors use when attempting to compromise web servers or other web-related assets.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1078](https://attack.mitre.org/techniques/T1078/), [T1136](https://attack.mitre.org/techniques/T1136/)
- **Last Updated**: 2018-10-08

<details>
  <summary>details</summary>

#### Detection Profile

* [Web Fraud - Account Harvesting](detections.md#web-fraud---account-harvesting)

* [Web Fraud - Anomalous User Clickspeed](detections.md#web-fraud---anomalous-user-clickspeed)

* [Web Fraud - Password Sharing Across Accounts](detections.md#web-fraud---password-sharing-across-accounts)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1136 | Create Account | Persistence |
| T1078 | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://www.fbi.gov/scams-and-safety/common-fraud-schemes/internet-fraud

* https://www.fbi.gov/news/stories/2017-internet-crime-report-released-050718


_version_: 1
</details>

---

</details>

## Adversary Tactics
<details>
  <summary>details</summary>

### Baron Samedit CVE-2021-3156
Uncover activity consistent with CVE-2021-3156. Discovered by the Qualys Research Team, this vulnerability has been found to affect sudo across multiple Linux distributions (Ubuntu 20.04 and prior, Debian 10 and prior, Fedora 33 and prior). As this vulnerability was committed to code in July 2011, there will be many distributions affected. Successful exploitation of this vulnerability allows any unprivileged user to gain root privileges on the vulnerable host.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1068](https://attack.mitre.org/techniques/T1068/)
- **Last Updated**: 2021-01-27

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect Baron Samedit CVE-2021-3156](detections.md#detect-baron-samedit-cve-2021-3156)

* [Detect Baron Samedit CVE-2021-3156 Segfault](detections.md#detect-baron-samedit-cve-2021-3156-segfault)

* [Detect Baron Samedit CVE-2021-3156 via OSQuery](detections.md#detect-baron-samedit-cve-2021-3156-via-osquery)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |

#### Kill Chain Phase

* Exploitation


#### Reference

* https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit


_version_: 1
</details>

---

### Cobalt Strike
Cobalt Strike is threat emulation software. Red teams and penetration testers use Cobalt Strike to demonstrate the risk of a breach and evaluate mature security programs. Most recently, Cobalt Strike has become the choice tool by threat groups due to its ease of use and extensibility.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1218.011](https://attack.mitre.org/techniques/T1218.011/)
- **Last Updated**: 2021-02-16

<details>
  <summary>details</summary>

#### Detection Profile

* [Suspicious Rundll32 StartW](detections.md#suspicious-rundll32-startw)

* [Suspicious Rundll32 no CommandLine Arguments](detections.md#suspicious-rundll32-no-commandline-arguments)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1218.011 | Rundll32 | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://www.cobaltstrike.com/

* https://www.infocyte.com/blog/2020/09/02/cobalt-strike-the-new-favorite-among-thieves/

* https://bluescreenofjeff.com/2017-01-24-how-to-write-malleable-c2-profiles-for-cobalt-strike/

* https://blog.talosintelligence.com/2020/09/coverage-strikes-back-cobalt-strike-paper.html

* https://www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html


_version_: 1
</details>

---

### Collection and Staging
Monitor for and investigate activities--such as suspicious writes to the Windows Recycling Bin or email servers sending high amounts of traffic to specific hosts, for example--that may indicate that an adversary is harvesting and exfiltrating sensitive data. 

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint, Network_Traffic
- **ATT&CK**: [T1036](https://attack.mitre.org/techniques/T1036/), [T1114.001](https://attack.mitre.org/techniques/T1114.001/), [T1114.002](https://attack.mitre.org/techniques/T1114.002/)
- **Last Updated**: 2020-02-03

<details>
  <summary>details</summary>

#### Detection Profile

* [Email files written outside of the Outlook directory](detections.md#email-files-written-outside-of-the-outlook-directory)

* [Email servers sending high volume traffic to hosts](detections.md#email-servers-sending-high-volume-traffic-to-hosts)

* [Hosts receiving high volume of network traffic from email server](detections.md#hosts-receiving-high-volume-of-network-traffic-from-email-server)

* [Suspicious writes to System Volume Information](detections.md#suspicious-writes-to-system-volume-information)

* [Suspicious writes to windows Recycle Bin](detections.md#suspicious-writes-to-windows-recycle-bin)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1114.001 | Local Email Collection | Collection |
| T1114.002 | Remote Email Collection | Collection |
| T1036 | Masquerading | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://attack.mitre.org/wiki/Collection

* https://attack.mitre.org/wiki/Technique/T1074


_version_: 1
</details>

---

### Command and Control
Detect and investigate tactics, techniques, and procedures leveraged by attackers to establish and operate command and control channels. Implants installed by attackers on compromised endpoints use these channels to receive instructions and send data back to the malicious operators.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Network_Resolution, Network_Traffic
- **ATT&CK**: [T1048](https://attack.mitre.org/techniques/T1048/), [T1048.003](https://attack.mitre.org/techniques/T1048.003/), [T1071.001](https://attack.mitre.org/techniques/T1071.001/), [T1071.004](https://attack.mitre.org/techniques/T1071.004/), [T1095](https://attack.mitre.org/techniques/T1095/), [T1189](https://attack.mitre.org/techniques/T1189/)
- **Last Updated**: 2018-06-01

<details>
  <summary>details</summary>

#### Detection Profile

* [Clients Connecting to Multiple DNS Servers](detections.md#clients-connecting-to-multiple-dns-servers)

* [DNS Query Length Outliers - MLTK](detections.md#dns-query-length-outliers---mltk)

* [DNS Query Length With High Standard Deviation](detections.md#dns-query-length-with-high-standard-deviation)

* [DNS Query Requests Resolved by Unauthorized DNS Servers](detections.md#dns-query-requests-resolved-by-unauthorized-dns-servers)

* [Detect Large Outbound ICMP Packets](detections.md#detect-large-outbound-icmp-packets)

* [Detect Long DNS TXT Record Response](detections.md#detect-long-dns-txt-record-response)

* [Detect Spike in blocked Outbound Traffic from your AWS](detections.md#detect-spike-in-blocked-outbound-traffic-from-your-aws)

* [Detect hosts connecting to dynamic domain providers](detections.md#detect-hosts-connecting-to-dynamic-domain-providers)

* [Detection of DNS Tunnels](detections.md#detection-of-dns-tunnels)

* [Excessive DNS Failures](detections.md#excessive-dns-failures)

* [Prohibited Network Traffic Allowed](detections.md#prohibited-network-traffic-allowed)

* [Protocol or Port Mismatch](detections.md#protocol-or-port-mismatch)

* [TOR Traffic](detections.md#tor-traffic)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1048.003 | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |
| T1071.004 | DNS | Command and Control |
| T1095 | Non-Application Layer Protocol | Command and Control |
| T1189 | Drive-by Compromise | Initial Access |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |
| T1071.001 | Web Protocols | Command and Control |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Delivery


#### Reference

* https://attack.mitre.org/wiki/Command_and_Control

* https://searchsecurity.techtarget.com/feature/Command-and-control-servers-The-puppet-masters-that-govern-malware


_version_: 1
</details>

---

### Common Phishing Frameworks
Detect DNS and web requests to fake websites generated by the EvilGinx2 toolkit. These websites are designed to fool unwitting users who have clicked on a malicious link in a phishing email. 

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Network_Resolution
- **ATT&CK**: [T1566.003](https://attack.mitre.org/techniques/T1566.003/)
- **Last Updated**: 2019-04-29

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect DNS requests to Phishing Sites leveraging EvilGinx2](detections.md#detect-dns-requests-to-phishing-sites-leveraging-evilginx2)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1566.003 | Spearphishing via Service | Initial Access |

#### Kill Chain Phase

* Command and Control

* Delivery


#### Reference

* https://github.com/kgretzky/evilginx2

* https://attack.mitre.org/techniques/T1192/

* https://breakdev.org/evilginx-advanced-phishing-with-two-factor-authentication-bypass/


_version_: 1
</details>

---

### Credential Dumping
Uncover activity consistent with credential dumping, a technique wherein attackers compromise systems and attempt to obtain and exfiltrate passwords. The threat actors use these pilfered credentials to further escalate privileges and spread throughout a target environment. The included searches in this Analytic Story are designed to identify attempts to credential dumping.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1003](https://attack.mitre.org/techniques/T1003/), [T1003.001](https://attack.mitre.org/techniques/T1003.001/), [T1003.002](https://attack.mitre.org/techniques/T1003.002/), [T1003.003](https://attack.mitre.org/techniques/T1003.003/), [T1059.001](https://attack.mitre.org/techniques/T1059.001/)
- **Last Updated**: 2020-02-04

<details>
  <summary>details</summary>

#### Detection Profile

* [Access LSASS Memory for Dump Creation](detections.md#access-lsass-memory-for-dump-creation)

* [Attempt To Set Default PowerShell Execution Policy To Unrestricted or Bypass](detections.md#attempt-to-set-default-powershell-execution-policy-to-unrestricted-or-bypass)

* [Attempted Credential Dump From Registry via Reg exe](detections.md#attempted-credential-dump-from-registry-via-reg-exe)

* [Create Remote Thread into LSASS](detections.md#create-remote-thread-into-lsass)

* [Creation of Shadow Copy](detections.md#creation-of-shadow-copy)

* [Creation of Shadow Copy with wmic and powershell](detections.md#creation-of-shadow-copy-with-wmic-and-powershell)

* [Creation of lsass Dump with Taskmgr](detections.md#creation-of-lsass-dump-with-taskmgr)

* [Credential Dumping via Copy Command from Shadow Copy](detections.md#credential-dumping-via-copy-command-from-shadow-copy)

* [Credential Dumping via Symlink to Shadow Copy](detections.md#credential-dumping-via-symlink-to-shadow-copy)

* [Detect Credential Dumping through LSASS access](detections.md#detect-credential-dumping-through-lsass-access)

* [Detect Dump LSASS Memory using comsvcs](detections.md#detect-dump-lsass-memory-using-comsvcs)

* [Detect Mimikatz Using Loaded Images](detections.md#detect-mimikatz-using-loaded-images)

* [Dump LSASS via comsvcs DLL](detections.md#dump-lsass-via-comsvcs-dll)

* [Dump LSASS via procdump](detections.md#dump-lsass-via-procdump)

* [Dump LSASS via procdump Rename](detections.md#dump-lsass-via-procdump-rename)

* [Ntdsutil export ntds](detections.md#ntdsutil-export-ntds)

* [Unsigned Image Loaded by LSASS](detections.md#unsigned-image-loaded-by-lsass)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1003.001 | LSASS Memory | Credential Access |
| T1059.001 | PowerShell | Execution |
| T1003.002 | Security Account Manager | Credential Access |
| T1003 | OS Credential Dumping | Credential Access |
| T1003.003 | NTDS | Credential Access |

#### Kill Chain Phase

* Actions on Objectives

* Installation


#### Reference

* https://attack.mitre.org/wiki/Technique/T1003

* https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html


_version_: 3
</details>

---

### DNS Hijacking
Secure your environment against DNS hijacks with searches that help you detect and investigate unauthorized changes to DNS records.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Network_Resolution
- **ATT&CK**: [T1048.003](https://attack.mitre.org/techniques/T1048.003/), [T1071.004](https://attack.mitre.org/techniques/T1071.004/), [T1189](https://attack.mitre.org/techniques/T1189/)
- **Last Updated**: 2020-02-04

<details>
  <summary>details</summary>

#### Detection Profile

* [Clients Connecting to Multiple DNS Servers](detections.md#clients-connecting-to-multiple-dns-servers)

* [DNS Query Requests Resolved by Unauthorized DNS Servers](detections.md#dns-query-requests-resolved-by-unauthorized-dns-servers)

* [DNS record changed](detections.md#dns-record-changed)

* [Detect hosts connecting to dynamic domain providers](detections.md#detect-hosts-connecting-to-dynamic-domain-providers)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1048.003 | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |
| T1071.004 | DNS | Command and Control |
| T1095 | Non-Application Layer Protocol | Command and Control |
| T1189 | Drive-by Compromise | Initial Access |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |
| T1071.001 | Web Protocols | Command and Control |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control


#### Reference

* https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html

* https://umbrella.cisco.com/blog/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/

* http://www.noip.com/blog/2014/07/11/dynamic-dns-can-use-2/

* https://www.splunk.com/blog/2015/08/04/detecting-dynamic-dns-domains-in-splunk.html


_version_: 1
</details>

---

### Data Exfiltration
The stealing of data by an adversary.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1041](https://attack.mitre.org/techniques/T1041/)
- **Last Updated**: 2020-10-21

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect SNICat SNI Exfiltration](detections.md#detect-snicat-sni-exfiltration)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1041 | Exfiltration Over C2 Channel | Exfiltration |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://attack.mitre.org/tactics/TA0010/


_version_: 1
</details>

---

### Detect Zerologon Attack
Uncover activity related to the execution of Zerologon CVE-2020-11472, a technique wherein attackers target a Microsoft Windows Domain Controller to reset its computer account password. The result from this attack is attackers can now provide themselves high privileges and take over Domain Controller. The included searches in this Analytic Story are designed to identify attempts to reset Domain Controller Computer Account via exploit code remotely or via the use of tool Mimikatz as payload carrier.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1003.001](https://attack.mitre.org/techniques/T1003.001/), [T1190](https://attack.mitre.org/techniques/T1190/), [T1210](https://attack.mitre.org/techniques/T1210/)
- **Last Updated**: 2020-09-18

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect Computer Changed with Anonymous Account](detections.md#detect-computer-changed-with-anonymous-account)

* [Detect Credential Dumping through LSASS access](detections.md#detect-credential-dumping-through-lsass-access)

* [Detect Mimikatz Using Loaded Images](detections.md#detect-mimikatz-using-loaded-images)

* [Detect Zerologon via Zeek](detections.md#detect-zerologon-via-zeek)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1210 | Exploitation of Remote Services | Lateral Movement |
| T1003.001 | LSASS Memory | Credential Access |
| T1190 | Exploit Public-Facing Application | Initial Access |

#### Kill Chain Phase

* Actions on Objectives

* Exploitation


#### Reference

* https://attack.mitre.org/wiki/Technique/T1003

* https://github.com/SecuraBV/CVE-2020-1472

* https://www.secura.com/blog/zero-logon

* https://nvd.nist.gov/vuln/detail/CVE-2020-1472


_version_: 1
</details>

---

### Disabling Security Tools
Looks for activities and techniques associated with the disabling of security tools on a Windows system, such as suspicious `reg.exe` processes, processes launching netsh, and many others.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1112](https://attack.mitre.org/techniques/T1112/), [T1543.003](https://attack.mitre.org/techniques/T1543.003/), [T1553.004](https://attack.mitre.org/techniques/T1553.004/), [T1562.001](https://attack.mitre.org/techniques/T1562.001/), [T1562.004](https://attack.mitre.org/techniques/T1562.004/)
- **Last Updated**: 2020-02-04

<details>
  <summary>details</summary>

#### Detection Profile

* [Attempt To Add Certificate To Untrusted Store](detections.md#attempt-to-add-certificate-to-untrusted-store)

* [Attempt To Stop Security Service](detections.md#attempt-to-stop-security-service)

* [Processes launching netsh](detections.md#processes-launching-netsh)

* [Sc exe Manipulating Windows Services](detections.md#sc-exe-manipulating-windows-services)

* [Suspicious Reg exe Process](detections.md#suspicious-reg-exe-process)

* [Unload Sysmon Filter Driver](detections.md#unload-sysmon-filter-driver)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1553.004 | Install Root Certificate | Defense Evasion |
| T1562.001 | Disable or Modify Tools | Defense Evasion |
| T1562.004 | Disable or Modify System Firewall | Defense Evasion |
| T1543.003 | Windows Service | Persistence, Privilege Escalation |
| T1112 | Modify Registry | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives

* Installation


#### Reference

* https://attack.mitre.org/wiki/Technique/T1089

* https://blog.malwarebytes.com/cybercrime/2015/11/vonteera-adware-uses-certificates-to-disable-anti-malware/

* https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Tools-Report.pdf


_version_: 2
</details>

---

### F5 TMUI RCE CVE-2020-5902
Uncover activity consistent with CVE-2020-5902. Discovered by Positive Technologies researchers, this vulnerability affects F5 BIG-IP, BIG-IQ. and Traffix SDC devices (vulnerable versions in F5 support link below). This vulnerability allows unauthenticated users, along with authenticated users, who have access to the configuration utility to execute system commands, create/delete files, disable services, and/or execute Java code.  This vulnerability can result in full system compromise.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1190](https://attack.mitre.org/techniques/T1190/)
- **Last Updated**: 2020-08-02

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect F5 TMUI RCE CVE-2020-5902](detections.md#detect-f5-tmui-rce-cve-2020-5902)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1190 | Exploit Public-Facing Application | Initial Access |

#### Kill Chain Phase

* Exploitation


#### Reference

* https://www.ptsecurity.com/ww-en/about/news/f5-fixes-critical-vulnerability-discovered-by-positive-technologies-in-big-ip-application-delivery-controller/

* https://support.f5.com/csp/article/K52145254

* https://blog.cloudflare.com/cve-2020-5902-helping-to-protect-against-the-f5-tmui-rce-vulnerability/


_version_: 1
</details>

---

### Lateral Movement
Detect and investigate tactics, techniques, and procedures around how attackers move laterally within the enterprise. Because lateral movement can expose the adversary to detection, it should be an important focus for security analysts.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint, Network_Traffic
- **ATT&CK**: [T1021.001](https://attack.mitre.org/techniques/T1021.001/), [T1053.005](https://attack.mitre.org/techniques/T1053.005/), [T1550.002](https://attack.mitre.org/techniques/T1550.002/), [T1558.003](https://attack.mitre.org/techniques/T1558.003/)
- **Last Updated**: 2020-02-04

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect Activity Related to Pass the Hash Attacks](detections.md#detect-activity-related-to-pass-the-hash-attacks)

* [Kerberoasting spn request with RC4 encryption](detections.md#kerberoasting-spn-request-with-rc4-encryption)

* [Remote Desktop Network Traffic](detections.md#remote-desktop-network-traffic)

* [Remote Desktop Process Running On System](detections.md#remote-desktop-process-running-on-system)

* [Schtasks scheduling job on remote system](detections.md#schtasks-scheduling-job-on-remote-system)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1550.002 | Pass the Hash | Defense Evasion, Lateral Movement |
| T1558.003 | Kerberoasting | Credential Access |
| T1021.001 | Remote Desktop Protocol | Lateral Movement |
| T1053.005 | Scheduled Task | Execution, Persistence, Privilege Escalation |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://www.fireeye.com/blog/executive-perspective/2015/08/malware_lateral_move.html


_version_: 2
</details>

---

### Malicious PowerShell
Attackers are finding stealthy ways "live off the land," leveraging utilities and tools that come standard on the endpoint--such as PowerShell--to achieve their goals without downloading binary files. These searches can help you detect and investigate PowerShell command-line options that may be indicative of malicious intent.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1027](https://attack.mitre.org/techniques/T1027/), [T1059.001](https://attack.mitre.org/techniques/T1059.001/)
- **Last Updated**: 2017-08-23

<details>
  <summary>details</summary>

#### Detection Profile

* [Attempt To Set Default PowerShell Execution Policy To Unrestricted or Bypass](detections.md#attempt-to-set-default-powershell-execution-policy-to-unrestricted-or-bypass)

* [Malicious PowerShell Process - Connect To Internet With Hidden Window](detections.md#malicious-powershell-process---connect-to-internet-with-hidden-window)

* [Malicious PowerShell Process - Encoded Command](detections.md#malicious-powershell-process---encoded-command)

* [Malicious PowerShell Process - Multiple Suspicious Command-Line Arguments](detections.md#malicious-powershell-process---multiple-suspicious-command-line-arguments)

* [Malicious PowerShell Process With Obfuscation Techniques](detections.md#malicious-powershell-process-with-obfuscation-techniques)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1059.001 | PowerShell | Execution |
| T1027 | Obfuscated Files or Information | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Installation


#### Reference

* https://blogs.mcafee.com/mcafee-labs/malware-employs-powershell-to-infect-systems/

* https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/


_version_: 4
</details>

---

### Phishing Payloads
Detect signs of malicious payloads that may indicate that your environment has been breached via a phishing attack.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1566.001](https://attack.mitre.org/techniques/T1566.001/), [T1566.002](https://attack.mitre.org/techniques/T1566.002/)
- **Last Updated**: 2019-04-29

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect Oulook exe writing a  zip file](detections.md#detect-oulook-exe-writing-a--zip-file)

* [Process Creating LNK file in Suspicious Location](detections.md#process-creating-lnk-file-in-suspicious-location)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1566.001 | Spearphishing Attachment | Initial Access |
| T1566.002 | Spearphishing Link | Initial Access |

#### Kill Chain Phase

* Actions on Objectives

* Installation


#### Reference

* https://www.fireeye.com/blog/threat-research/2019/04/spear-phishing-campaign-targets-ukraine-government.html


_version_: 1
</details>

---

### Possible Backdoor Activity Associated With MUDCARP Espionage Campaigns
Monitor your environment for suspicious behaviors that resemble the techniques employed by the MUDCARP threat group.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1059.001](https://attack.mitre.org/techniques/T1059.001/), [T1059.003](https://attack.mitre.org/techniques/T1059.003/), [T1547.001](https://attack.mitre.org/techniques/T1547.001/)
- **Last Updated**: 2020-01-22

<details>
  <summary>details</summary>

#### Detection Profile

* [First time seen command line argument](detections.md#first-time-seen-command-line-argument)

* [Malicious PowerShell Process - Connect To Internet With Hidden Window](detections.md#malicious-powershell-process---connect-to-internet-with-hidden-window)

* [Registry Keys Used For Persistence](detections.md#registry-keys-used-for-persistence)

* [Unusually Long Command Line](detections.md#unusually-long-command-line)

* [Unusually Long Command Line - MLTK](detections.md#unusually-long-command-line---mltk)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1059.001 | PowerShell | Execution |
| T1059.003 | Windows Command Shell | Execution |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control


#### Reference

* https://www.infosecurity-magazine.com/news/scope-of-mudcarp-attacks-highlight-1/

* http://blog.amossys.fr/badflick-is-not-so-bad.html


_version_: 1
</details>

---

### SQL Injection
Use the searches in this Analytic Story to help you detect structured query language (SQL) injection attempts characterized by long URLs that contain malicious parameters.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Web
- **ATT&CK**: [T1190](https://attack.mitre.org/techniques/T1190/)
- **Last Updated**: 2017-09-19

<details>
  <summary>details</summary>

#### Detection Profile

* [SQL Injection with Long URLs](detections.md#sql-injection-with-long-urls)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1190 | Exploit Public-Facing Application | Initial Access |

#### Kill Chain Phase

* Delivery


#### Reference

* https://capec.mitre.org/data/definitions/66.html

* https://www.incapsula.com/web-application-security/sql-injection.html


_version_: 1
</details>

---

### Sunburst Malware
Sunburst is a trojanized updates to SolarWinds Orion IT monitoring and management software. It was discovered by FireEye in December 2020. The actors behind this campaign gained access to numerous public and private organizations around the world.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint, Network_Traffic, Web
- **ATT&CK**: [T1018](https://attack.mitre.org/techniques/T1018/), [T1027](https://attack.mitre.org/techniques/T1027/), [T1053.005](https://attack.mitre.org/techniques/T1053.005/), [T1059.003](https://attack.mitre.org/techniques/T1059.003/), [T1071.001](https://attack.mitre.org/techniques/T1071.001/), [T1071.002](https://attack.mitre.org/techniques/T1071.002/), [T1203](https://attack.mitre.org/techniques/T1203/), [T1505.003](https://attack.mitre.org/techniques/T1505.003/), [T1543.003](https://attack.mitre.org/techniques/T1543.003/), [T1569.002](https://attack.mitre.org/techniques/T1569.002/)
- **Last Updated**: 2020-12-14

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect Outbound SMB Traffic](detections.md#detect-outbound-smb-traffic)

* [Detect Prohibited Applications Spawning cmd exe](detections.md#detect-prohibited-applications-spawning-cmd-exe)

* [First Time Seen Running Windows Service](detections.md#first-time-seen-running-windows-service)

* [Malicious PowerShell Process - Encoded Command](detections.md#malicious-powershell-process---encoded-command)

* [Sc exe Manipulating Windows Services](detections.md#sc-exe-manipulating-windows-services)

* [Scheduled Task Deleted Or Created via CMD](detections.md#scheduled-task-deleted-or-created-via-cmd)

* [Schtasks scheduling job on remote system](detections.md#schtasks-scheduling-job-on-remote-system)

* [Sunburst Correlation DLL and Network Event](detections.md#sunburst-correlation-dll-and-network-event)

* [Supernova Webshell](detections.md#supernova-webshell)

* [TOR Traffic](detections.md#tor-traffic)

* [Windows AdFind Exe](detections.md#windows-adfind-exe)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1071.002 | File Transfer Protocols | Command and Control |
| T1059.003 | Windows Command Shell | Execution |
| T1569.002 | Service Execution | Execution |
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1543.003 | Windows Service | Persistence, Privilege Escalation |
| T1053.005 | Scheduled Task | Execution, Persistence, Privilege Escalation |
| T1203 | Exploitation for Client Execution | Execution |
| T1505.003 | Web Shell | Persistence |
| T1071.001 | Web Protocols | Command and Control |
| T1018 | Remote System Discovery | Discovery |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Exfiltration

* Exploitation

* Installation


#### Reference

* https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html

* https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/


_version_: 1
</details>

---

### Suspicious Command-Line Executions
Leveraging the Windows command-line interface (CLI) is one of the most common attack techniques--one that is also detailed in the MITRE ATT&CK framework. Use this Analytic Story to help you identify unusual or suspicious use of the CLI on Windows systems.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1036.003](https://attack.mitre.org/techniques/T1036.003/), [T1059.001](https://attack.mitre.org/techniques/T1059.001/), [T1059.003](https://attack.mitre.org/techniques/T1059.003/)
- **Last Updated**: 2020-02-03

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect Prohibited Applications Spawning cmd exe](detections.md#detect-prohibited-applications-spawning-cmd-exe)

* [Detect Use of cmd exe to Launch Script Interpreters](detections.md#detect-use-of-cmd-exe-to-launch-script-interpreters)

* [First time seen command line argument](detections.md#first-time-seen-command-line-argument)

* [System Processes Run From Unexpected Locations](detections.md#system-processes-run-from-unexpected-locations)

* [Unusually Long Command Line](detections.md#unusually-long-command-line)

* [Unusually Long Command Line - MLTK](detections.md#unusually-long-command-line---mltk)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1059.003 | Windows Command Shell | Execution |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
| T1059.001 | PowerShell | Execution |
| T1036.003 | Rename System Utilities | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Exploitation


#### Reference

* https://attack.mitre.org/wiki/Technique/T1059

* https://www.microsoft.com/en-us/wdsi/threats/macro-malware

* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf


_version_: 2
</details>

---

### Suspicious Compiled HTML Activity
Monitor and detect techniques used by attackers who leverage the mshta.exe process to execute malicious code.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1218.001](https://attack.mitre.org/techniques/T1218.001/)
- **Last Updated**: 2021-02-11

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect HTML Help Renamed](detections.md#detect-html-help-renamed)

* [Detect HTML Help Spawn Child Process](detections.md#detect-html-help-spawn-child-process)

* [Detect HTML Help URL in Command Line](detections.md#detect-html-help-url-in-command-line)

* [Detect HTML Help Using InfoTech Storage Handlers](detections.md#detect-html-help-using-infotech-storage-handlers)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1218.001 | Compiled HTML File | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://redcanary.com/blog/introducing-atomictestharnesses/

* https://attack.mitre.org/techniques/T1218/001/

* https://docs.microsoft.com/en-us/windows/win32/api/htmlhelp/nf-htmlhelp-htmlhelpa


_version_: 1
</details>

---

### Suspicious DNS Traffic
Attackers often attempt to hide within or otherwise abuse the domain name system (DNS). You can thwart attempts to manipulate this omnipresent protocol by monitoring for these types of abuses.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Network_Resolution
- **ATT&CK**: [T1048.003](https://attack.mitre.org/techniques/T1048.003/), [T1071.004](https://attack.mitre.org/techniques/T1071.004/), [T1189](https://attack.mitre.org/techniques/T1189/)
- **Last Updated**: 2017-09-18

<details>
  <summary>details</summary>

#### Detection Profile

* [Clients Connecting to Multiple DNS Servers](detections.md#clients-connecting-to-multiple-dns-servers)

* [DNS Query Length Outliers - MLTK](detections.md#dns-query-length-outliers---mltk)

* [DNS Query Length With High Standard Deviation](detections.md#dns-query-length-with-high-standard-deviation)

* [DNS Query Requests Resolved by Unauthorized DNS Servers](detections.md#dns-query-requests-resolved-by-unauthorized-dns-servers)

* [Detect Long DNS TXT Record Response](detections.md#detect-long-dns-txt-record-response)

* [Detect hosts connecting to dynamic domain providers](detections.md#detect-hosts-connecting-to-dynamic-domain-providers)

* [Detection of DNS Tunnels](detections.md#detection-of-dns-tunnels)

* [Excessive DNS Failures](detections.md#excessive-dns-failures)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1048.003 | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |
| T1071.004 | DNS | Command and Control |
| T1095 | Non-Application Layer Protocol | Command and Control |
| T1189 | Drive-by Compromise | Initial Access |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |
| T1071.001 | Web Protocols | Command and Control |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control


#### Reference

* http://blogs.splunk.com/2015/10/01/random-words-on-entropy-and-dns/

* http://www.darkreading.com/analytics/security-monitoring/got-malware-three-signs-revealed-in-dns-traffic/d/d-id/1139680

* https://live.paloaltonetworks.com/t5/Threat-Vulnerability-Articles/What-are-suspicious-DNS-queries/ta-p/71454


_version_: 1
</details>

---

### Suspicious Emails
Email remains one of the primary means for attackers to gain an initial foothold within the modern enterprise. Detect and investigate suspicious emails in your environment with the help of the searches in this Analytic Story.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Email, UEBA
- **ATT&CK**: [T1566](https://attack.mitre.org/techniques/T1566/), [T1566.001](https://attack.mitre.org/techniques/T1566.001/)
- **Last Updated**: 2020-01-27

<details>
  <summary>details</summary>

#### Detection Profile

* [Email Attachments With Lots Of Spaces](detections.md#email-attachments-with-lots-of-spaces)

* [Monitor Email For Brand Abuse](detections.md#monitor-email-for-brand-abuse)

* [Suspicious Email - UBA Anomaly](detections.md#suspicious-email---uba-anomaly)

* [Suspicious Email Attachment Extensions](detections.md#suspicious-email-attachment-extensions)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1566 | Phishing | Initial Access |
| T1566.001 | Spearphishing Attachment | Initial Access |

#### Kill Chain Phase

* Delivery


#### Reference

* https://www.splunk.com/blog/2015/06/26/phishing-hits-a-new-level-of-quality/


_version_: 1
</details>

---

### Suspicious MSHTA Activity
Monitor and detect techniques used by attackers who leverage the mshta.exe process to execute malicious code.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1059.003](https://attack.mitre.org/techniques/T1059.003/), [T1218.005](https://attack.mitre.org/techniques/T1218.005/), [T1547.001](https://attack.mitre.org/techniques/T1547.001/)
- **Last Updated**: 2021-01-20

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect MSHTA Url in Command Line](detections.md#detect-mshta-url-in-command-line)

* [Detect Prohibited Applications Spawning cmd exe](detections.md#detect-prohibited-applications-spawning-cmd-exe)

* [Detect Rundll32 Inline HTA Execution](detections.md#detect-rundll32-inline-hta-execution)

* [Detect mshta inline hta execution](detections.md#detect-mshta-inline-hta-execution)

* [Detect mshta renamed](detections.md#detect-mshta-renamed)

* [Registry Keys Used For Persistence](detections.md#registry-keys-used-for-persistence)

* [Suspicious mshta child process](detections.md#suspicious-mshta-child-process)

* [Suspicious mshta spawn](detections.md#suspicious-mshta-spawn)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1218.005 | Mshta | Defense Evasion |
| T1059.003 | Windows Command Shell | Execution |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation |

#### Kill Chain Phase

* Actions on Objectives

* Exploitation


#### Reference

* https://redcanary.com/blog/introducing-atomictestharnesses/

* https://redcanary.com/blog/windows-registry-attacks-threat-detection/

* https://attack.mitre.org/techniques/T1218/005/

* https://medium.com/@mbromileyDFIR/malware-monday-aebb456356c5


_version_: 2
</details>

---

### Suspicious Okta Activity
Monitor your Okta environment for suspicious activities. Due to the Covid outbreak, many users are migrating over to leverage cloud services more and more. Okta is a popular tool to manage multiple users and the web-based applications they need to stay productive. The searches in this story will help monitor your Okta environment for suspicious activities and associated user behaviors.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1078.001](https://attack.mitre.org/techniques/T1078.001/)
- **Last Updated**: 2020-04-02

<details>
  <summary>details</summary>

#### Detection Profile

* [Multiple Okta Users With Invalid Credentials From The Same IP](detections.md#multiple-okta-users-with-invalid-credentials-from-the-same-ip)

* [Okta Account Lockout Events](detections.md#okta-account-lockout-events)

* [Okta Failed SSO Attempts](detections.md#okta-failed-sso-attempts)

* [Okta User Logins From Multiple Cities](detections.md#okta-user-logins-from-multiple-cities)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1078.001 | Default Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Kill Chain Phase


#### Reference

* https://attack.mitre.org/wiki/Technique/T1078

* https://owasp.org/www-community/attacks/Credential_stuffing

* https://searchsecurity.techtarget.com/answer/What-is-a-password-spraying-attack-and-how-does-it-work


_version_: 1
</details>

---

### Suspicious Regsvcs Regasm Activity
Monitor and detect techniques used by attackers who leverage the mshta.exe process to execute malicious code.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1218.009](https://attack.mitre.org/techniques/T1218.009/)
- **Last Updated**: 2021-02-11

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect Regasm Spawning a Process](detections.md#detect-regasm-spawning-a-process)

* [Detect Regasm with Network Connection](detections.md#detect-regasm-with-network-connection)

* [Detect Regasm with no Command Line Arguments](detections.md#detect-regasm-with-no-command-line-arguments)

* [Detect Regsvcs Spawning a Process](detections.md#detect-regsvcs-spawning-a-process)

* [Detect Regsvcs with Network Connection](detections.md#detect-regsvcs-with-network-connection)

* [Detect Regsvcs with No Command Line Arguments](detections.md#detect-regsvcs-with-no-command-line-arguments)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1218.009 | Regsvcs/Regasm | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://attack.mitre.org/techniques/T1218/009/

* https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/evasion/windows/applocker_evasion_regasm_regsvcs.md

* https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/


_version_: 1
</details>

---

### Suspicious Regsvr32 Activity
Monitor and detect techniques used by attackers who leverage the regsvr32.exe process to execute malicious code.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1218.010](https://attack.mitre.org/techniques/T1218.010/)
- **Last Updated**: 2021-01-29

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect Regsvr32 Application Control Bypass](detections.md#detect-regsvr32-application-control-bypass)

* [Suspicious Regsvr32 Register Suspicious Path](detections.md#suspicious-regsvr32-register-suspicious-path)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1218.010 | Regsvr32 | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://attack.mitre.org/techniques/T1218/010/

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md

* https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/


_version_: 1
</details>

---

### Suspicious Rundll32 Activity
Monitor and detect techniques used by attackers who leverage rundll32.exe to execute arbitrary malicious code.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1003.001](https://attack.mitre.org/techniques/T1003.001/), [T1036.003](https://attack.mitre.org/techniques/T1036.003/), [T1218.011](https://attack.mitre.org/techniques/T1218.011/)
- **Last Updated**: 2021-02-03

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect Rundll32 Application Control Bypass - advpack](detections.md#detect-rundll32-application-control-bypass---advpack)

* [Detect Rundll32 Application Control Bypass - setupapi](detections.md#detect-rundll32-application-control-bypass---setupapi)

* [Detect Rundll32 Application Control Bypass - syssetup](detections.md#detect-rundll32-application-control-bypass---syssetup)

* [Dump LSASS via comsvcs DLL](detections.md#dump-lsass-via-comsvcs-dll)

* [Suspicious Rundll32 Rename](detections.md#suspicious-rundll32-rename)

* [Suspicious Rundll32 StartW](detections.md#suspicious-rundll32-startw)

* [Suspicious Rundll32 dllregisterserver](detections.md#suspicious-rundll32-dllregisterserver)

* [Suspicious Rundll32 no CommandLine Arguments](detections.md#suspicious-rundll32-no-commandline-arguments)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1218.011 | Rundll32 | Defense Evasion |
| T1003.001 | LSASS Memory | Credential Access |
| T1036.003 | Rename System Utilities | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://attack.mitre.org/techniques/T1218/011/

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md

* https://lolbas-project.github.io/lolbas/Binaries/Rundll32


_version_: 1
</details>

---

### Suspicious WMI Use
Attackers are increasingly abusing Windows Management Instrumentation (WMI), a framework and associated utilities available on all modern Windows operating systems. Because WMI can be leveraged to manage both local and remote systems, it is important to identify the processes executed and the user context within which the activity occurred.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1047](https://attack.mitre.org/techniques/T1047/), [T1546.003](https://attack.mitre.org/techniques/T1546.003/)
- **Last Updated**: 2018-10-23

<details>
  <summary>details</summary>

#### Detection Profile

* [Process Execution via WMI](detections.md#process-execution-via-wmi)

* [Remote Process Instantiation via WMI](detections.md#remote-process-instantiation-via-wmi)

* [Remote WMI Command Attempt](detections.md#remote-wmi-command-attempt)

* [Script Execution via WMI](detections.md#script-execution-via-wmi)

* [WMI Permanent Event Subscription](detections.md#wmi-permanent-event-subscription)

* [WMI Permanent Event Subscription - Sysmon](detections.md#wmi-permanent-event-subscription---sysmon)

* [WMI Temporary Event Subscription](detections.md#wmi-temporary-event-subscription)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1047 | Windows Management Instrumentation | Execution |
| T1546.003 | Windows Management Instrumentation Event Subscription | Persistence, Privilege Escalation |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf

* https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html


_version_: 2
</details>

---

### Suspicious Windows Registry Activities
Monitor and detect registry changes initiated from remote locations, which can be a sign that an attacker has infiltrated your system.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1546.001](https://attack.mitre.org/techniques/T1546.001/), [T1546.011](https://attack.mitre.org/techniques/T1546.011/), [T1546.012](https://attack.mitre.org/techniques/T1546.012/), [T1547.001](https://attack.mitre.org/techniques/T1547.001/), [T1547.010](https://attack.mitre.org/techniques/T1547.010/), [T1548.002](https://attack.mitre.org/techniques/T1548.002/), [T1564.001](https://attack.mitre.org/techniques/T1564.001/)
- **Last Updated**: 2018-05-31

<details>
  <summary>details</summary>

#### Detection Profile

* [Disabling Remote User Account Control](detections.md#disabling-remote-user-account-control)

* [Monitor Registry Keys for Print Monitors](detections.md#monitor-registry-keys-for-print-monitors)

* [Reg exe used to hide files directories via registry keys](detections.md#reg-exe-used-to-hide-files-directories-via-registry-keys)

* [Registry Keys Used For Persistence](detections.md#registry-keys-used-for-persistence)

* [Registry Keys Used For Privilege Escalation](detections.md#registry-keys-used-for-privilege-escalation)

* [Registry Keys for Creating SHIM Databases](detections.md#registry-keys-for-creating-shim-databases)

* [Remote Registry Key modifications](detections.md#remote-registry-key-modifications)

* [Suspicious Changes to File Associations](detections.md#suspicious-changes-to-file-associations)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1548.002 | Bypass User Account Control | Defense Evasion, Privilege Escalation |
| T1222.001 | Windows File and Directory Permissions Modification | Defense Evasion |
| T1547.010 | Port Monitors | Persistence, Privilege Escalation |
| T1564.001 | Hidden Files and Directories | Defense Evasion |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation |
| T1546.012 | Image File Execution Options Injection | Persistence, Privilege Escalation |
| T1546.011 | Application Shimming | Persistence, Privilege Escalation |
| T1546.001 | Change Default File Association | Persistence, Privilege Escalation |
| T1112 | Modify Registry | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://redcanary.com/blog/windows-registry-attacks-threat-detection/

* https://attack.mitre.org/wiki/Technique/T1112


_version_: 1
</details>

---

### Suspicious Zoom Child Processes
Attackers are using Zoom as an vector to increase privileges on a sytems. This story detects new child processes of zoom and provides investigative actions for this detection.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1059.003](https://attack.mitre.org/techniques/T1059.003/), [T1068](https://attack.mitre.org/techniques/T1068/)
- **Last Updated**: 2020-04-13

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect Prohibited Applications Spawning cmd exe](detections.md#detect-prohibited-applications-spawning-cmd-exe)

* [First Time Seen Child Process of Zoom](detections.md#first-time-seen-child-process-of-zoom)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1059.003 | Windows Command Shell | Execution |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
| T1059.001 | PowerShell | Execution |
| T1036.003 | Rename System Utilities | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives

* Exploitation


#### Reference

* https://blog.rapid7.com/2020/04/02/dispelling-zoom-bugbears-what-you-need-to-know-about-the-latest-zoom-vulnerabilities/

* https://threatpost.com/two-zoom-zero-day-flaws-uncovered/154337/


_version_: 1
</details>

---

### Trusted Developer Utilities Proxy Execution
Monitor and detect behaviors used by attackers who leverage trusted developer utilities to execute malicious code.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1036.003](https://attack.mitre.org/techniques/T1036.003/), [T1127](https://attack.mitre.org/techniques/T1127/)
- **Last Updated**: 2021-01-12

<details>
  <summary>details</summary>

#### Detection Profile

* [Suspicious microsoft workflow compiler rename](detections.md#suspicious-microsoft-workflow-compiler-rename)

* [Suspicious microsoft workflow compiler usage](detections.md#suspicious-microsoft-workflow-compiler-usage)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1127 | Trusted Developer Utilities Proxy Execution | Defense Evasion |
| T1036.003 | Rename System Utilities | Defense Evasion |

#### Kill Chain Phase

* Exploitation


#### Reference

* https://attack.mitre.org/techniques/T1127/

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md

* https://lolbas-project.github.io/lolbas/Binaries/Microsoft.Workflow.Compiler/


_version_: 1
</details>

---

### Trusted Developer Utilities Proxy Execution MSBuild
Monitor and detect techniques used by attackers who leverage the msbuild.exe process to execute malicious code.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1036.003](https://attack.mitre.org/techniques/T1036.003/), [T1127.001](https://attack.mitre.org/techniques/T1127.001/)
- **Last Updated**: 2021-01-21

<details>
  <summary>details</summary>

#### Detection Profile

* [Suspicious MSBuild Rename](detections.md#suspicious-msbuild-rename)

* [Suspicious MSBuild Spawn](detections.md#suspicious-msbuild-spawn)

* [Suspicious msbuild path](detections.md#suspicious-msbuild-path)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1127.001 | MSBuild | Defense Evasion |
| T1036.003 | Rename System Utilities | Defense Evasion |

#### Kill Chain Phase

* Exploitation


#### Reference

* https://attack.mitre.org/techniques/T1127/001/

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1127.001/T1127.001.md

* https://github.com/infosecn1nja/MaliciousMacroMSBuild

* https://github.com/xorrior/RandomPS-Scripts/blob/master/Invoke-ExecuteMSBuild.ps1

* https://lolbas-project.github.io/lolbas/Binaries/Msbuild/

* https://github.com/MHaggis/CBR-Queries/blob/master/msbuild.md


_version_: 1
</details>

---

### Windows DNS SIGRed CVE-2020-1350
Uncover activity consistent with CVE-2020-1350, or SIGRed. Discovered by Checkpoint researchers, this vulnerability affects Windows 2003 to 2019, and is triggered by a malicious DNS response (only affects DNS over TCP). An attacker can use the malicious payload to cause a buffer overflow on the vulnerable system, leading to compromise.  The included searches in this Analytic Story are designed to identify the large response payload for SIG and KEY DNS records which can be used for the exploit.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Network_Resolution
- **ATT&CK**: [T1203](https://attack.mitre.org/techniques/T1203/)
- **Last Updated**: 2020-07-28

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect Windows DNS SIGRed via Splunk Stream](detections.md#detect-windows-dns-sigred-via-splunk-stream)

* [Detect Windows DNS SIGRed via Zeek](detections.md#detect-windows-dns-sigred-via-zeek)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1203 | Exploitation for Client Execution | Execution |

#### Kill Chain Phase

* Exploitation


#### Reference

* https://research.checkpoint.com/2020/resolving-your-way-into-domain-admin-exploiting-a-17-year-old-bug-in-windows-dns-servers/

* https://support.microsoft.com/en-au/help/4569509/windows-dns-server-remote-code-execution-vulnerability


_version_: 1
</details>

---

### Windows Defense Evasion Tactics
Detect tactics used by malware to evade defenses on Windows endpoints. A few of these include suspicious `reg.exe` processes, files hidden with `attrib.exe` and disabling user-account control, among many others 

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1112](https://attack.mitre.org/techniques/T1112/), [T1222.001](https://attack.mitre.org/techniques/T1222.001/), [T1548.002](https://attack.mitre.org/techniques/T1548.002/), [T1564.001](https://attack.mitre.org/techniques/T1564.001/)
- **Last Updated**: 2018-05-31

<details>
  <summary>details</summary>

#### Detection Profile

* [Disabling Remote User Account Control](detections.md#disabling-remote-user-account-control)

* [Hiding Files And Directories With Attrib exe](detections.md#hiding-files-and-directories-with-attrib-exe)

* [Reg exe used to hide files directories via registry keys](detections.md#reg-exe-used-to-hide-files-directories-via-registry-keys)

* [Remote Registry Key modifications](detections.md#remote-registry-key-modifications)

* [Suspicious Reg exe Process](detections.md#suspicious-reg-exe-process)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1548.002 | Bypass User Account Control | Defense Evasion, Privilege Escalation |
| T1222.001 | Windows File and Directory Permissions Modification | Defense Evasion |
| T1547.010 | Port Monitors | Persistence, Privilege Escalation |
| T1564.001 | Hidden Files and Directories | Defense Evasion |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation |
| T1546.012 | Image File Execution Options Injection | Persistence, Privilege Escalation |
| T1546.011 | Application Shimming | Persistence, Privilege Escalation |
| T1546.001 | Change Default File Association | Persistence, Privilege Escalation |
| T1112 | Modify Registry | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://attack.mitre.org/wiki/Defense_Evasion


_version_: 1
</details>

---

### Windows Log Manipulation
Adversaries often try to cover their tracks by manipulating Windows logs. Use these searches to help you monitor for suspicious activity surrounding log files--an essential component of an effective defense.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1070](https://attack.mitre.org/techniques/T1070/), [T1070.001](https://attack.mitre.org/techniques/T1070.001/), [T1490](https://attack.mitre.org/techniques/T1490/)
- **Last Updated**: 2017-09-12

<details>
  <summary>details</summary>

#### Detection Profile

* [Deleting Shadow Copies](detections.md#deleting-shadow-copies)

* [Suspicious wevtutil Usage](detections.md#suspicious-wevtutil-usage)

* [USN Journal Deletion](detections.md#usn-journal-deletion)

* [Windows Event Log Cleared](detections.md#windows-event-log-cleared)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1490 | Inhibit System Recovery | Impact |
| T1070.001 | Clear Windows Event Logs | Defense Evasion |
| T1070 | Indicator Removal on Host | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/

* https://zeltser.com/security-incident-log-review-checklist/

* http://journeyintoir.blogspot.com/2013/01/re-introducing-usnjrnl.html


_version_: 2
</details>

---

### Windows Persistence Techniques
Monitor for activities and techniques associated with maintaining persistence on a Windows system--a sign that an adversary may have compromised your environment.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1053.005](https://attack.mitre.org/techniques/T1053.005/), [T1222.001](https://attack.mitre.org/techniques/T1222.001/), [T1543.003](https://attack.mitre.org/techniques/T1543.003/), [T1546.011](https://attack.mitre.org/techniques/T1546.011/), [T1547.001](https://attack.mitre.org/techniques/T1547.001/), [T1547.010](https://attack.mitre.org/techniques/T1547.010/), [T1564.001](https://attack.mitre.org/techniques/T1564.001/), [T1574.009](https://attack.mitre.org/techniques/T1574.009/), [T1574.011](https://attack.mitre.org/techniques/T1574.011/)
- **Last Updated**: 2018-05-31

<details>
  <summary>details</summary>

#### Detection Profile

* [Certutil exe certificate extraction](detections.md#certutil-exe-certificate-extraction)

* [Detect Path Interception By Creation Of program exe](detections.md#detect-path-interception-by-creation-of-program-exe)

* [Hiding Files And Directories With Attrib exe](detections.md#hiding-files-and-directories-with-attrib-exe)

* [Monitor Registry Keys for Print Monitors](detections.md#monitor-registry-keys-for-print-monitors)

* [Reg exe Manipulating Windows Services Registry Keys](detections.md#reg-exe-manipulating-windows-services-registry-keys)

* [Reg exe used to hide files directories via registry keys](detections.md#reg-exe-used-to-hide-files-directories-via-registry-keys)

* [Registry Keys Used For Persistence](detections.md#registry-keys-used-for-persistence)

* [Registry Keys for Creating SHIM Databases](detections.md#registry-keys-for-creating-shim-databases)

* [Remote Registry Key modifications](detections.md#remote-registry-key-modifications)

* [Sc exe Manipulating Windows Services](detections.md#sc-exe-manipulating-windows-services)

* [Schtasks used for forcing a reboot](detections.md#schtasks-used-for-forcing-a-reboot)

* [Shim Database File Creation](detections.md#shim-database-file-creation)

* [Shim Database Installation With Suspicious Parameters](detections.md#shim-database-installation-with-suspicious-parameters)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1574.009 | Path Interception by Unquoted Path | Defense Evasion, Persistence, Privilege Escalation |
| T1222.001 | Windows File and Directory Permissions Modification | Defense Evasion |
| T1547.010 | Port Monitors | Persistence, Privilege Escalation |
| T1574.011 | Services Registry Permissions Weakness | Defense Evasion, Persistence, Privilege Escalation |
| T1564.001 | Hidden Files and Directories | Defense Evasion |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation |
| T1546.011 | Application Shimming | Persistence, Privilege Escalation |
| T1543.003 | Windows Service | Persistence, Privilege Escalation |
| T1053.005 | Scheduled Task | Execution, Persistence, Privilege Escalation |

#### Kill Chain Phase

* Actions on Objectives

* Installation


#### Reference

* http://www.fuzzysecurity.com/tutorials/19.html

* https://www.fireeye.com/blog/threat-research/2010/07/malware-persistence-windows-registry.html

* http://resources.infosecinstitute.com/common-malware-persistence-mechanisms/

* https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html

* https://www.youtube.com/watch?v=dq2Hv7J9fvk


_version_: 2
</details>

---

### Windows Privilege Escalation
Monitor for and investigate activities that may be associated with a Windows privilege-escalation attack, including unusual processes running on endpoints, modified registry keys, and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1068](https://attack.mitre.org/techniques/T1068/), [T1204.002](https://attack.mitre.org/techniques/T1204.002/), [T1546.008](https://attack.mitre.org/techniques/T1546.008/), [T1546.012](https://attack.mitre.org/techniques/T1546.012/)
- **Last Updated**: 2020-02-04

<details>
  <summary>details</summary>

#### Detection Profile

* [Child Processes of Spoolsv exe](detections.md#child-processes-of-spoolsv-exe)

* [Overwriting Accessibility Binaries](detections.md#overwriting-accessibility-binaries)

* [Registry Keys Used For Privilege Escalation](detections.md#registry-keys-used-for-privilege-escalation)

* [Uncommon Processes On Endpoint](detections.md#uncommon-processes-on-endpoint)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
| T1546.008 | Accessibility Features | Persistence, Privilege Escalation |
| T1546.012 | Image File Execution Options Injection | Persistence, Privilege Escalation |
| T1204.002 | Malicious File | Execution |

#### Kill Chain Phase

* Actions on Objectives

* Exploitation


#### Reference

* https://attack.mitre.org/tactics/TA0004/


_version_: 2
</details>

---

</details>

## Best Practices
<details>
  <summary>details</summary>

### Asset Tracking
Keep a careful inventory of every asset on your network to make it easier to detect rogue devices. Unauthorized/unmanaged devices could be an indication of malicious behavior that should be investigated further.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Network_Sessions
- **ATT&CK**: 
- **Last Updated**: 2017-09-13

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect Unauthorized Assets by MAC address](detections.md#detect-unauthorized-assets-by-mac-address)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|

#### Kill Chain Phase

* Actions on Objectives

* Delivery

* Reconnaissance


#### Reference

* https://www.cisecurity.org/controls/inventory-of-authorized-and-unauthorized-devices/


_version_: 1
</details>

---

### Monitor Backup Solution
Address common concerns when monitoring your backup processes. These searches can help you reduce risks from ransomware, device theft, or denial of physical access to a host by backing up data on endpoints.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: 
- **Last Updated**: 2017-09-12

<details>
  <summary>details</summary>

#### Detection Profile

* [Extended Period Without Successful Netbackup Backups](detections.md#extended-period-without-successful-netbackup-backups)

* [Unsuccessful Netbackup backups](detections.md#unsuccessful-netbackup-backups)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|

#### Kill Chain Phase


#### Reference

* https://www.carbonblack.com/2016/03/04/tracking-locky-ransomware-using-carbon-black/


_version_: 1
</details>

---

### Monitor for Unauthorized Software
Identify and investigate prohibited/unauthorized software or processes that may be concealing malicious behavior within your environment. 

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: 
- **Last Updated**: 2017-09-15

<details>
  <summary>details</summary>

#### Detection Profile

* [Prohibited Software On Endpoint](detections.md#prohibited-software-on-endpoint)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Installation


#### Reference

* https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/


_version_: 1
</details>

---

### Monitor for Updates
Monitor your enterprise to ensure that your endpoints are being patched and updated. Adversaries notoriously exploit known vulnerabilities that could be mitigated by applying routine security patches.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Updates
- **ATT&CK**: 
- **Last Updated**: 2017-09-15

<details>
  <summary>details</summary>

#### Detection Profile

* [No Windows Updates in a time frame](detections.md#no-windows-updates-in-a-time-frame)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|

#### Kill Chain Phase


#### Reference

* https://learn.cisecurity.org/20-controls-download


_version_: 1
</details>

---

### Prohibited Traffic Allowed or Protocol Mismatch
Detect instances of prohibited network traffic allowed in the environment, as well as protocols running on non-standard ports. Both of these types of behaviors typically violate policy and can be leveraged by attackers.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Network_Resolution, Network_Traffic
- **ATT&CK**: [T1048](https://attack.mitre.org/techniques/T1048/), [T1048.003](https://attack.mitre.org/techniques/T1048.003/), [T1071.001](https://attack.mitre.org/techniques/T1071.001/), [T1189](https://attack.mitre.org/techniques/T1189/)
- **Last Updated**: 2017-09-11

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect hosts connecting to dynamic domain providers](detections.md#detect-hosts-connecting-to-dynamic-domain-providers)

* [Prohibited Network Traffic Allowed](detections.md#prohibited-network-traffic-allowed)

* [Protocol or Port Mismatch](detections.md#protocol-or-port-mismatch)

* [TOR Traffic](detections.md#tor-traffic)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1189 | Drive-by Compromise | Initial Access |
| T1071.001 | Web Protocols | Command and Control |
| T1048.003 | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Delivery


#### Reference

* http://www.novetta.com/2015/02/advanced-methods-to-detect-advanced-cyber-attacks-protocol-abuse/


_version_: 1
</details>

---

### Router and Infrastructure Security
Validate the security configuration of network infrastructure and verify that only authorized users and systems are accessing critical assets. Core routing and switching infrastructure are common strategic targets for attackers.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Authentication, Network_Traffic
- **ATT&CK**: [T1020.001](https://attack.mitre.org/techniques/T1020.001/), [T1200](https://attack.mitre.org/techniques/T1200/), [T1498](https://attack.mitre.org/techniques/T1498/), [T1542.005](https://attack.mitre.org/techniques/T1542.005/), [T1557](https://attack.mitre.org/techniques/T1557/), [T1557.002](https://attack.mitre.org/techniques/T1557.002/)
- **Last Updated**: 2017-09-12

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect ARP Poisoning](detections.md#detect-arp-poisoning)

* [Detect IPv6 Network Infrastructure Threats](detections.md#detect-ipv6-network-infrastructure-threats)

* [Detect New Login Attempts to Routers](detections.md#detect-new-login-attempts-to-routers)

* [Detect Port Security Violation](detections.md#detect-port-security-violation)

* [Detect Rogue DHCP Server](detections.md#detect-rogue-dhcp-server)

* [Detect Software Download To Network Device](detections.md#detect-software-download-to-network-device)

* [Detect Traffic Mirroring](detections.md#detect-traffic-mirroring)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1200 | Hardware Additions | Initial Access |
| T1498 | Network Denial of Service | Impact |
| T1557.002 | ARP Cache Poisoning | Collection, Credential Access |
| T1557 | Man-in-the-Middle | Collection, Credential Access |
| T1542.005 | TFTP Boot | Defense Evasion, Persistence |
| T1020.001 | Traffic Duplication | Exfiltration |

#### Kill Chain Phase

* Actions on Objectives

* Delivery

* Exploitation

* Reconnaissance


#### Reference

* https://www.fireeye.com/blog/executive-perspective/2015/09/the_new_route_toper.html

* https://www.cisco.com/c/en/us/about/security-center/event-response/synful-knock.html


_version_: 1
</details>

---

### Use of Cleartext Protocols
Leverage searches that detect cleartext network protocols that may leak credentials or should otherwise be encrypted.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Network_Traffic
- **ATT&CK**: 
- **Last Updated**: 2017-09-15

<details>
  <summary>details</summary>

#### Detection Profile

* [Protocols passing authentication in cleartext](detections.md#protocols-passing-authentication-in-cleartext)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|

#### Kill Chain Phase

* Actions on Objectives

* Reconnaissance


#### Reference

* https://www.monkey.org/~dugsong/dsniff/


_version_: 1
</details>

---

</details>

## Cloud Security
<details>
  <summary>details</summary>

### AWS Cross Account Activity
Track when a user assumes an IAM role in another AWS account to obtain cross-account access to services and resources in that account. Accessing new roles could be an indication of malicious activity.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1078](https://attack.mitre.org/techniques/T1078/), [T1550](https://attack.mitre.org/techniques/T1550/)
- **Last Updated**: 2018-06-04

<details>
  <summary>details</summary>

#### Detection Profile

* [aws detect attach to role policy](detections.md#aws-detect-attach-to-role-policy)

* [aws detect permanent key creation](detections.md#aws-detect-permanent-key-creation)

* [aws detect role creation](detections.md#aws-detect-role-creation)

* [aws detect sts assume role abuse](detections.md#aws-detect-sts-assume-role-abuse)

* [aws detect sts get session token abuse](detections.md#aws-detect-sts-get-session-token-abuse)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1078 | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |
| T1550 | Use Alternate Authentication Material | Defense Evasion, Lateral Movement |

#### Kill Chain Phase

* Lateral Movement


#### Reference

* https://aws.amazon.com/blogs/security/aws-cloudtrail-now-tracks-cross-account-activity-to-its-origin/


_version_: 1
</details>

---

### AWS Cryptomining
Monitor your AWS EC2 instances for activities related to cryptojacking/cryptomining. New instances that originate from previously unseen regions, users who launch abnormally high numbers of instances, or EC2 instances started by previously unseen users are just a few examples of potentially malicious behavior.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1078.004](https://attack.mitre.org/techniques/T1078.004/), [T1535](https://attack.mitre.org/techniques/T1535/)
- **Last Updated**: 2018-03-08

<details>
  <summary>details</summary>

#### Detection Profile

* [Abnormally High AWS Instances Launched by User](detections.md#abnormally-high-aws-instances-launched-by-user)

* [Abnormally High AWS Instances Launched by User - MLTK](detections.md#abnormally-high-aws-instances-launched-by-user---mltk)

* [EC2 Instance Started In Previously Unseen Region](detections.md#ec2-instance-started-in-previously-unseen-region)

* [EC2 Instance Started With Previously Unseen AMI](detections.md#ec2-instance-started-with-previously-unseen-ami)

* [EC2 Instance Started With Previously Unseen Instance Type](detections.md#ec2-instance-started-with-previously-unseen-instance-type)

* [EC2 Instance Started With Previously Unseen User](detections.md#ec2-instance-started-with-previously-unseen-user)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1078.004 | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |
| T1535 | Unused/Unsupported Cloud Regions | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf


_version_: 1
</details>

---

### AWS Network ACL Activity
Monitor your AWS network infrastructure for bad configurations and malicious activity. Investigative searches help you probe deeper, when the facts warrant it.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1562.007](https://attack.mitre.org/techniques/T1562.007/)
- **Last Updated**: 2018-05-21

<details>
  <summary>details</summary>

#### Detection Profile

* [AWS Network Access Control List Created with All Open Ports](detections.md#aws-network-access-control-list-created-with-all-open-ports)

* [AWS Network Access Control List Deleted](detections.md#aws-network-access-control-list-deleted)

* [Detect Spike in Network ACL Activity](detections.md#detect-spike-in-network-acl-activity)

* [Detect Spike in blocked Outbound Traffic from your AWS](detections.md#detect-spike-in-blocked-outbound-traffic-from-your-aws)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1562.007 | Disable or Modify Cloud Firewall | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control


#### Reference

* https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Appendix_NACLs.html

* https://aws.amazon.com/blogs/security/how-to-help-prepare-for-ddos-attacks-by-reducing-your-attack-surface/


_version_: 2
</details>

---

### AWS Security Hub Alerts
This story is focused around detecting Security Hub alerts generated from AWS

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: 
- **Last Updated**: 2020-08-04

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect Spike in AWS Security Hub Alerts for EC2 Instance](detections.md#detect-spike-in-aws-security-hub-alerts-for-ec2-instance)

* [Detect Spike in AWS Security Hub Alerts for User](detections.md#detect-spike-in-aws-security-hub-alerts-for-user)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|

#### Kill Chain Phase


#### Reference

* https://aws.amazon.com/security-hub/features/


_version_: 1
</details>

---

### AWS Suspicious Provisioning Activities
Monitor your AWS provisioning activities for behaviors originating from unfamiliar or unusual locations. These behaviors may indicate that malicious activities are occurring somewhere within your network.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1535](https://attack.mitre.org/techniques/T1535/)
- **Last Updated**: 2018-03-16

<details>
  <summary>details</summary>

#### Detection Profile

* [AWS Cloud Provisioning From Previously Unseen City](detections.md#aws-cloud-provisioning-from-previously-unseen-city)

* [AWS Cloud Provisioning From Previously Unseen Country](detections.md#aws-cloud-provisioning-from-previously-unseen-country)

* [AWS Cloud Provisioning From Previously Unseen IP Address](detections.md#aws-cloud-provisioning-from-previously-unseen-ip-address)

* [AWS Cloud Provisioning From Previously Unseen Region](detections.md#aws-cloud-provisioning-from-previously-unseen-region)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1535 | Unused/Unsupported Cloud Regions | Defense Evasion |

#### Kill Chain Phase


#### Reference

* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf


_version_: 1
</details>

---

### AWS User Monitoring
Detect and investigate dormant user accounts for your AWS environment that have become active again. Because inactive and ad-hoc accounts are common attack targets, it's critical to enable governance within your environment.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1078.004](https://attack.mitre.org/techniques/T1078.004/)
- **Last Updated**: 2018-03-12

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect API activity from users without MFA](detections.md#detect-api-activity-from-users-without-mfa)

* [Detect AWS API Activities From Unapproved Accounts](detections.md#detect-aws-api-activities-from-unapproved-accounts)

* [Detect Spike in AWS API Activity](detections.md#detect-spike-in-aws-api-activity)

* [Detect Spike in Security Group Activity](detections.md#detect-spike-in-security-group-activity)

* [Detect new API calls from user roles](detections.md#detect-new-api-calls-from-user-roles)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1078.004 | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf

* https://redlock.io/blog/cryptojacking-tesla


_version_: 1
</details>

---

### Cloud Cryptomining
Monitor your cloud compute instances for activities related to cryptojacking/cryptomining. New instances that originate from previously unseen regions, users who launch abnormally high numbers of instances, or compute instances started by previously unseen users are just a few examples of potentially malicious behavior.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Change
- **ATT&CK**: [T1078.004](https://attack.mitre.org/techniques/T1078.004/), [T1535](https://attack.mitre.org/techniques/T1535/)
- **Last Updated**: 2019-10-02

<details>
  <summary>details</summary>

#### Detection Profile

* [Abnormally High Number Of Cloud Instances Launched](detections.md#abnormally-high-number-of-cloud-instances-launched)

* [Cloud Compute Instance Created By Previously Unseen User](detections.md#cloud-compute-instance-created-by-previously-unseen-user)

* [Cloud Compute Instance Created In Previously Unused Region](detections.md#cloud-compute-instance-created-in-previously-unused-region)

* [Cloud Compute Instance Created With Previously Unseen Image](detections.md#cloud-compute-instance-created-with-previously-unseen-image)

* [Cloud Compute Instance Created With Previously Unseen Instance Type](detections.md#cloud-compute-instance-created-with-previously-unseen-instance-type)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1078.004 | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |
| T1535 | Unused/Unsupported Cloud Regions | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf


_version_: 1
</details>

---

### Cloud Federated Credential Abuse
This analytical story addresses events that indicate abuse of cloud federated credentials. These credentials are usually extracted from endpoint desktop or servers specially those servers that provide federation services such as Windows Active Directory Federation Services. Identity Federation relies on objects such as Oauth2 tokens, cookies or SAML assertions in order to provide seamless access between cloud and perimeter environments. If these objects are either hijacked or forged then attackers will be able to pivot into victim's cloud environements.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1003.001](https://attack.mitre.org/techniques/T1003.001/), [T1078](https://attack.mitre.org/techniques/T1078/), [T1136.003](https://attack.mitre.org/techniques/T1136.003/), [T1204.002](https://attack.mitre.org/techniques/T1204.002/), [T1546.012](https://attack.mitre.org/techniques/T1546.012/), [T1556](https://attack.mitre.org/techniques/T1556/)
- **Last Updated**: 2021-01-26

<details>
  <summary>details</summary>

#### Detection Profile

* [AWS SAML Access by Provider User and Principal](detections.md#aws-saml-access-by-provider-user-and-principal)

* [AWS SAML Update identity provider](detections.md#aws-saml-update-identity-provider)

* [Certutil exe certificate extraction](detections.md#certutil-exe-certificate-extraction)

* [Detect Mimikatz Using Loaded Images](detections.md#detect-mimikatz-using-loaded-images)

* [Detect Mimikatz Via PowerShell And EventCode 4703](detections.md#detect-mimikatz-via-powershell-and-eventcode-4703)

* [Detect Rare Executables](detections.md#detect-rare-executables)

* [O365 Add App Role Assignment Grant User](detections.md#o365-add-app-role-assignment-grant-user)

* [O365 Added Service Principal](detections.md#o365-added-service-principal)

* [O365 Excessive SSO logon errors](detections.md#o365-excessive-sso-logon-errors)

* [O365 New Federated Domain Added](detections.md#o365-new-federated-domain-added)

* [Registry Keys Used For Privilege Escalation](detections.md#registry-keys-used-for-privilege-escalation)

* [Uncommon Processes On Endpoint](detections.md#uncommon-processes-on-endpoint)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1078 | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |
| T1003.001 | LSASS Memory | Credential Access |
| T1136.003 | Cloud Account | Persistence |
| T1556 | Modify Authentication Process | Credential Access, Defense Evasion |
| T1546.012 | Image File Execution Options Injection | Persistence, Privilege Escalation |
| T1204.002 | Malicious File | Execution |

#### Kill Chain Phase

* Actions on Objective

* Actions on Objectives

* Command and Control

* Installation


#### Reference

* https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps

* https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf

* https://us-cert.cisa.gov/ncas/alerts/aa21-008a


_version_: 1
</details>

---

### Container Implantation Monitoring and Investigation
Use the searches in this story to monitor your Kubernetes registry repositories for upload, and deployment of potentially vulnerable, backdoor, or implanted containers. These searches provide information on source users, destination path, container names and repository names. The searches provide context to address Mitre T1525 which refers to container implantation upload to a company's repository either in Amazon Elastic Container Registry, Google Container Registry and Azure Container Registry.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1525](https://attack.mitre.org/techniques/T1525/)
- **Last Updated**: 2020-02-20

<details>
  <summary>details</summary>

#### Detection Profile

* [GCP GCR container uploaded](detections.md#gcp-gcr-container-uploaded)

* [New container uploaded to AWS ECR](detections.md#new-container-uploaded-to-aws-ecr)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1525 | Implant Container Image | Persistence |

#### Kill Chain Phase


#### Reference

* https://github.com/splunk/cloud-datamodel-security-research


_version_: 1
</details>

---

### GCP Cross Account Activity
Track when a user assumes an IAM role in another GCP account to obtain cross-account access to services and resources in that account. Accessing new roles could be an indication of malicious activity.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1078](https://attack.mitre.org/techniques/T1078/)
- **Last Updated**: 2020-09-01

<details>
  <summary>details</summary>

#### Detection Profile

* [GCP Detect accounts with high risk roles by project](detections.md#gcp-detect-accounts-with-high-risk-roles-by-project)

* [GCP Detect gcploit framework](detections.md#gcp-detect-gcploit-framework)

* [GCP Detect high risk permissions by resource and account](detections.md#gcp-detect-high-risk-permissions-by-resource-and-account)

* [gcp detect oauth token abuse](detections.md#gcp-detect-oauth-token-abuse)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1078 | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Kill Chain Phase

* Lateral Movement


#### Reference

* https://cloud.google.com/iam/docs/understanding-service-accounts


_version_: 1
</details>

---

### Kubernetes Scanning Activity
This story addresses detection against Kubernetes cluster fingerprint scan and attack by providing information on items such as source ip, user agent, cluster names.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1526](https://attack.mitre.org/techniques/T1526/)
- **Last Updated**: 2020-04-15

<details>
  <summary>details</summary>

#### Detection Profile

* [Amazon EKS Kubernetes Pod scan detection](detections.md#amazon-eks-kubernetes-pod-scan-detection)

* [Amazon EKS Kubernetes cluster scan detection](detections.md#amazon-eks-kubernetes-cluster-scan-detection)

* [GCP Kubernetes cluster pod scan detection](detections.md#gcp-kubernetes-cluster-pod-scan-detection)

* [GCP Kubernetes cluster scan detection](detections.md#gcp-kubernetes-cluster-scan-detection)

* [Kubernetes Azure pod scan fingerprint](detections.md#kubernetes-azure-pod-scan-fingerprint)

* [Kubernetes Azure scan fingerprint](detections.md#kubernetes-azure-scan-fingerprint)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1526 | Cloud Service Discovery | Discovery |

#### Kill Chain Phase

* Reconnaissance


#### Reference

* https://github.com/splunk/cloud-datamodel-security-research


_version_: 1
</details>

---

### Kubernetes Sensitive Object Access Activity
This story addresses detection and response of accounts acccesing Kubernetes cluster sensitive objects such as configmaps or secrets providing information on items such as user user, group. object, namespace and authorization reason.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: 
- **Last Updated**: 2020-05-20

<details>
  <summary>details</summary>

#### Detection Profile

* [AWS EKS Kubernetes cluster sensitive object access](detections.md#aws-eks-kubernetes-cluster-sensitive-object-access)

* [Kubernetes AWS detect service accounts forbidden failure access](detections.md#kubernetes-aws-detect-service-accounts-forbidden-failure-access)

* [Kubernetes AWS detect suspicious kubectl calls](detections.md#kubernetes-aws-detect-suspicious-kubectl-calls)

* [Kubernetes Azure detect sensitive object access](detections.md#kubernetes-azure-detect-sensitive-object-access)

* [Kubernetes Azure detect service accounts forbidden failure access](detections.md#kubernetes-azure-detect-service-accounts-forbidden-failure-access)

* [Kubernetes Azure detect suspicious kubectl calls](detections.md#kubernetes-azure-detect-suspicious-kubectl-calls)

* [Kubernetes GCP detect sensitive object access](detections.md#kubernetes-gcp-detect-sensitive-object-access)

* [Kubernetes GCP detect service accounts forbidden failure access](detections.md#kubernetes-gcp-detect-service-accounts-forbidden-failure-access)

* [Kubernetes GCP detect suspicious kubectl calls](detections.md#kubernetes-gcp-detect-suspicious-kubectl-calls)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|

#### Kill Chain Phase

* Lateral Movement


#### Reference

* https://www.splunk.com/en_us/blog/security/approaching-kubernetes-security-detecting-kubernetes-scan-with-splunk.html


_version_: 1
</details>

---

### Kubernetes Sensitive Role Activity
This story addresses detection and response around Sensitive Role usage within a Kubernetes clusters against cluster resources and namespaces.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: 
- **Last Updated**: 2020-05-20

<details>
  <summary>details</summary>

#### Detection Profile

* [Kubernetes AWS detect RBAC authorization by account](detections.md#kubernetes-aws-detect-rbac-authorization-by-account)

* [Kubernetes AWS detect most active service accounts by pod](detections.md#kubernetes-aws-detect-most-active-service-accounts-by-pod)

* [Kubernetes AWS detect sensitive role access](detections.md#kubernetes-aws-detect-sensitive-role-access)

* [Kubernetes Azure detect RBAC authorization by account](detections.md#kubernetes-azure-detect-rbac-authorization-by-account)

* [Kubernetes Azure detect most active service accounts by pod namespace](detections.md#kubernetes-azure-detect-most-active-service-accounts-by-pod-namespace)

* [Kubernetes Azure detect sensitive role access](detections.md#kubernetes-azure-detect-sensitive-role-access)

* [Kubernetes GCP detect RBAC authorizations by account](detections.md#kubernetes-gcp-detect-rbac-authorizations-by-account)

* [Kubernetes GCP detect most active service accounts by pod](detections.md#kubernetes-gcp-detect-most-active-service-accounts-by-pod)

* [Kubernetes GCP detect sensitive role access](detections.md#kubernetes-gcp-detect-sensitive-role-access)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|

#### Kill Chain Phase

* Lateral Movement


#### Reference

* https://www.splunk.com/en_us/blog/security/approaching-kubernetes-security-detecting-kubernetes-scan-with-splunk.html


_version_: 1
</details>

---

### Office 365 Detections
This story is focused around detecting Office 365 Attacks.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1110](https://attack.mitre.org/techniques/T1110/), [T1110.001](https://attack.mitre.org/techniques/T1110.001/), [T1114](https://attack.mitre.org/techniques/T1114/), [T1114.002](https://attack.mitre.org/techniques/T1114.002/), [T1114.003](https://attack.mitre.org/techniques/T1114.003/), [T1136.003](https://attack.mitre.org/techniques/T1136.003/), [T1556](https://attack.mitre.org/techniques/T1556/), [T1562.007](https://attack.mitre.org/techniques/T1562.007/)
- **Last Updated**: 2020-12-16

<details>
  <summary>details</summary>

#### Detection Profile

* [High Number of Login Failures from a single source](detections.md#high-number-of-login-failures-from-a-single-source)

* [O365 Add App Role Assignment Grant User](detections.md#o365-add-app-role-assignment-grant-user)

* [O365 Added Service Principal](detections.md#o365-added-service-principal)

* [O365 Bypass MFA via Trusted IP](detections.md#o365-bypass-mfa-via-trusted-ip)

* [O365 Disable MFA](detections.md#o365-disable-mfa)

* [O365 Excessive Authentication Failures Alert](detections.md#o365-excessive-authentication-failures-alert)

* [O365 Excessive SSO logon errors](detections.md#o365-excessive-sso-logon-errors)

* [O365 New Federated Domain Added](detections.md#o365-new-federated-domain-added)

* [O365 PST export alert](detections.md#o365-pst-export-alert)

* [O365 Suspicious Admin Email Forwarding](detections.md#o365-suspicious-admin-email-forwarding)

* [O365 Suspicious Rights Delegation](detections.md#o365-suspicious-rights-delegation)

* [O365 Suspicious User Email Forwarding](detections.md#o365-suspicious-user-email-forwarding)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1110.001 | Password Guessing | Credential Access |
| T1136.003 | Cloud Account | Persistence |
| T1562.007 | Disable or Modify Cloud Firewall | Defense Evasion |
| T1556 | Modify Authentication Process | Credential Access, Defense Evasion |
| T1110 | Brute Force | Credential Access |
| T1114 | Email Collection | Collection |
| T1114.003 | Email Forwarding Rule | Collection |
| T1114.002 | Remote Email Collection | Collection |

#### Kill Chain Phase

* Actions on Objective

* Actions on Objectives

* Not Applicable


#### Reference

* https://i.blackhat.com/USA-20/Thursday/us-20-Bienstock-My-Cloud-Is-APTs-Cloud-Investigating-And-Defending-Office-365.pdf


_version_: 1
</details>

---

### Suspicious AWS EC2 Activities
Use the searches in this Analytic Story to monitor your AWS EC2 instances for evidence of anomalous activity and suspicious behaviors, such as EC2 instances that originate from unusual locations or those launched by previously unseen users (among others). Included investigative searches will help you probe more deeply, when the information warrants it.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1078.004](https://attack.mitre.org/techniques/T1078.004/), [T1535](https://attack.mitre.org/techniques/T1535/)
- **Last Updated**: 2018-02-09

<details>
  <summary>details</summary>

#### Detection Profile

* [Abnormally High AWS Instances Launched by User](detections.md#abnormally-high-aws-instances-launched-by-user)

* [Abnormally High AWS Instances Launched by User - MLTK](detections.md#abnormally-high-aws-instances-launched-by-user---mltk)

* [Abnormally High AWS Instances Terminated by User](detections.md#abnormally-high-aws-instances-terminated-by-user)

* [Abnormally High AWS Instances Terminated by User - MLTK](detections.md#abnormally-high-aws-instances-terminated-by-user---mltk)

* [EC2 Instance Started In Previously Unseen Region](detections.md#ec2-instance-started-in-previously-unseen-region)

* [EC2 Instance Started With Previously Unseen User](detections.md#ec2-instance-started-with-previously-unseen-user)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1078.004 | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |
| T1535 | Unused/Unsupported Cloud Regions | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf


_version_: 1
</details>

---

### Suspicious AWS Login Activities
Monitor your AWS authentication events using your CloudTrail logs. Searches within this Analytic Story will help you stay aware of and investigate suspicious logins. 

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Authentication
- **ATT&CK**: [T1078.004](https://attack.mitre.org/techniques/T1078.004/), [T1535](https://attack.mitre.org/techniques/T1535/)
- **Last Updated**: 2019-05-01

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect AWS Console Login by User from New City](detections.md#detect-aws-console-login-by-user-from-new-city)

* [Detect AWS Console Login by User from New Country](detections.md#detect-aws-console-login-by-user-from-new-country)

* [Detect AWS Console Login by User from New Region](detections.md#detect-aws-console-login-by-user-from-new-region)

* [Detect new user AWS Console Login](detections.md#detect-new-user-aws-console-login)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1535 | Unused/Unsupported Cloud Regions | Defense Evasion |
| T1078.004 | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html


_version_: 1
</details>

---

### Suspicious AWS S3 Activities
Use the searches in this Analytic Story to monitor your AWS S3 buckets for evidence of anomalous activity and suspicious behaviors, such as detecting open S3 buckets and buckets being accessed from a new IP. The contextual and investigative searches will give you more information, when required.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1530](https://attack.mitre.org/techniques/T1530/)
- **Last Updated**: 2018-07-24

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect New Open S3 Buckets over AWS CLI](detections.md#detect-new-open-s3-buckets-over-aws-cli)

* [Detect New Open S3 buckets](detections.md#detect-new-open-s3-buckets)

* [Detect S3 access from a new IP](detections.md#detect-s3-access-from-a-new-ip)

* [Detect Spike in S3 Bucket deletion](detections.md#detect-spike-in-s3-bucket-deletion)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1530 | Data from Cloud Storage Object | Collection |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf

* https://www.tripwire.com/state-of-security/security-data-protection/cloud/public-aws-s3-buckets-writable/


_version_: 2
</details>

---

### Suspicious AWS Traffic
Leverage these searches to monitor your AWS network traffic for evidence of anomalous activity and suspicious behaviors, such as a spike in blocked outbound traffic in your virtual private cloud (VPC).

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: 
- **Last Updated**: 2018-05-07

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect Spike in blocked Outbound Traffic from your AWS](detections.md#detect-spike-in-blocked-outbound-traffic-from-your-aws)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|

#### Kill Chain Phase

* Actions on Objectives

* Command and Control


#### Reference

* https://rhinosecuritylabs.com/aws/hiding-cloudcobalt-strike-beacon-c2-using-amazon-apis/


_version_: 1
</details>

---

### Suspicious Cloud Authentication Activities
Monitor your cloud authentication events. Searches within this Analytic Story leverage the recent cloud updates to the Authentication data model to help you stay aware of and investigate suspicious login activity. 

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Authentication
- **ATT&CK**: [T1535](https://attack.mitre.org/techniques/T1535/)
- **Last Updated**: 2020-06-04

<details>
  <summary>details</summary>

#### Detection Profile

* [AWS Cross Account Activity From Previously Unseen Account](detections.md#aws-cross-account-activity-from-previously-unseen-account)

* [Detect AWS Console Login by New User](detections.md#detect-aws-console-login-by-new-user)

* [Detect AWS Console Login by User from New City](detections.md#detect-aws-console-login-by-user-from-new-city)

* [Detect AWS Console Login by User from New Country](detections.md#detect-aws-console-login-by-user-from-new-country)

* [Detect AWS Console Login by User from New Region](detections.md#detect-aws-console-login-by-user-from-new-region)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1535 | Unused/Unsupported Cloud Regions | Defense Evasion |
| T1078.004 | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://aws.amazon.com/blogs/security/aws-cloudtrail-now-tracks-cross-account-activity-to-its-origin/

* https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html


_version_: 1
</details>

---

### Suspicious Cloud Instance Activities
Monitor your cloud infrastructure provisioning activities for behaviors originating from unfamiliar or unusual locations. These behaviors may indicate that malicious activities are occurring somewhere within your cloud environment.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Change
- **ATT&CK**: [T1078.004](https://attack.mitre.org/techniques/T1078.004/)
- **Last Updated**: 2020-08-25

<details>
  <summary>details</summary>

#### Detection Profile

* [Abnormally High Number Of Cloud Instances Destroyed](detections.md#abnormally-high-number-of-cloud-instances-destroyed)

* [Abnormally High Number Of Cloud Instances Launched](detections.md#abnormally-high-number-of-cloud-instances-launched)

* [Cloud Instance Modified By Previously Unseen User](detections.md#cloud-instance-modified-by-previously-unseen-user)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1078.004 | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf


_version_: 1
</details>

---

### Suspicious Cloud Provisioning Activities
Monitor your cloud infrastructure provisioning activities for behaviors originating from unfamiliar or unusual locations. These behaviors may indicate that malicious activities are occurring somewhere within your cloud environment.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Change
- **ATT&CK**: [T1078](https://attack.mitre.org/techniques/T1078/)
- **Last Updated**: 2018-08-20

<details>
  <summary>details</summary>

#### Detection Profile

* [Cloud Provisioning Activity From Previously Unseen City](detections.md#cloud-provisioning-activity-from-previously-unseen-city)

* [Cloud Provisioning Activity From Previously Unseen Country](detections.md#cloud-provisioning-activity-from-previously-unseen-country)

* [Cloud Provisioning Activity From Previously Unseen IP Address](detections.md#cloud-provisioning-activity-from-previously-unseen-ip-address)

* [Cloud Provisioning Activity From Previously Unseen Region](detections.md#cloud-provisioning-activity-from-previously-unseen-region)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1078 | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Kill Chain Phase


#### Reference

* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf


_version_: 1
</details>

---

### Suspicious Cloud User Activities
Detect and investigate suspicious activities by users and roles in your cloud environments.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Change
- **ATT&CK**: [T1078](https://attack.mitre.org/techniques/T1078/), [T1078.004](https://attack.mitre.org/techniques/T1078.004/)
- **Last Updated**: 2020-09-04

<details>
  <summary>details</summary>

#### Detection Profile

* [Abnormally High Number Of Cloud Infrastructure API Calls](detections.md#abnormally-high-number-of-cloud-infrastructure-api-calls)

* [Abnormally High Number Of Cloud Security Group API Calls](detections.md#abnormally-high-number-of-cloud-security-group-api-calls)

* [Cloud API Calls From Previously Unseen User Roles](detections.md#cloud-api-calls-from-previously-unseen-user-roles)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1078.004 | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |
| T1078 | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf

* https://redlock.io/blog/cryptojacking-tesla


_version_: 1
</details>

---

### Suspicious GCP Storage Activities
Use the searches in this Analytic Story to monitor your GCP Storage buckets for evidence of anomalous activity and suspicious behaviors, such as detecting open storage buckets and buckets being accessed from a new IP. The contextual and investigative searches will give you more information, when required.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1530](https://attack.mitre.org/techniques/T1530/)
- **Last Updated**: 2020-08-05

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect GCP Storage access from a new IP](detections.md#detect-gcp-storage-access-from-a-new-ip)

* [Detect New Open GCP Storage Buckets](detections.md#detect-new-open-gcp-storage-buckets)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1530 | Data from Cloud Storage Object | Collection |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://cloud.google.com/blog/product/gcp/4-steps-for-hardening-your-cloud-storage-buckets-taking-charge-of-your-security

* https://rhinosecuritylabs.com/gcp/google-cloud-platform-gcp-bucket-enumeration/


_version_: 1
</details>

---

### Unusual AWS EC2 Modifications
Identify unusual changes to your AWS EC2 instances that may indicate malicious activity. Modifications to your EC2 instances by previously unseen users is an example of an activity that may warrant further investigation.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1078.004](https://attack.mitre.org/techniques/T1078.004/)
- **Last Updated**: 2018-04-09

<details>
  <summary>details</summary>

#### Detection Profile

* [EC2 Instance Modified With Previously Unseen User](detections.md#ec2-instance-modified-with-previously-unseen-user)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1078.004 | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Kill Chain Phase


#### Reference

* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf


_version_: 1
</details>

---

</details>

## Malware
<details>
  <summary>details</summary>

### ColdRoot MacOS RAT
Leverage searches that allow you to detect and investigate unusual activities that relate to the ColdRoot Remote Access Trojan that affects MacOS. An example of some of these activities are changing sensative binaries in the MacOS sub-system, detecting process names and executables associated with the RAT, detecting when a keyboard tab is installed on a MacOS machine and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: 
- **Last Updated**: 2019-01-09

<details>
  <summary>details</summary>

#### Detection Profile

* [Osquery pack - ColdRoot detection](detections.md#osquery-pack---coldroot-detection)

* [Processes Tapping Keyboard Events](detections.md#processes-tapping-keyboard-events)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|

#### Kill Chain Phase

* Command and Control

* Installation


#### Reference

* https://www.intego.com/mac-security-blog/osxcoldroot-and-the-rat-invasion/

* https://objective-see.com/blog/blog_0x2A.html

* https://www.bleepingcomputer.com/news/security/coldroot-rat-still-undetectable-despite-being-uploaded-on-github-two-years-ago/


_version_: 1
</details>

---

### DHS Report TA18-074A
Monitor for suspicious activities associated with DHS Technical Alert US-CERT TA18-074A. Some of the activities that adversaries used in these compromises included spearfishing attacks, malware, watering-hole domains, many and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint, Network_Traffic
- **ATT&CK**: [T1021.002](https://attack.mitre.org/techniques/T1021.002/), [T1053.005](https://attack.mitre.org/techniques/T1053.005/), [T1059.001](https://attack.mitre.org/techniques/T1059.001/), [T1059.003](https://attack.mitre.org/techniques/T1059.003/), [T1071.002](https://attack.mitre.org/techniques/T1071.002/), [T1112](https://attack.mitre.org/techniques/T1112/), [T1136.001](https://attack.mitre.org/techniques/T1136.001/), [T1204.002](https://attack.mitre.org/techniques/T1204.002/), [T1543.003](https://attack.mitre.org/techniques/T1543.003/), [T1547.001](https://attack.mitre.org/techniques/T1547.001/), [T1562.004](https://attack.mitre.org/techniques/T1562.004/)
- **Last Updated**: 2020-01-22

<details>
  <summary>details</summary>

#### Detection Profile

* [Create local admin accounts using net exe](detections.md#create-local-admin-accounts-using-net-exe)

* [Detect New Local Admin account](detections.md#detect-new-local-admin-account)

* [Detect Outbound SMB Traffic](detections.md#detect-outbound-smb-traffic)

* [Detect PsExec With accepteula Flag](detections.md#detect-psexec-with-accepteula-flag)

* [First time seen command line argument](detections.md#first-time-seen-command-line-argument)

* [Malicious PowerShell Process - Execution Policy Bypass](detections.md#malicious-powershell-process---execution-policy-bypass)

* [Processes launching netsh](detections.md#processes-launching-netsh)

* [Registry Keys Used For Persistence](detections.md#registry-keys-used-for-persistence)

* [SMB Traffic Spike](detections.md#smb-traffic-spike)

* [SMB Traffic Spike - MLTK](detections.md#smb-traffic-spike---mltk)

* [Sc exe Manipulating Windows Services](detections.md#sc-exe-manipulating-windows-services)

* [Scheduled Task Deleted Or Created via CMD](detections.md#scheduled-task-deleted-or-created-via-cmd)

* [Single Letter Process On Endpoint](detections.md#single-letter-process-on-endpoint)

* [Suspicious Reg exe Process](detections.md#suspicious-reg-exe-process)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1136.001 | Local Account | Persistence |
| T1071.002 | File Transfer Protocols | Command and Control |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| T1059.001 | PowerShell | Execution |
| T1059.003 | Windows Command Shell | Execution |
| T1562.004 | Disable or Modify System Firewall | Defense Evasion |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation |
| T1543.003 | Windows Service | Persistence, Privilege Escalation |
| T1053.005 | Scheduled Task | Execution, Persistence, Privilege Escalation |
| T1204.002 | Malicious File | Execution |
| T1112 | Modify Registry | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Installation


#### Reference

* https://www.us-cert.gov/ncas/alerts/TA18-074A


_version_: 2
</details>

---

### Dynamic DNS
Detect and investigate hosts in your environment that may be communicating with dynamic domain providers. Attackers may leverage these services to help them avoid firewall blocks and deny lists.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Network_Resolution, Web
- **ATT&CK**: [T1071.001](https://attack.mitre.org/techniques/T1071.001/), [T1189](https://attack.mitre.org/techniques/T1189/)
- **Last Updated**: 2018-09-06

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect hosts connecting to dynamic domain providers](detections.md#detect-hosts-connecting-to-dynamic-domain-providers)

* [Detect web traffic to dynamic domain providers](detections.md#detect-web-traffic-to-dynamic-domain-providers)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1189 | Drive-by Compromise | Initial Access |
| T1071.001 | Web Protocols | Command and Control |
| T1048.003 | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control


#### Reference

* https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html

* https://umbrella.cisco.com/blog/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/

* http://www.noip.com/blog/2014/07/11/dynamic-dns-can-use-2/

* https://www.splunk.com/blog/2015/08/04/detecting-dynamic-dns-domains-in-splunk.html


_version_: 2
</details>

---

### Emotet Malware  DHS Report TA18-201A 
Detect rarely used executables, specific registry paths that may confer malware survivability and persistence, instances where cmd.exe is used to launch script interpreters, and other indicators that the Emotet financial malware has compromised your environment.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Email, Endpoint, Network_Traffic
- **ATT&CK**: [T1021.002](https://attack.mitre.org/techniques/T1021.002/), [T1059.003](https://attack.mitre.org/techniques/T1059.003/), [T1072](https://attack.mitre.org/techniques/T1072/), [T1547.001](https://attack.mitre.org/techniques/T1547.001/), [T1566.001](https://attack.mitre.org/techniques/T1566.001/)
- **Last Updated**: 2020-01-27

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect Rare Executables](detections.md#detect-rare-executables)

* [Detect Use of cmd exe to Launch Script Interpreters](detections.md#detect-use-of-cmd-exe-to-launch-script-interpreters)

* [Detection of tools built by NirSoft](detections.md#detection-of-tools-built-by-nirsoft)

* [Email Attachments With Lots Of Spaces](detections.md#email-attachments-with-lots-of-spaces)

* [Prohibited Software On Endpoint](detections.md#prohibited-software-on-endpoint)

* [Registry Keys Used For Persistence](detections.md#registry-keys-used-for-persistence)

* [SMB Traffic Spike](detections.md#smb-traffic-spike)

* [SMB Traffic Spike - MLTK](detections.md#smb-traffic-spike---mltk)

* [Suspicious Email Attachment Extensions](detections.md#suspicious-email-attachment-extensions)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1059.003 | Windows Command Shell | Execution |
| T1072 | Software Deployment Tools | Execution, Lateral Movement |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| T1566.001 | Spearphishing Attachment | Initial Access |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Delivery

* Exploitation

* Installation


#### Reference

* https://www.us-cert.gov/ncas/alerts/TA18-201A

* https://www.first.org/resources/papers/conf2017/Advanced-Incident-Detection-and-Threat-Hunting-using-Sysmon-and-Splunk.pdf

* https://www.vkremez.com/2017/05/emotet-banking-trojan-malware-analysis.html


_version_: 1
</details>

---

### Hidden Cobra Malware
Monitor for and investigate activities, including the creation or deletion of hidden shares and file writes, that may be evidence of infiltration by North Korean government-sponsored cybercriminals. Details of this activity were reported in DHS Report TA-18-149A.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint, Network_Resolution, Network_Traffic
- **ATT&CK**: [T1021.001](https://attack.mitre.org/techniques/T1021.001/), [T1021.002](https://attack.mitre.org/techniques/T1021.002/), [T1048.003](https://attack.mitre.org/techniques/T1048.003/), [T1059.001](https://attack.mitre.org/techniques/T1059.001/), [T1059.003](https://attack.mitre.org/techniques/T1059.003/), [T1070.005](https://attack.mitre.org/techniques/T1070.005/), [T1071.002](https://attack.mitre.org/techniques/T1071.002/), [T1071.004](https://attack.mitre.org/techniques/T1071.004/)
- **Last Updated**: 2020-01-22

<details>
  <summary>details</summary>

#### Detection Profile

* [Create or delete windows shares using net exe](detections.md#create-or-delete-windows-shares-using-net-exe)

* [DNS Query Length Outliers - MLTK](detections.md#dns-query-length-outliers---mltk)

* [DNS Query Length With High Standard Deviation](detections.md#dns-query-length-with-high-standard-deviation)

* [Detect Outbound SMB Traffic](detections.md#detect-outbound-smb-traffic)

* [First time seen command line argument](detections.md#first-time-seen-command-line-argument)

* [Remote Desktop Network Traffic](detections.md#remote-desktop-network-traffic)

* [Remote Desktop Process Running On System](detections.md#remote-desktop-process-running-on-system)

* [SMB Traffic Spike](detections.md#smb-traffic-spike)

* [SMB Traffic Spike - MLTK](detections.md#smb-traffic-spike---mltk)

* [Suspicious File Write](detections.md#suspicious-file-write)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1070.005 | Network Share Connection Removal | Defense Evasion |
| T1071.004 | DNS | Command and Control |
| T1048.003 | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |
| T1071.002 | File Transfer Protocols | Command and Control |
| T1059.001 | PowerShell | Execution |
| T1059.003 | Windows Command Shell | Execution |
| T1021.001 | Remote Desktop Protocol | Lateral Movement |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control


#### Reference

* https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity

* https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Destructive-Malware-Report.pdf


_version_: 2
</details>

---

### Orangeworm Attack Group
Detect activities and various techniques associated with the Orangeworm Attack Group, a group that frequently targets the healthcare industry.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1059.001](https://attack.mitre.org/techniques/T1059.001/), [T1059.003](https://attack.mitre.org/techniques/T1059.003/), [T1543.003](https://attack.mitre.org/techniques/T1543.003/), [T1569.002](https://attack.mitre.org/techniques/T1569.002/)
- **Last Updated**: 2020-01-22

<details>
  <summary>details</summary>

#### Detection Profile

* [First Time Seen Running Windows Service](detections.md#first-time-seen-running-windows-service)

* [First time seen command line argument](detections.md#first-time-seen-command-line-argument)

* [Sc exe Manipulating Windows Services](detections.md#sc-exe-manipulating-windows-services)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1569.002 | Service Execution | Execution |
| T1059.001 | PowerShell | Execution |
| T1059.003 | Windows Command Shell | Execution |
| T1574.011 | Services Registry Permissions Weakness | Defense Evasion, Persistence, Privilege Escalation |
| T1543.003 | Windows Service | Persistence, Privilege Escalation |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Installation


#### Reference

* https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia

* https://www.infosecurity-magazine.com/news/healthcare-targeted-by-hacker/


_version_: 2
</details>

---

### Ransomware
Leverage searches that allow you to detect and investigate unusual activities that might relate to ransomware--spikes in SMB traffic, suspicious wevtutil usage, the presence of common ransomware extensions, and system processes run from unexpected locations, and many others.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint, Network_Traffic
- **ATT&CK**: [T1021.002](https://attack.mitre.org/techniques/T1021.002/), [T1036.003](https://attack.mitre.org/techniques/T1036.003/), [T1047](https://attack.mitre.org/techniques/T1047/), [T1048](https://attack.mitre.org/techniques/T1048/), [T1053.005](https://attack.mitre.org/techniques/T1053.005/), [T1070](https://attack.mitre.org/techniques/T1070/), [T1070.001](https://attack.mitre.org/techniques/T1070.001/), [T1071.001](https://attack.mitre.org/techniques/T1071.001/), [T1485](https://attack.mitre.org/techniques/T1485/), [T1490](https://attack.mitre.org/techniques/T1490/), [T1547.001](https://attack.mitre.org/techniques/T1547.001/)
- **Last Updated**: 2020-02-04

<details>
  <summary>details</summary>

#### Detection Profile

* [BCDEdit Failure Recovery Modification](detections.md#bcdedit-failure-recovery-modification)

* [Common Ransomware Extensions](detections.md#common-ransomware-extensions)

* [Common Ransomware Notes](detections.md#common-ransomware-notes)

* [Deleting Shadow Copies](detections.md#deleting-shadow-copies)

* [Prohibited Network Traffic Allowed](detections.md#prohibited-network-traffic-allowed)

* [Registry Keys Used For Persistence](detections.md#registry-keys-used-for-persistence)

* [Remote Process Instantiation via WMI](detections.md#remote-process-instantiation-via-wmi)

* [SMB Traffic Spike](detections.md#smb-traffic-spike)

* [SMB Traffic Spike - MLTK](detections.md#smb-traffic-spike---mltk)

* [Scheduled tasks used in BadRabbit ransomware](detections.md#scheduled-tasks-used-in-badrabbit-ransomware)

* [Schtasks used for forcing a reboot](detections.md#schtasks-used-for-forcing-a-reboot)

* [Spike in File Writes](detections.md#spike-in-file-writes)

* [Suspicious wevtutil Usage](detections.md#suspicious-wevtutil-usage)

* [System Processes Run From Unexpected Locations](detections.md#system-processes-run-from-unexpected-locations)

* [TOR Traffic](detections.md#tor-traffic)

* [USN Journal Deletion](detections.md#usn-journal-deletion)

* [Unusually Long Command Line](detections.md#unusually-long-command-line)

* [Unusually Long Command Line - MLTK](detections.md#unusually-long-command-line---mltk)

* [WBAdmin Delete System Backups](detections.md#wbadmin-delete-system-backups)

* [Windows Event Log Cleared](detections.md#windows-event-log-cleared)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1490 | Inhibit System Recovery | Impact |
| T1485 | Data Destruction | Impact |
| T1482 | Domain Trust Discovery | Discovery |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation |
| T1021.001 | Remote Desktop Protocol | Lateral Movement |
| T1047 | Windows Management Instrumentation | Execution |
| T1486 | Data Encrypted for Impact | Impact |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| T1053.005 | Scheduled Task | Execution, Persistence, Privilege Escalation |
| T1070.001 | Clear Windows Event Logs | Defense Evasion |
| T1036.003 | Rename System Utilities | Defense Evasion |
| T1071.001 | Web Protocols | Command and Control |
| T1070 | Indicator Removal on Host | Defense Evasion |
| T1562.001 | Disable or Modify Tools | Defense Evasion |
| T1489 | Service Stop | Impact |
| T1059.003 | Windows Command Shell | Execution |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Delivery


#### Reference

* https://www.carbonblack.com/2017/06/28/carbon-black-threat-research-technical-analysis-petya-notpetya-ransomware/

* https://www.splunk.com/blog/2017/06/27/closing-the-detection-to-mitigation-gap-or-to-petya-or-notpetya-whocares-.html


_version_: 1
</details>

---

### Ransomware Cloud
Leverage searches that allow you to detect and investigate unusual activities that might relate to ransomware. These searches include cloud related objects that may be targeted by malicious actors via cloud providers own encryption features.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1486](https://attack.mitre.org/techniques/T1486/)
- **Last Updated**: 2020-10-27

<details>
  <summary>details</summary>

#### Detection Profile

* [AWS Detect Users creating keys with encrypt policy without MFA](detections.md#aws-detect-users-creating-keys-with-encrypt-policy-without-mfa)

* [AWS Detect Users with KMS keys performing encryption S3](detections.md#aws-detect-users-with-kms-keys-performing-encryption-s3)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1486 | Data Encrypted for Impact | Impact |

#### Kill Chain Phase


#### Reference

* https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/

* https://github.com/d1vious/git-wild-hunt

* https://www.youtube.com/watch?v=PgzNib37g0M


_version_: 1
</details>

---

### Ryuk Ransomware
Leverage searches that allow you to detect and investigate unusual activities that might relate to the Ryuk ransomware, including looking for file writes associated with Ryuk, Stopping Security Access Manager, DisableAntiSpyware registry key modification, suspicious psexec use, and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint, Network_Traffic
- **ATT&CK**: [T1021.001](https://attack.mitre.org/techniques/T1021.001/), [T1059.003](https://attack.mitre.org/techniques/T1059.003/), [T1482](https://attack.mitre.org/techniques/T1482/), [T1485](https://attack.mitre.org/techniques/T1485/), [T1486](https://attack.mitre.org/techniques/T1486/), [T1489](https://attack.mitre.org/techniques/T1489/), [T1490](https://attack.mitre.org/techniques/T1490/), [T1562.001](https://attack.mitre.org/techniques/T1562.001/)
- **Last Updated**: 2020-11-06

<details>
  <summary>details</summary>

#### Detection Profile

* [BCDEdit Failure Recovery Modification](detections.md#bcdedit-failure-recovery-modification)

* [Common Ransomware Notes](detections.md#common-ransomware-notes)

* [NLTest Domain Trust Discovery](detections.md#nltest-domain-trust-discovery)

* [Remote Desktop Network Bruteforce](detections.md#remote-desktop-network-bruteforce)

* [Remote Desktop Network Traffic](detections.md#remote-desktop-network-traffic)

* [Ryuk Test Files Detected](detections.md#ryuk-test-files-detected)

* [Spike in File Writes](detections.md#spike-in-file-writes)

* [WBAdmin Delete System Backups](detections.md#wbadmin-delete-system-backups)

* [Windows DisableAntiSpyware Registry](detections.md#windows-disableantispyware-registry)

* [Windows Security Account Manager Stopped](detections.md#windows-security-account-manager-stopped)

* [Windows connhost exe started forcefully](detections.md#windows-connhost-exe-started-forcefully)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1490 | Inhibit System Recovery | Impact |
| T1485 | Data Destruction | Impact |
| T1482 | Domain Trust Discovery | Discovery |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation |
| T1021.001 | Remote Desktop Protocol | Lateral Movement |
| T1047 | Windows Management Instrumentation | Execution |
| T1486 | Data Encrypted for Impact | Impact |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| T1053.005 | Scheduled Task | Execution, Persistence, Privilege Escalation |
| T1070.001 | Clear Windows Event Logs | Defense Evasion |
| T1036.003 | Rename System Utilities | Defense Evasion |
| T1071.001 | Web Protocols | Command and Control |
| T1070 | Indicator Removal on Host | Defense Evasion |
| T1562.001 | Disable or Modify Tools | Defense Evasion |
| T1489 | Service Stop | Impact |
| T1059.003 | Windows Command Shell | Execution |

#### Kill Chain Phase

* Actions on Objectives

* Delivery

* Exploitation

* Reconnaissance


#### Reference

* https://www.splunk.com/en_us/blog/security/detecting-ryuk-using-splunk-attack-range.html

* https://www.crowdstrike.com/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/

* https://us-cert.cisa.gov/ncas/alerts/aa20-302a


_version_: 1
</details>

---

### SamSam Ransomware
Leverage searches that allow you to detect and investigate unusual activities that might relate to the SamSam ransomware, including looking for file writes associated with SamSam, RDP brute force attacks, the presence of files with SamSam ransomware extensions, suspicious psexec use, and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint, Network_Traffic, Web
- **ATT&CK**: [T1021.001](https://attack.mitre.org/techniques/T1021.001/), [T1021.002](https://attack.mitre.org/techniques/T1021.002/), [T1082](https://attack.mitre.org/techniques/T1082/), [T1204.002](https://attack.mitre.org/techniques/T1204.002/), [T1485](https://attack.mitre.org/techniques/T1485/), [T1486](https://attack.mitre.org/techniques/T1486/), [T1490](https://attack.mitre.org/techniques/T1490/)
- **Last Updated**: 2018-12-13

<details>
  <summary>details</summary>

#### Detection Profile

* [Batch File Write to System32](detections.md#batch-file-write-to-system32)

* [Common Ransomware Extensions](detections.md#common-ransomware-extensions)

* [Common Ransomware Notes](detections.md#common-ransomware-notes)

* [Deleting Shadow Copies](detections.md#deleting-shadow-copies)

* [Detect PsExec With accepteula Flag](detections.md#detect-psexec-with-accepteula-flag)

* [Detect attackers scanning for vulnerable JBoss servers](detections.md#detect-attackers-scanning-for-vulnerable-jboss-servers)

* [Detect malicious requests to exploit JBoss servers](detections.md#detect-malicious-requests-to-exploit-jboss-servers)

* [File with Samsam Extension](detections.md#file-with-samsam-extension)

* [Prohibited Software On Endpoint](detections.md#prohibited-software-on-endpoint)

* [Remote Desktop Network Bruteforce](detections.md#remote-desktop-network-bruteforce)

* [Remote Desktop Network Traffic](detections.md#remote-desktop-network-traffic)

* [Samsam Test File Write](detections.md#samsam-test-file-write)

* [Spike in File Writes](detections.md#spike-in-file-writes)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1204.002 | Malicious File | Execution |
| T1485 | Data Destruction | Impact |
| T1490 | Inhibit System Recovery | Impact |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| T1082 | System Information Discovery | Discovery |
| T1021.001 | Remote Desktop Protocol | Lateral Movement |
| T1486 | Data Encrypted for Impact | Impact |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Delivery

* Installation

* Reconnaissance


#### Reference

* https://www.crowdstrike.com/blog/an-in-depth-analysis-of-samsam-ransomware-and-boss-spider/

* https://nakedsecurity.sophos.com/2018/07/31/samsam-the-almost-6-million-ransomware/

* https://thehackernews.com/2018/07/samsam-ransomware-attacks.html


_version_: 1
</details>

---

### Unusual Processes
Quickly identify systems running new or unusual processes in your environment that could be indicators of suspicious activity. Processes run from unusual locations, those with conspicuously long command lines, and rare executables are all examples of activities that may warrant deeper investigation.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1016](https://attack.mitre.org/techniques/T1016/), [T1036.003](https://attack.mitre.org/techniques/T1036.003/), [T1204.002](https://attack.mitre.org/techniques/T1204.002/), [T1218.011](https://attack.mitre.org/techniques/T1218.011/)
- **Last Updated**: 2020-02-04

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect Rare Executables](detections.md#detect-rare-executables)

* [Detect processes used for System Network Configuration Discovery](detections.md#detect-processes-used-for-system-network-configuration-discovery)

* [RunDLL Loading DLL By Ordinal](detections.md#rundll-loading-dll-by-ordinal)

* [System Processes Run From Unexpected Locations](detections.md#system-processes-run-from-unexpected-locations)

* [Uncommon Processes On Endpoint](detections.md#uncommon-processes-on-endpoint)

* [Unusually Long Command Line](detections.md#unusually-long-command-line)

* [Unusually Long Command Line - MLTK](detections.md#unusually-long-command-line---mltk)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1016 | System Network Configuration Discovery | Discovery |
| T1218.011 | Rundll32 | Defense Evasion |
| T1036.003 | Rename System Utilities | Defense Evasion |
| T1204.002 | Malicious File | Execution |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Installation


#### Reference

* https://www.fireeye.com/blog/threat-research/2017/08/monitoring-windows-console-activity-part-two.html

* https://www.splunk.com/pdfs/technical-briefs/advanced-threat-detection-and-response-tech-brief.pdf

* https://www.sans.org/reading-room/whitepapers/logging/detecting-security-incidents-windows-workstation-event-logs-34262


_version_: 2
</details>

---

### Windows File Extension and Association Abuse
Detect and investigate suspected abuse of file extensions and Windows file associations. Some of the malicious behaviors involved may include inserting spaces before file extensions or prepending the file extension with a different one, among other techniques.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1036.003](https://attack.mitre.org/techniques/T1036.003/), [T1546.001](https://attack.mitre.org/techniques/T1546.001/)
- **Last Updated**: 2018-01-26

<details>
  <summary>details</summary>

#### Detection Profile

* [Execution of File With Spaces Before Extension](detections.md#execution-of-file-with-spaces-before-extension)

* [Execution of File with Multiple Extensions](detections.md#execution-of-file-with-multiple-extensions)

* [Suspicious Changes to File Associations](detections.md#suspicious-changes-to-file-associations)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1036.003 | Rename System Utilities | Defense Evasion |
| T1546.001 | Change Default File Association | Persistence, Privilege Escalation |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://blog.malwarebytes.com/cybercrime/2013/12/file-extensions-2/

* https://attack.mitre.org/wiki/Technique/T1042


_version_: 1
</details>

---

### Windows Service Abuse
Windows services are often used by attackers for persistence and the ability to load drivers or otherwise interact with the Windows kernel. This Analytic Story helps you monitor your environment for indications that Windows services are being modified or created in a suspicious manner.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1543.003](https://attack.mitre.org/techniques/T1543.003/), [T1569.002](https://attack.mitre.org/techniques/T1569.002/), [T1574.011](https://attack.mitre.org/techniques/T1574.011/)
- **Last Updated**: 2017-11-02

<details>
  <summary>details</summary>

#### Detection Profile

* [First Time Seen Running Windows Service](detections.md#first-time-seen-running-windows-service)

* [Reg exe Manipulating Windows Services Registry Keys](detections.md#reg-exe-manipulating-windows-services-registry-keys)

* [Sc exe Manipulating Windows Services](detections.md#sc-exe-manipulating-windows-services)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1569.002 | Service Execution | Execution |
| T1059.001 | PowerShell | Execution |
| T1059.003 | Windows Command Shell | Execution |
| T1574.011 | Services Registry Permissions Weakness | Defense Evasion, Persistence, Privilege Escalation |
| T1543.003 | Windows Service | Persistence, Privilege Escalation |

#### Kill Chain Phase

* Actions on Objectives

* Installation


#### Reference

* https://attack.mitre.org/wiki/Technique/T1050

* https://attack.mitre.org/wiki/Technique/T1031


_version_: 3
</details>

---

</details>

## Vulnerability
<details>
  <summary>details</summary>

### Apache Struts Vulnerability
Detect and investigate activities--such as unusually long `Content-Type` length, suspicious java classes and web servers executing suspicious processes--consistent with attempts to exploit Apache Struts vulnerabilities.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1082](https://attack.mitre.org/techniques/T1082/)
- **Last Updated**: 2018-12-06

<details>
  <summary>details</summary>

#### Detection Profile

* [Suspicious Java Classes](detections.md#suspicious-java-classes)

* [Unusually Long Content-Type Length](detections.md#unusually-long-content-type-length)

* [Web Servers Executing Suspicious Processes](detections.md#web-servers-executing-suspicious-processes)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1082 | System Information Discovery | Discovery |

#### Kill Chain Phase

* Actions on Objectives

* Delivery

* Exploitation


#### Reference

* https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.2/dev/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf


_version_: 1
</details>

---

### JBoss Vulnerability
In March of 2016, adversaries were seen using JexBoss--an open-source utility used for testing and exploiting JBoss application servers. These searches help detect evidence of these attacks, such as network connections to external resources or web services spawning atypical child processes, among others.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Web
- **ATT&CK**: [T1082](https://attack.mitre.org/techniques/T1082/)
- **Last Updated**: 2017-09-14

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect attackers scanning for vulnerable JBoss servers](detections.md#detect-attackers-scanning-for-vulnerable-jboss-servers)

* [Detect malicious requests to exploit JBoss servers](detections.md#detect-malicious-requests-to-exploit-jboss-servers)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1082 | System Information Discovery | Discovery |

#### Kill Chain Phase

* Delivery

* Reconnaissance


#### Reference

* http://www.deependresearch.org/2016/04/jboss-exploits-view-from-victim.html


_version_: 1
</details>

---

### Spectre And Meltdown Vulnerabilities
Assess and mitigate your systems' vulnerability to Spectre and Meltdown exploitation with the searches in this Analytic Story.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Vulnerabilities
- **ATT&CK**: 
- **Last Updated**: 2018-01-08

<details>
  <summary>details</summary>

#### Detection Profile

* [Spectre and Meltdown Vulnerable Systems](detections.md#spectre-and-meltdown-vulnerable-systems)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|

#### Kill Chain Phase


#### Reference

* https://meltdownattack.com/


_version_: 1
</details>

---

### Splunk Enterprise Vulnerability
Keeping your Splunk deployment up to date is critical and may help you reduce the risk of CVE-2016-4859, an open-redirection vulnerability within some older versions of Splunk Enterprise. The detection search will help ensure that users are being properly authenticated and not being redirected to malicious domains.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: 
- **Last Updated**: 2017-09-19

<details>
  <summary>details</summary>

#### Detection Profile

* [Open Redirect in Splunk Web](detections.md#open-redirect-in-splunk-web)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|

#### Kill Chain Phase

* Delivery


#### Reference

* http://www.splunk.com/view/SP-CAAAPQ6#announce

* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4859


_version_: 1
</details>

---

### Splunk Enterprise Vulnerability CVE-2018-11409
Reduce the risk of CVE-2018-11409, an information disclosure vulnerability within some older versions of Splunk Enterprise, with searches designed to help ensure that your Splunk system does not leak information to authenticated users.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: 
- **Last Updated**: 2018-06-14

<details>
  <summary>details</summary>

#### Detection Profile

* [Splunk Enterprise Information Disclosure](detections.md#splunk-enterprise-information-disclosure)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|

#### Kill Chain Phase

* Delivery


#### Reference

* https://nvd.nist.gov/vuln/detail/CVE-2018-11409

* https://www.splunk.com/view/SP-CAAAP5E#VulnerabilityDescriptionsandRatings

* https://www.exploit-db.com/exploits/44865/


_version_: 1
</details>

---

</details>
