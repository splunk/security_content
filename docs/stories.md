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
- **Datamodel**: Email, Web
- **ATT&CK**: 
- **Last Updated**: 2017-12-19

<details>
  <summary>details</summary>

#### Detection Profile

* [Monitor Email For Brand Abuse](detections.md#monitor-email-for-brand-abuse)

* [Monitor Web Traffic For Brand Abuse](detections.md#monitor-web-traffic-for-brand-abuse)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|

#### Kill Chain Phase

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
- **Datamodel**: Network_Resolution
- **ATT&CK**: [T1189](https://attack.mitre.org/techniques/T1189/)
- **Last Updated**: 2017-09-14

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect hosts connecting to dynamic domain providers](detections.md#detect-hosts-connecting-to-dynamic-domain-providers)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1189 | Drive-by Compromise | Initial Access |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control


#### Reference

* https://www.cisecurity.org/controls/data-protection/

* https://www.sans.org/reading-room/whitepapers/dns/splunk-detect-dns-tunneling-37022

* https://umbrella.cisco.com/blog/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/


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

</details>

## Adversary Tactics
<details>
  <summary>details</summary>

### Active Directory Password Spraying
Monitor for activities and techniques associated with Password Spraying attacks within Active Directory environments.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1110.003](https://attack.mitre.org/techniques/T1110.003/)
- **Last Updated**: 2021-04-07

<details>
  <summary>details</summary>

#### Detection Profile

* [Multiple Disabled Users Failing To Authenticate From Host Using Kerberos](detections.md#multiple-disabled-users-failing-to-authenticate-from-host-using-kerberos)

* [Multiple Invalid Users Failing To Authenticate From Host Using Kerberos](detections.md#multiple-invalid-users-failing-to-authenticate-from-host-using-kerberos)

* [Multiple Invalid Users Failing To Authenticate From Host Using NTLM](detections.md#multiple-invalid-users-failing-to-authenticate-from-host-using-ntlm)

* [Multiple Users Attempting To Authenticate Using Explicit Credentials](detections.md#multiple-users-attempting-to-authenticate-using-explicit-credentials)

* [Multiple Users Failing To Authenticate From Host Using Kerberos](detections.md#multiple-users-failing-to-authenticate-from-host-using-kerberos)

* [Multiple Users Failing To Authenticate From Host Using NTLM](detections.md#multiple-users-failing-to-authenticate-from-host-using-ntlm)

* [Multiple Users Failing To Authenticate From Process](detections.md#multiple-users-failing-to-authenticate-from-process)

* [Multiple Users Remotely Failing To Authenticate From Host](detections.md#multiple-users-remotely-failing-to-authenticate-from-host)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1110.003 | Password Spraying | Credential Access |

#### Kill Chain Phase

* Exploitation


#### Reference

* https://attack.mitre.org/techniques/T1110/003/

* https://www.microsoft.com/security/blog/2020/04/23/protecting-organization-password-spray-attacks/

* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn452415(v=ws.11)


_version_: 1
</details>

---

### BITS Jobs
Adversaries may abuse BITS jobs to persistently execute or clean up after malicious payloads.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1105](https://attack.mitre.org/techniques/T1105/), [T1197](https://attack.mitre.org/techniques/T1197/)
- **Last Updated**: 2021-03-26

<details>
  <summary>details</summary>

#### Detection Profile

* [BITS Job Persistence](detections.md#bits-job-persistence)

* [BITSAdmin Download File](detections.md#bitsadmin-download-file)

* [PowerShell Start-BitsTransfer](detections.md#powershell-start-bitstransfer)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1197 | BITS Jobs | Defense Evasion, Persistence |
| T1105 | Ingress Tool Transfer | Command And Control |

#### Kill Chain Phase

* Exploitation


#### Reference

* https://attack.mitre.org/techniques/T1197/

* https://docs.microsoft.com/en-us/windows/win32/bits/bitsadmin-tool


_version_: 1
</details>

---

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
- **ATT&CK**: [T1036.003](https://attack.mitre.org/techniques/T1036.003/), [T1055](https://attack.mitre.org/techniques/T1055/), [T1059.003](https://attack.mitre.org/techniques/T1059.003/), [T1127](https://attack.mitre.org/techniques/T1127/), [T1127.001](https://attack.mitre.org/techniques/T1127.001/), [T1218.010](https://attack.mitre.org/techniques/T1218.010/), [T1218.011](https://attack.mitre.org/techniques/T1218.011/), [T1543.003](https://attack.mitre.org/techniques/T1543.003/), [T1548](https://attack.mitre.org/techniques/T1548/), [T1560.001](https://attack.mitre.org/techniques/T1560.001/)
- **Last Updated**: 2021-02-16

<details>
  <summary>details</summary>

#### Detection Profile

* [Anomalous usage of 7zip](detections.md#anomalous-usage-of-7zip)

* [CMD Echo Pipe - Escalation](detections.md#cmd-echo-pipe---escalation)

* [Cobalt Strike Named Pipes](detections.md#cobalt-strike-named-pipes)

* [DLLHost with no Command Line Arguments with Network](detections.md#dllhost-with-no-command-line-arguments-with-network)

* [Detect Regsvr32 Application Control Bypass](detections.md#detect-regsvr32-application-control-bypass)

* [GPUpdate with no Command Line Arguments with Network](detections.md#gpupdate-with-no-command-line-arguments-with-network)

* [Rundll32 with no Command Line Arguments with Network](detections.md#rundll32-with-no-command-line-arguments-with-network)

* [SearchProtocolHost with no Command Line with Network](detections.md#searchprotocolhost-with-no-command-line-with-network)

* [Services Escalate Exe](detections.md#services-escalate-exe)

* [Suspicious DLLHost no Command Line Arguments](detections.md#suspicious-dllhost-no-command-line-arguments)

* [Suspicious GPUpdate no Command Line Arguments](detections.md#suspicious-gpupdate-no-command-line-arguments)

* [Suspicious MSBuild Rename](detections.md#suspicious-msbuild-rename)

* [Suspicious Rundll32 StartW](detections.md#suspicious-rundll32-startw)

* [Suspicious Rundll32 no Command Line Arguments](detections.md#suspicious-rundll32-no-command-line-arguments)

* [Suspicious SearchProtocolHost no Command Line Arguments](detections.md#suspicious-searchprotocolhost-no-command-line-arguments)

* [Suspicious microsoft workflow compiler rename](detections.md#suspicious-microsoft-workflow-compiler-rename)

* [Suspicious msbuild path](detections.md#suspicious-msbuild-path)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1560.001 | Archive via Utility | Collection |
| T1059.003 | Windows Command Shell | Execution |
| T1543.003 | Windows Service | Persistence, Privilege Escalation |
| T1055 | Process Injection | Defense Evasion, Privilege Escalation |
| T1071.002 | File Transfer Protocols | Command And Control |
| T1218.010 | Regsvr32 | Defense Evasion |
| T1218.005 | Mshta | Defense Evasion |
| T1569.002 | Service Execution | Execution |
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1218.011 | Rundll32 | Defense Evasion |
| T1053.005 | Scheduled Task | Execution, Persistence, Privilege Escalation |
| T1548 | Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion |
| T1203 | Exploitation for Client Execution | Execution |
| T1505.003 | Web Shell | Persistence |
| T1127.001 | MSBuild | Defense Evasion |
| T1036.003 | Rename System Utilities | Defense Evasion |
| T1127 | Trusted Developer Utilities Proxy Execution | Defense Evasion |
| T1071.001 | Web Protocols | Command And Control |
| T1018 | Remote System Discovery | Discovery |

#### Kill Chain Phase

* Actions on Objective

* Actions on Objectives

* Exploitation

* Privilege Escalation


#### Reference

* https://www.cobaltstrike.com/

* https://www.infocyte.com/blog/2020/09/02/cobalt-strike-the-new-favorite-among-thieves/

* https://bluescreenofjeff.com/2017-01-24-how-to-write-malleable-c2-profiles-for-cobalt-strike/

* https://blog.talosintelligence.com/2020/09/coverage-strikes-back-cobalt-strike-paper.html

* https://www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html

* https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence

* https://github.com/zer0yu/Awesome-CobaltStrike


_version_: 1
</details>

---

### Collection and Staging
Monitor for and investigate activities--such as suspicious writes to the Windows Recycling Bin or email servers sending high amounts of traffic to specific hosts, for example--that may indicate that an adversary is harvesting and exfiltrating sensitive data. 

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint, Network_Traffic
- **ATT&CK**: [T1036](https://attack.mitre.org/techniques/T1036/), [T1114.001](https://attack.mitre.org/techniques/T1114.001/), [T1114.002](https://attack.mitre.org/techniques/T1114.002/), [T1560.001](https://attack.mitre.org/techniques/T1560.001/)
- **Last Updated**: 2020-02-03

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect Renamed 7-Zip](detections.md#detect-renamed-7-zip)

* [Detect Renamed WinRAR](detections.md#detect-renamed-winrar)

* [Email files written outside of the Outlook directory](detections.md#email-files-written-outside-of-the-outlook-directory)

* [Email servers sending high volume traffic to hosts](detections.md#email-servers-sending-high-volume-traffic-to-hosts)

* [Hosts receiving high volume of network traffic from email server](detections.md#hosts-receiving-high-volume-of-network-traffic-from-email-server)

* [Suspicious writes to windows Recycle Bin](detections.md#suspicious-writes-to-windows-recycle-bin)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1560.001 | Archive via Utility | Collection |
| T1114.001 | Local Email Collection | Collection |
| T1114.002 | Remote Email Collection | Collection |
| T1036 | Masquerading | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives

* Exfiltration

* Exploitation


#### Reference

* https://attack.mitre.org/wiki/Collection

* https://attack.mitre.org/wiki/Technique/T1074


_version_: 1
</details>

---

### Command and Control
Detect and investigate tactics, techniques, and procedures leveraged by attackers to establish and operate command and control channels. Implants installed by attackers on compromised endpoints use these channels to receive instructions and send data back to the malicious operators.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint, Network_Resolution, Network_Traffic
- **ATT&CK**: [T1048](https://attack.mitre.org/techniques/T1048/), [T1048.003](https://attack.mitre.org/techniques/T1048.003/), [T1071.001](https://attack.mitre.org/techniques/T1071.001/), [T1071.004](https://attack.mitre.org/techniques/T1071.004/), [T1095](https://attack.mitre.org/techniques/T1095/), [T1189](https://attack.mitre.org/techniques/T1189/)
- **Last Updated**: 2018-06-01

<details>
  <summary>details</summary>

#### Detection Profile

* [DNS Exfiltration Using Nslookup App](detections.md#dns-exfiltration-using-nslookup-app)

* [DNS Query Length Outliers - MLTK](detections.md#dns-query-length-outliers---mltk)

* [DNS Query Length With High Standard Deviation](detections.md#dns-query-length-with-high-standard-deviation)

* [Detect Large Outbound ICMP Packets](detections.md#detect-large-outbound-icmp-packets)

* [Detect Spike in blocked Outbound Traffic from your AWS](detections.md#detect-spike-in-blocked-outbound-traffic-from-your-aws)

* [Detect hosts connecting to dynamic domain providers](detections.md#detect-hosts-connecting-to-dynamic-domain-providers)

* [Excessive DNS Failures](detections.md#excessive-dns-failures)

* [Excessive Usage of NSLOOKUP App](detections.md#excessive-usage-of-nslookup-app)

* [Multiple Archive Files Http Post Traffic](detections.md#multiple-archive-files-http-post-traffic)

* [Plain HTTP POST Exfiltrated Data](detections.md#plain-http-post-exfiltrated-data)

* [Prohibited Network Traffic Allowed](detections.md#prohibited-network-traffic-allowed)

* [Protocol or Port Mismatch](detections.md#protocol-or-port-mismatch)

* [TOR Traffic](detections.md#tor-traffic)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |
| T1071.004 | DNS | Command And Control |
| T1048.003 | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |
| T1095 | Non-Application Layer Protocol | Command And Control |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1189 | Drive-by Compromise | Initial Access |
| T1114.001 | Local Email Collection | Collection |
| T1114 | Email Collection | Collection |
| T1114.003 | Email Forwarding Rule | Collection |
| T1071.001 | Web Protocols | Command And Control |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Delivery

* Exfiltration

* Exploitation


#### Reference

* https://attack.mitre.org/wiki/Command_and_Control

* https://searchsecurity.techtarget.com/feature/Command-and-control-servers-The-puppet-masters-that-govern-malware


_version_: 1
</details>

---

### Credential Dumping
Uncover activity consistent with credential dumping, a technique wherein attackers compromise systems and attempt to obtain and exfiltrate passwords. The threat actors use these pilfered credentials to further escalate privileges and spread throughout a target environment. The included searches in this Analytic Story are designed to identify attempts to credential dumping.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1003](https://attack.mitre.org/techniques/T1003/), [T1003.001](https://attack.mitre.org/techniques/T1003.001/), [T1003.002](https://attack.mitre.org/techniques/T1003.002/), [T1003.003](https://attack.mitre.org/techniques/T1003.003/), [T1055](https://attack.mitre.org/techniques/T1055/), [T1059.001](https://attack.mitre.org/techniques/T1059.001/), [T1068](https://attack.mitre.org/techniques/T1068/), [T1078](https://attack.mitre.org/techniques/T1078/), [T1087](https://attack.mitre.org/techniques/T1087/), [T1098](https://attack.mitre.org/techniques/T1098/), [T1134](https://attack.mitre.org/techniques/T1134/), [T1201](https://attack.mitre.org/techniques/T1201/), [T1543](https://attack.mitre.org/techniques/T1543/), [T1547](https://attack.mitre.org/techniques/T1547/), [T1548](https://attack.mitre.org/techniques/T1548/), [T1552](https://attack.mitre.org/techniques/T1552/), [T1554](https://attack.mitre.org/techniques/T1554/), [T1555](https://attack.mitre.org/techniques/T1555/), [T1556](https://attack.mitre.org/techniques/T1556/), [T1558](https://attack.mitre.org/techniques/T1558/), [T1558.003](https://attack.mitre.org/techniques/T1558.003/)
- **Last Updated**: 2020-02-04

<details>
  <summary>details</summary>

#### Detection Profile

* [Access LSASS Memory for Dump Creation](detections.md#access-lsass-memory-for-dump-creation)

* [Applying Stolen Credentials via Mimikatz modules](detections.md#applying-stolen-credentials-via-mimikatz-modules)

* [Applying Stolen Credentials via PowerSploit modules](detections.md#applying-stolen-credentials-via-powersploit-modules)

* [Assessment of Credential Strength via DSInternals modules](detections.md#assessment-of-credential-strength-via-dsinternals-modules)

* [Attempted Credential Dump From Registry via Reg exe](detections.md#attempted-credential-dump-from-registry-via-reg-exe)

* [Create Remote Thread into LSASS](detections.md#create-remote-thread-into-lsass)

* [Creation of Shadow Copy](detections.md#creation-of-shadow-copy)

* [Creation of Shadow Copy with wmic and powershell](detections.md#creation-of-shadow-copy-with-wmic-and-powershell)

* [Creation of lsass Dump with Taskmgr](detections.md#creation-of-lsass-dump-with-taskmgr)

* [Credential Dumping via Copy Command from Shadow Copy](detections.md#credential-dumping-via-copy-command-from-shadow-copy)

* [Credential Dumping via Symlink to Shadow Copy](detections.md#credential-dumping-via-symlink-to-shadow-copy)

* [Credential Extraction indicative of FGDump and CacheDump with s option](detections.md#credential-extraction-indicative-of-fgdump-and-cachedump-with-s-option)

* [Credential Extraction indicative of FGDump and CacheDump with v option](detections.md#credential-extraction-indicative-of-fgdump-and-cachedump-with-v-option)

* [Credential Extraction indicative of Lazagne command line options](detections.md#credential-extraction-indicative-of-lazagne-command-line-options)

* [Credential Extraction indicative of use of DSInternals credential conversion modules](detections.md#credential-extraction-indicative-of-use-of-dsinternals-credential-conversion-modules)

* [Credential Extraction indicative of use of DSInternals modules](detections.md#credential-extraction-indicative-of-use-of-dsinternals-modules)

* [Credential Extraction indicative of use of Mimikatz modules](detections.md#credential-extraction-indicative-of-use-of-mimikatz-modules)

* [Credential Extraction indicative of use of PowerSploit modules](detections.md#credential-extraction-indicative-of-use-of-powersploit-modules)

* [Credential Extraction native Microsoft debuggers peek into the kernel](detections.md#credential-extraction-native-microsoft-debuggers-peek-into-the-kernel)

* [Credential Extraction native Microsoft debuggers via z command line option](detections.md#credential-extraction-native-microsoft-debuggers-via-z-command-line-option)

* [Credential Extraction via Get-ADDBAccount module present in PowerSploit and DSInternals](detections.md#credential-extraction-via-get-addbaccount-module-present-in-powersploit-and-dsinternals)

* [Detect Credential Dumping through LSASS access](detections.md#detect-credential-dumping-through-lsass-access)

* [Detect Dump LSASS Memory using comsvcs](detections.md#detect-dump-lsass-memory-using-comsvcs)

* [Detect Kerberoasting](detections.md#detect-kerberoasting)

* [Detect Mimikatz Using Loaded Images](detections.md#detect-mimikatz-using-loaded-images)

* [Dump LSASS via comsvcs DLL](detections.md#dump-lsass-via-comsvcs-dll)

* [Dump LSASS via procdump](detections.md#dump-lsass-via-procdump)

* [Dump LSASS via procdump Rename](detections.md#dump-lsass-via-procdump-rename)

* [Extract SAM from Registry](detections.md#extract-sam-from-registry)

* [Ntdsutil Export NTDS](detections.md#ntdsutil-export-ntds)

* [SecretDumps Offline NTDS Dumping Tool](detections.md#secretdumps-offline-ntds-dumping-tool)

* [Set Default PowerShell Execution Policy To Unrestricted or Bypass](detections.md#set-default-powershell-execution-policy-to-unrestricted-or-bypass)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1003.001 | LSASS Memory | Credential Access |
| T1055 | Process Injection | Defense Evasion, Privilege Escalation |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
| T1078 | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |
| T1098 | Account Manipulation | Persistence |
| T1134 | Access Token Manipulation | Defense Evasion, Privilege Escalation |
| T1543 | Create or Modify System Process | Persistence, Privilege Escalation |
| T1547 | Boot or Logon Autostart Execution | Persistence, Privilege Escalation |
| T1548 | Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion |
| T1554 | Compromise Client Software Binary | Persistence |
| T1556 | Modify Authentication Process | Credential Access, Defense Evasion, Persistence |
| T1558 | Steal or Forge Kerberos Tickets | Credential Access |
| T1555 | Credentials from Password Stores | Credential Access |
| T1087 | Account Discovery | Discovery |
| T1201 | Password Policy Discovery | Discovery |
| T1552 | Unsecured Credentials | Credential Access |
| T1003.002 | Security Account Manager | Credential Access |
| T1003 | OS Credential Dumping | Credential Access |
| T1003.003 | NTDS | Credential Access |
| T1558.003 | Kerberoasting | Credential Access |
| T1059.001 | PowerShell | Execution |

#### Kill Chain Phase

* Actions on Objectives

* Exploitation

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
- **ATT&CK**: [T1189](https://attack.mitre.org/techniques/T1189/)
- **Last Updated**: 2020-02-04

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect hosts connecting to dynamic domain providers](detections.md#detect-hosts-connecting-to-dynamic-domain-providers)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1189 | Drive-by Compromise | Initial Access |

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
- **Datamodel**: Endpoint, Network_Traffic
- **ATT&CK**: [T1041](https://attack.mitre.org/techniques/T1041/), [T1048](https://attack.mitre.org/techniques/T1048/), [T1048.003](https://attack.mitre.org/techniques/T1048.003/), [T1114](https://attack.mitre.org/techniques/T1114/), [T1114.001](https://attack.mitre.org/techniques/T1114.001/), [T1114.003](https://attack.mitre.org/techniques/T1114.003/)
- **Last Updated**: 2020-10-21

<details>
  <summary>details</summary>

#### Detection Profile

* [DNS Exfiltration Using Nslookup App](detections.md#dns-exfiltration-using-nslookup-app)

* [Detect SNICat SNI Exfiltration](detections.md#detect-snicat-sni-exfiltration)

* [Excessive Usage of NSLOOKUP App](detections.md#excessive-usage-of-nslookup-app)

* [Mailsniper Invoke functions](detections.md#mailsniper-invoke-functions)

* [Multiple Archive Files Http Post Traffic](detections.md#multiple-archive-files-http-post-traffic)

* [O365 PST export alert](detections.md#o365-pst-export-alert)

* [O365 Suspicious Admin Email Forwarding](detections.md#o365-suspicious-admin-email-forwarding)

* [O365 Suspicious User Email Forwarding](detections.md#o365-suspicious-user-email-forwarding)

* [Plain HTTP POST Exfiltrated Data](detections.md#plain-http-post-exfiltrated-data)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |
| T1071.004 | DNS | Command And Control |
| T1048.003 | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |
| T1095 | Non-Application Layer Protocol | Command And Control |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1189 | Drive-by Compromise | Initial Access |
| T1114.001 | Local Email Collection | Collection |
| T1114 | Email Collection | Collection |
| T1114.003 | Email Forwarding Rule | Collection |
| T1071.001 | Web Protocols | Command And Control |

#### Kill Chain Phase

* Actions on Objective

* Actions on Objectives

* Exfiltration

* Exploitation


#### Reference

* https://attack.mitre.org/tactics/TA0010/


_version_: 1
</details>

---

### Deobfuscate-Decode Files or Information
Adversaries may use Obfuscated Files or Information to hide artifacts of an intrusion from analysis.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1140](https://attack.mitre.org/techniques/T1140/)
- **Last Updated**: 2021-03-24

<details>
  <summary>details</summary>

#### Detection Profile

* [CertUtil With Decode Argument](detections.md#certutil-with-decode-argument)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1140 | Deobfuscate/Decode Files or Information | Defense Evasion |

#### Kill Chain Phase

* Exploitation


#### Reference

* https://attack.mitre.org/techniques/T1140/


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

### Domain Trust Discovery
Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities in Windows multi-domain/forest environments.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1018](https://attack.mitre.org/techniques/T1018/), [T1482](https://attack.mitre.org/techniques/T1482/)
- **Last Updated**: 2021-03-25

<details>
  <summary>details</summary>

#### Detection Profile

* [DSQuery Domain Discovery](detections.md#dsquery-domain-discovery)

* [NLTest Domain Trust Discovery](detections.md#nltest-domain-trust-discovery)

* [Windows AdFind Exe](detections.md#windows-adfind-exe)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1482 | Domain Trust Discovery | Discovery |
| T1018 | Remote System Discovery | Discovery |

#### Kill Chain Phase

* Exploitation


#### Reference

* https://attack.mitre.org/techniques/T1482/


_version_: 1
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

### HAFNIUM Group
HAFNIUM group was identified by Microsoft as exploiting 4 Microsoft Exchange CVEs in the wild - CVE-2021-26855, CVE-2021-26857, CVE-2021-26858 and CVE-2021-27065.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint, Network_Traffic
- **ATT&CK**: [T1003.001](https://attack.mitre.org/techniques/T1003.001/), [T1003.003](https://attack.mitre.org/techniques/T1003.003/), [T1021.002](https://attack.mitre.org/techniques/T1021.002/), [T1059.001](https://attack.mitre.org/techniques/T1059.001/), [T1114.002](https://attack.mitre.org/techniques/T1114.002/), [T1136.001](https://attack.mitre.org/techniques/T1136.001/), [T1190](https://attack.mitre.org/techniques/T1190/), [T1505.003](https://attack.mitre.org/techniques/T1505.003/), [T1569.002](https://attack.mitre.org/techniques/T1569.002/)
- **Last Updated**: 2021-03-03

<details>
  <summary>details</summary>

#### Detection Profile

* [Any Powershell DownloadString](detections.md#any-powershell-downloadstring)

* [Detect Exchange Web Shell](detections.md#detect-exchange-web-shell)

* [Detect New Local Admin account](detections.md#detect-new-local-admin-account)

* [Detect PsExec With accepteula Flag](detections.md#detect-psexec-with-accepteula-flag)

* [Detect Renamed PSExec](detections.md#detect-renamed-psexec)

* [Dump LSASS via comsvcs DLL](detections.md#dump-lsass-via-comsvcs-dll)

* [Dump LSASS via procdump](detections.md#dump-lsass-via-procdump)

* [Dump LSASS via procdump Rename](detections.md#dump-lsass-via-procdump-rename)

* [Email servers sending high volume traffic to hosts](detections.md#email-servers-sending-high-volume-traffic-to-hosts)

* [Malicious PowerShell Process - Connect To Internet With Hidden Window](detections.md#malicious-powershell-process---connect-to-internet-with-hidden-window)

* [Malicious PowerShell Process - Execution Policy Bypass](detections.md#malicious-powershell-process---execution-policy-bypass)

* [Nishang PowershellTCPOneLine](detections.md#nishang-powershelltcponeline)

* [Ntdsutil Export NTDS](detections.md#ntdsutil-export-ntds)

* [Set Default PowerShell Execution Policy To Unrestricted or Bypass](detections.md#set-default-powershell-execution-policy-to-unrestricted-or-bypass)

* [Unified Messaging Service Spawning a Process](detections.md#unified-messaging-service-spawning-a-process)

* [W3WP Spawning Shell](detections.md#w3wp-spawning-shell)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1059.001 | PowerShell | Execution |
| T1505.003 | Web Shell | Persistence |
| T1136.001 | Local Account | Persistence |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| T1569.002 | Service Execution | Execution |
| T1003.001 | LSASS Memory | Credential Access |
| T1114.002 | Remote Email Collection | Collection |
| T1003.003 | NTDS | Credential Access |
| T1190 | Exploit Public-Facing Application | Initial Access |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Execution

* Exploitation

* Installation

* Lateral Movement


#### Reference

* https://www.splunk.com/en_us/blog/security/detecting-hafnium-exchange-server-zero-day-activity-in-splunk.html

* https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/

* https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/

* https://blog.rapid7.com/2021/03/03/rapid7s-insightidr-enables-detection-and-response-to-microsoft-exchange-0-day/


_version_: 1
</details>

---

### Ingress Tool Transfer
Adversaries may transfer tools or other files from an external system into a compromised environment. Files may be copied from an external adversary controlled system through the command and control channel to bring tools into the victim network or through alternate protocols with another tool such as FTP.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1059.001](https://attack.mitre.org/techniques/T1059.001/), [T1105](https://attack.mitre.org/techniques/T1105/), [T1197](https://attack.mitre.org/techniques/T1197/)
- **Last Updated**: 2021-03-24

<details>
  <summary>details</summary>

#### Detection Profile

* [Any Powershell DownloadFile](detections.md#any-powershell-downloadfile)

* [Any Powershell DownloadString](detections.md#any-powershell-downloadstring)

* [BITSAdmin Download File](detections.md#bitsadmin-download-file)

* [CertUtil Download With URLCache and Split Arguments](detections.md#certutil-download-with-urlcache-and-split-arguments)

* [CertUtil Download With VerifyCtl and Split Arguments](detections.md#certutil-download-with-verifyctl-and-split-arguments)

* [Suspicious Curl Network Connection](detections.md#suspicious-curl-network-connection)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1059.001 | PowerShell | Execution |
| T1197 | BITS Jobs | Defense Evasion, Persistence |
| T1105 | Ingress Tool Transfer | Command And Control |
| T1003 | OS Credential Dumping | Credential Access |
| T1021 | Remote Services | Lateral Movement |
| T1113 | Screen Capture | Collection |
| T1123 | Audio Capture | Collection |
| T1563 | Remote Service Session Hijacking | Lateral Movement |
| T1053 | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |
| T1134 | Access Token Manipulation | Defense Evasion, Privilege Escalation |
| T1548 | Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion |
| T1055 | Process Injection | Defense Evasion, Privilege Escalation |
| T1106 | Native API | Execution |
| T1569 | System Services | Execution |
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1027.005 | Indicator Removal from Tools | Defense Evasion |
| T1140 | Deobfuscate/Decode Files or Information | Defense Evasion |
| T1592 | Gather Victim Host Information | Reconnaissance |
| T1562 | Impair Defenses | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives

* Exploitation


#### Reference

* https://attack.mitre.org/techniques/T1105/


_version_: 1
</details>

---

### Lateral Movement
Detect and investigate tactics, techniques, and procedures around how attackers move laterally within the enterprise. Because lateral movement can expose the adversary to detection, it should be an important focus for security analysts.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint, Network_Traffic
- **ATT&CK**: [T1021.001](https://attack.mitre.org/techniques/T1021.001/), [T1021.002](https://attack.mitre.org/techniques/T1021.002/), [T1053.005](https://attack.mitre.org/techniques/T1053.005/), [T1550.002](https://attack.mitre.org/techniques/T1550.002/), [T1558.003](https://attack.mitre.org/techniques/T1558.003/), [T1569.002](https://attack.mitre.org/techniques/T1569.002/)
- **Last Updated**: 2020-02-04

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect Activity Related to Pass the Hash Attacks](detections.md#detect-activity-related-to-pass-the-hash-attacks)

* [Detect Pass the Hash](detections.md#detect-pass-the-hash)

* [Detect PsExec With accepteula Flag](detections.md#detect-psexec-with-accepteula-flag)

* [Detect Renamed PSExec](detections.md#detect-renamed-psexec)

* [Kerberoasting spn request with RC4 encryption](detections.md#kerberoasting-spn-request-with-rc4-encryption)

* [Remote Desktop Network Traffic](detections.md#remote-desktop-network-traffic)

* [Remote Desktop Process Running On System](detections.md#remote-desktop-process-running-on-system)

* [Schtasks scheduling job on remote system](detections.md#schtasks-scheduling-job-on-remote-system)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1550.002 | Pass the Hash | Defense Evasion, Lateral Movement |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| T1569.002 | Service Execution | Execution |
| T1558.003 | Kerberoasting | Credential Access |
| T1021.001 | Remote Desktop Protocol | Lateral Movement |
| T1053.005 | Scheduled Task | Execution, Persistence, Privilege Escalation |

#### Kill Chain Phase

* Actions on Objectives

* Execution

* Exploitation

* Lateral Movement


#### Reference

* https://www.fireeye.com/blog/executive-perspective/2015/08/malware_lateral_move.html


_version_: 2
</details>

---

### Malicious PowerShell
Attackers are finding stealthy ways "live off the land," leveraging utilities and tools that come standard on the endpoint--such as PowerShell--to achieve their goals without downloading binary files. These searches can help you detect and investigate PowerShell command-line options that may be indicative of malicious intent.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1003](https://attack.mitre.org/techniques/T1003/), [T1021](https://attack.mitre.org/techniques/T1021/), [T1027](https://attack.mitre.org/techniques/T1027/), [T1027.005](https://attack.mitre.org/techniques/T1027.005/), [T1053](https://attack.mitre.org/techniques/T1053/), [T1055](https://attack.mitre.org/techniques/T1055/), [T1059.001](https://attack.mitre.org/techniques/T1059.001/), [T1106](https://attack.mitre.org/techniques/T1106/), [T1113](https://attack.mitre.org/techniques/T1113/), [T1123](https://attack.mitre.org/techniques/T1123/), [T1134](https://attack.mitre.org/techniques/T1134/), [T1140](https://attack.mitre.org/techniques/T1140/), [T1548](https://attack.mitre.org/techniques/T1548/), [T1562](https://attack.mitre.org/techniques/T1562/), [T1563](https://attack.mitre.org/techniques/T1563/), [T1569](https://attack.mitre.org/techniques/T1569/), [T1592](https://attack.mitre.org/techniques/T1592/)
- **Last Updated**: 2017-08-23

<details>
  <summary>details</summary>

#### Detection Profile

* [Any Powershell DownloadFile](detections.md#any-powershell-downloadfile)

* [Any Powershell DownloadString](detections.md#any-powershell-downloadstring)

* [Credential Extraction indicative of use of DSInternals credential conversion modules](detections.md#credential-extraction-indicative-of-use-of-dsinternals-credential-conversion-modules)

* [Credential Extraction indicative of use of DSInternals modules](detections.md#credential-extraction-indicative-of-use-of-dsinternals-modules)

* [Credential Extraction indicative of use of PowerSploit modules](detections.md#credential-extraction-indicative-of-use-of-powersploit-modules)

* [Credential Extraction via Get-ADDBAccount module present in PowerSploit and DSInternals](detections.md#credential-extraction-via-get-addbaccount-module-present-in-powersploit-and-dsinternals)

* [Detect Empire with PowerShell Script Block Logging](detections.md#detect-empire-with-powershell-script-block-logging)

* [Detect Mimikatz With PowerShell Script Block Logging](detections.md#detect-mimikatz-with-powershell-script-block-logging)

* [Illegal Access To User Content via PowerSploit modules](detections.md#illegal-access-to-user-content-via-powersploit-modules)

* [Illegal Privilege Elevation and Persistence via PowerSploit modules](detections.md#illegal-privilege-elevation-and-persistence-via-powersploit-modules)

* [Illegal Service and Process Control via PowerSploit modules](detections.md#illegal-service-and-process-control-via-powersploit-modules)

* [Malicious PowerShell Process - Connect To Internet With Hidden Window](detections.md#malicious-powershell-process---connect-to-internet-with-hidden-window)

* [Malicious PowerShell Process - Encoded Command](detections.md#malicious-powershell-process---encoded-command)

* [Malicious PowerShell Process With Obfuscation Techniques](detections.md#malicious-powershell-process-with-obfuscation-techniques)

* [PowerShell Domain Enumeration](detections.md#powershell-domain-enumeration)

* [PowerShell Loading DotNET into Memory via System Reflection Assembly](detections.md#powershell-loading-dotnet-into-memory-via-system-reflection-assembly)

* [Powershell Creating Thread Mutex](detections.md#powershell-creating-thread-mutex)

* [Powershell Enable SMB1Protocol Feature](detections.md#powershell-enable-smb1protocol-feature)

* [Powershell Fileless Process Injection via GetProcAddress](detections.md#powershell-fileless-process-injection-via-getprocaddress)

* [Powershell Fileless Script Contains Base64 Encoded Content](detections.md#powershell-fileless-script-contains-base64-encoded-content)

* [Powershell Processing Stream Of Data](detections.md#powershell-processing-stream-of-data)

* [Powershell Using memory As Backing Store](detections.md#powershell-using-memory-as-backing-store)

* [Recon AVProduct Through Pwh or WMI](detections.md#recon-avproduct-through-pwh-or-wmi)

* [Recon Using WMI Class](detections.md#recon-using-wmi-class)

* [Set Default PowerShell Execution Policy To Unrestricted or Bypass](detections.md#set-default-powershell-execution-policy-to-unrestricted-or-bypass)

* [Unloading AMSI via Reflection](detections.md#unloading-amsi-via-reflection)

* [WMI Recon Running Process Or Services](detections.md#wmi-recon-running-process-or-services)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1059.001 | PowerShell | Execution |
| T1197 | BITS Jobs | Defense Evasion, Persistence |
| T1105 | Ingress Tool Transfer | Command And Control |
| T1003 | OS Credential Dumping | Credential Access |
| T1021 | Remote Services | Lateral Movement |
| T1113 | Screen Capture | Collection |
| T1123 | Audio Capture | Collection |
| T1563 | Remote Service Session Hijacking | Lateral Movement |
| T1053 | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |
| T1134 | Access Token Manipulation | Defense Evasion, Privilege Escalation |
| T1548 | Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion |
| T1055 | Process Injection | Defense Evasion, Privilege Escalation |
| T1106 | Native API | Execution |
| T1569 | System Services | Execution |
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1027.005 | Indicator Removal from Tools | Defense Evasion |
| T1140 | Deobfuscate/Decode Files or Information | Defense Evasion |
| T1592 | Gather Victim Host Information | Reconnaissance |
| T1562 | Impair Defenses | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Exploitation

* Installation

* Privilege Escalation

* Reconnaissance


#### Reference

* https://blogs.mcafee.com/mcafee-labs/malware-employs-powershell-to-infect-systems/

* https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/


_version_: 5
</details>

---

### Masquerading - Rename System Utilities
Adversaries may rename legitimate system utilities to try to evade security mechanisms concerning the usage of those utilities.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1036](https://attack.mitre.org/techniques/T1036/), [T1036.003](https://attack.mitre.org/techniques/T1036.003/), [T1127](https://attack.mitre.org/techniques/T1127/), [T1127.001](https://attack.mitre.org/techniques/T1127.001/), [T1218.011](https://attack.mitre.org/techniques/T1218.011/)
- **Last Updated**: 2021-04-26

<details>
  <summary>details</summary>

#### Detection Profile

* [Execution of File with Multiple Extensions](detections.md#execution-of-file-with-multiple-extensions)

* [Suspicious MSBuild Rename](detections.md#suspicious-msbuild-rename)

* [Suspicious Rundll32 Rename](detections.md#suspicious-rundll32-rename)

* [Suspicious microsoft workflow compiler rename](detections.md#suspicious-microsoft-workflow-compiler-rename)

* [Suspicious msbuild path](detections.md#suspicious-msbuild-path)

* [System Process Running from Unexpected Location](detections.md#system-process-running-from-unexpected-location)

* [System Processes Run From Unexpected Locations](detections.md#system-processes-run-from-unexpected-locations)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1036.003 | Rename System Utilities | Defense Evasion |
| T1127.001 | MSBuild | Defense Evasion |
| T1218.011 | Rundll32 | Defense Evasion |
| T1127 | Trusted Developer Utilities Proxy Execution | Defense Evasion |
| T1036 | Masquerading | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives

* Exploitation


#### Reference

* https://attack.mitre.org/techniques/T1036/003/


_version_: 1
</details>

---

### Meterpreter
Meterpreter provides red teams, pen testers and threat actors interactive access to a compromised host to run commands, upload payloads, download files, and other actions.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1033](https://attack.mitre.org/techniques/T1033/)
- **Last Updated**: 2021-06-08

<details>
  <summary>details</summary>

#### Detection Profile

* [Excessive number of taskhost processes](detections.md#excessive-number-of-taskhost-processes)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1033 | System Owner/User Discovery | Discovery |

#### Kill Chain Phase

* Exploitation


#### Reference

* https://www.offensive-security.com/metasploit-unleashed/about-meterpreter/

* https://doubleoctopus.com/security-wiki/threats-and-tools/meterpreter/

* https://www.rapid7.com/products/metasploit/


_version_: 1
</details>

---

### NOBELIUM Group
Sunburst is a trojanized updates to SolarWinds Orion IT monitoring and management software. It was discovered by FireEye in December 2020. The actors behind this campaign gained access to numerous public and private organizations around the world.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint, Network_Traffic, Web
- **ATT&CK**: [T1018](https://attack.mitre.org/techniques/T1018/), [T1027](https://attack.mitre.org/techniques/T1027/), [T1053.005](https://attack.mitre.org/techniques/T1053.005/), [T1059.003](https://attack.mitre.org/techniques/T1059.003/), [T1071.001](https://attack.mitre.org/techniques/T1071.001/), [T1071.002](https://attack.mitre.org/techniques/T1071.002/), [T1203](https://attack.mitre.org/techniques/T1203/), [T1218.005](https://attack.mitre.org/techniques/T1218.005/), [T1505.003](https://attack.mitre.org/techniques/T1505.003/), [T1543.003](https://attack.mitre.org/techniques/T1543.003/), [T1560.001](https://attack.mitre.org/techniques/T1560.001/), [T1569.002](https://attack.mitre.org/techniques/T1569.002/)
- **Last Updated**: 2020-12-14

<details>
  <summary>details</summary>

#### Detection Profile

* [Anomalous usage of 7zip](detections.md#anomalous-usage-of-7zip)

* [Detect Outbound SMB Traffic](detections.md#detect-outbound-smb-traffic)

* [Detect Prohibited Applications Spawning cmd exe](detections.md#detect-prohibited-applications-spawning-cmd-exe)

* [Detect Rundll32 Inline HTA Execution](detections.md#detect-rundll32-inline-hta-execution)

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
| T1560.001 | Archive via Utility | Collection |
| T1059.003 | Windows Command Shell | Execution |
| T1543.003 | Windows Service | Persistence, Privilege Escalation |
| T1055 | Process Injection | Defense Evasion, Privilege Escalation |
| T1071.002 | File Transfer Protocols | Command And Control |
| T1218.010 | Regsvr32 | Defense Evasion |
| T1218.005 | Mshta | Defense Evasion |
| T1569.002 | Service Execution | Execution |
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1218.011 | Rundll32 | Defense Evasion |
| T1053.005 | Scheduled Task | Execution, Persistence, Privilege Escalation |
| T1548 | Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion |
| T1203 | Exploitation for Client Execution | Execution |
| T1505.003 | Web Shell | Persistence |
| T1127.001 | MSBuild | Defense Evasion |
| T1036.003 | Rename System Utilities | Defense Evasion |
| T1127 | Trusted Developer Utilities Proxy Execution | Defense Evasion |
| T1071.001 | Web Protocols | Command And Control |
| T1018 | Remote System Discovery | Discovery |

#### Kill Chain Phase

* Actions on Objective

* Actions on Objectives

* Command and Control

* Exfiltration

* Exploitation

* Installation


#### Reference

* https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/

* https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html

* https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/


_version_: 2
</details>

---

### Possible Backdoor Activity Associated With MUDCARP Espionage Campaigns
Monitor your environment for suspicious behaviors that resemble the techniques employed by the MUDCARP threat group.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1059.001](https://attack.mitre.org/techniques/T1059.001/), [T1547.001](https://attack.mitre.org/techniques/T1547.001/)
- **Last Updated**: 2020-01-22

<details>
  <summary>details</summary>

#### Detection Profile

* [Malicious PowerShell Process - Connect To Internet With Hidden Window](detections.md#malicious-powershell-process---connect-to-internet-with-hidden-window)

* [Registry Keys Used For Persistence](detections.md#registry-keys-used-for-persistence)

* [Unusually Long Command Line](detections.md#unusually-long-command-line)

* [Unusually Long Command Line - MLTK](detections.md#unusually-long-command-line---mltk)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1059.001 | PowerShell | Execution |
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

### Silver Sparrow
Silver Sparrow, identified by Red Canary Intelligence, is a new forward looking MacOS (Intel and M1) malicious software downloader utilizing JavaScript for execution and a launchAgent to establish persistence.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1074](https://attack.mitre.org/techniques/T1074/), [T1105](https://attack.mitre.org/techniques/T1105/), [T1543.001](https://attack.mitre.org/techniques/T1543.001/)
- **Last Updated**: 2021-02-24

<details>
  <summary>details</summary>

#### Detection Profile

* [Suspicious Curl Network Connection](detections.md#suspicious-curl-network-connection)

* [Suspicious PlistBuddy Usage](detections.md#suspicious-plistbuddy-usage)

* [Suspicious PlistBuddy Usage via OSquery](detections.md#suspicious-plistbuddy-usage-via-osquery)

* [Suspicious SQLite3 LSQuarantine Behavior](detections.md#suspicious-sqlite3-lsquarantine-behavior)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1105 | Ingress Tool Transfer | Command And Control |
| T1543.001 | Launch Agent | Persistence, Privilege Escalation |
| T1074 | Data Staged | Collection |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://redcanary.com/blog/clipping-silver-sparrows-wings/

* https://www.sentinelone.com/blog/5-things-you-need-to-know-about-silver-sparrow/


_version_: 1
</details>

---

### Spearphishing Attachments
Detect signs of malicious payloads that may indicate that your environment has been breached via a phishing attack.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1003.002](https://attack.mitre.org/techniques/T1003.002/), [T1566.001](https://attack.mitre.org/techniques/T1566.001/), [T1566.002](https://attack.mitre.org/techniques/T1566.002/)
- **Last Updated**: 2019-04-29

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect Outlook exe writing a zip file](detections.md#detect-outlook-exe-writing-a-zip-file)

* [Excel Spawning PowerShell](detections.md#excel-spawning-powershell)

* [Excel Spawning Windows Script Host](detections.md#excel-spawning-windows-script-host)

* [Office Application Spawn rundll32 process](detections.md#office-application-spawn-rundll32-process)

* [Office Document Creating Schedule Task](detections.md#office-document-creating-schedule-task)

* [Office Document Executing Macro Code](detections.md#office-document-executing-macro-code)

* [Office Document Spawned Child Process To Download](detections.md#office-document-spawned-child-process-to-download)

* [Office Product Spawning BITSAdmin](detections.md#office-product-spawning-bitsadmin)

* [Office Product Spawning CertUtil](detections.md#office-product-spawning-certutil)

* [Office Product Spawning MSHTA](detections.md#office-product-spawning-mshta)

* [Office Product Spawning Rundll32 with no DLL](detections.md#office-product-spawning-rundll32-with-no-dll)

* [Office Product Spawning Wmic](detections.md#office-product-spawning-wmic)

* [Process Creating LNK file in Suspicious Location](detections.md#process-creating-lnk-file-in-suspicious-location)

* [Winword Spawning Cmd](detections.md#winword-spawning-cmd)

* [Winword Spawning PowerShell](detections.md#winword-spawning-powershell)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1566.001 | Spearphishing Attachment | Initial Access |
| T1003.002 | Security Account Manager | Credential Access |
| T1566.002 | Spearphishing Link | Initial Access |

#### Kill Chain Phase

* Actions on Objectives

* Exploitation

* Installation


#### Reference

* https://www.fireeye.com/blog/threat-research/2019/04/spear-phishing-campaign-targets-ukraine-government.html


_version_: 1
</details>

---

### Suspicious Command-Line Executions
Leveraging the Windows command-line interface (CLI) is one of the most common attack techniques--one that is also detailed in the MITRE ATT&CK framework. Use this Analytic Story to help you identify unusual or suspicious use of the CLI on Windows systems.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1036.003](https://attack.mitre.org/techniques/T1036.003/), [T1059](https://attack.mitre.org/techniques/T1059/), [T1059.003](https://attack.mitre.org/techniques/T1059.003/)
- **Last Updated**: 2020-02-03

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect Prohibited Applications Spawning cmd exe](detections.md#detect-prohibited-applications-spawning-cmd-exe)

* [Detect Use of cmd exe to Launch Script Interpreters](detections.md#detect-use-of-cmd-exe-to-launch-script-interpreters)

* [System Processes Run From Unexpected Locations](detections.md#system-processes-run-from-unexpected-locations)

* [Unusually Long Command Line](detections.md#unusually-long-command-line)

* [Unusually Long Command Line - MLTK](detections.md#unusually-long-command-line---mltk)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1059.003 | Windows Command Shell | Execution |
| T1059 | Command and Scripting Interpreter | Execution |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
| T1036.003 | Rename System Utilities | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives

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
- **Datamodel**: Endpoint, Network_Resolution
- **ATT&CK**: [T1048](https://attack.mitre.org/techniques/T1048/), [T1048.003](https://attack.mitre.org/techniques/T1048.003/), [T1071.004](https://attack.mitre.org/techniques/T1071.004/), [T1189](https://attack.mitre.org/techniques/T1189/)
- **Last Updated**: 2017-09-18

<details>
  <summary>details</summary>

#### Detection Profile

* [DNS Exfiltration Using Nslookup App](detections.md#dns-exfiltration-using-nslookup-app)

* [DNS Query Length Outliers - MLTK](detections.md#dns-query-length-outliers---mltk)

* [DNS Query Length With High Standard Deviation](detections.md#dns-query-length-with-high-standard-deviation)

* [Detect hosts connecting to dynamic domain providers](detections.md#detect-hosts-connecting-to-dynamic-domain-providers)

* [Excessive DNS Failures](detections.md#excessive-dns-failures)

* [Excessive Usage of NSLOOKUP App](detections.md#excessive-usage-of-nslookup-app)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |
| T1071.004 | DNS | Command And Control |
| T1048.003 | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |
| T1095 | Non-Application Layer Protocol | Command And Control |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1189 | Drive-by Compromise | Initial Access |
| T1114.001 | Local Email Collection | Collection |
| T1114 | Email Collection | Collection |
| T1114.003 | Email Forwarding Rule | Collection |
| T1071.001 | Web Protocols | Command And Control |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Exploitation


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
- **Datamodel**: Email
- **ATT&CK**: [T1566.001](https://attack.mitre.org/techniques/T1566.001/)
- **Last Updated**: 2020-01-27

<details>
  <summary>details</summary>

#### Detection Profile

* [Email Attachments With Lots Of Spaces](detections.md#email-attachments-with-lots-of-spaces)

* [Monitor Email For Brand Abuse](detections.md#monitor-email-for-brand-abuse)

* [Suspicious Email Attachment Extensions](detections.md#suspicious-email-attachment-extensions)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
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
- **ATT&CK**: [T1059](https://attack.mitre.org/techniques/T1059/), [T1059.003](https://attack.mitre.org/techniques/T1059.003/), [T1218.005](https://attack.mitre.org/techniques/T1218.005/), [T1547.001](https://attack.mitre.org/techniques/T1547.001/)
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
| T1059 | Command and Scripting Interpreter | Execution |
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
| T1078.001 | Default Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

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

* [Rundll32 with no Command Line Arguments with Network](detections.md#rundll32-with-no-command-line-arguments-with-network)

* [Suspicious Rundll32 Rename](detections.md#suspicious-rundll32-rename)

* [Suspicious Rundll32 StartW](detections.md#suspicious-rundll32-startw)

* [Suspicious Rundll32 dllregisterserver](detections.md#suspicious-rundll32-dllregisterserver)

* [Suspicious Rundll32 no Command Line Arguments](detections.md#suspicious-rundll32-no-command-line-arguments)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1218.011 | Rundll32 | Defense Evasion |
| T1003.001 | LSASS Memory | Credential Access |
| T1036.003 | Rename System Utilities | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives

* Exploitation


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

* [Detect WMI Event Subscription Persistence](detections.md#detect-wmi-event-subscription-persistence)

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
| T1546.003 | Windows Management Instrumentation Event Subscription | Privilege Escalation, Persistence |
| T1047 | Windows Management Instrumentation | Execution |

#### Kill Chain Phase

* Actions on Objectives

* Exploitation


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
- **ATT&CK**: [T1546.011](https://attack.mitre.org/techniques/T1546.011/), [T1546.012](https://attack.mitre.org/techniques/T1546.012/), [T1547.001](https://attack.mitre.org/techniques/T1547.001/), [T1547.010](https://attack.mitre.org/techniques/T1547.010/), [T1548.002](https://attack.mitre.org/techniques/T1548.002/)
- **Last Updated**: 2018-05-31

<details>
  <summary>details</summary>

#### Detection Profile

* [Disabling Remote User Account Control](detections.md#disabling-remote-user-account-control)

* [Monitor Registry Keys for Print Monitors](detections.md#monitor-registry-keys-for-print-monitors)

* [Registry Keys Used For Persistence](detections.md#registry-keys-used-for-persistence)

* [Registry Keys Used For Privilege Escalation](detections.md#registry-keys-used-for-privilege-escalation)

* [Registry Keys for Creating SHIM Databases](detections.md#registry-keys-for-creating-shim-databases)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1548.002 | Bypass User Account Control | Privilege Escalation, Defense Evasion |
| T1547.010 | Port Monitors | Persistence, Privilege Escalation |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation |
| T1546.012 | Image File Execution Options Injection | Privilege Escalation, Persistence |
| T1546.011 | Application Shimming | Privilege Escalation, Persistence |

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
- **ATT&CK**: [T1059](https://attack.mitre.org/techniques/T1059/), [T1059.003](https://attack.mitre.org/techniques/T1059.003/), [T1068](https://attack.mitre.org/techniques/T1068/)
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
| T1059 | Command and Scripting Interpreter | Execution |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
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
- **ATT&CK**: [T1036](https://attack.mitre.org/techniques/T1036/), [T1112](https://attack.mitre.org/techniques/T1112/), [T1222.001](https://attack.mitre.org/techniques/T1222.001/), [T1548.002](https://attack.mitre.org/techniques/T1548.002/), [T1562.001](https://attack.mitre.org/techniques/T1562.001/), [T1564.001](https://attack.mitre.org/techniques/T1564.001/)
- **Last Updated**: 2018-05-31

<details>
  <summary>details</summary>

#### Detection Profile

* [Disable Registry Tool](detections.md#disable-registry-tool)

* [Disable Show Hidden Files](detections.md#disable-show-hidden-files)

* [Disable Windows Behavior Monitoring](detections.md#disable-windows-behavior-monitoring)

* [Disable Windows SmartScreen Protection](detections.md#disable-windows-smartscreen-protection)

* [Disabling CMD Application](detections.md#disabling-cmd-application)

* [Disabling ControlPanel](detections.md#disabling-controlpanel)

* [Disabling Firewall with Netsh](detections.md#disabling-firewall-with-netsh)

* [Disabling FolderOptions Windows Feature](detections.md#disabling-folderoptions-windows-feature)

* [Disabling NoRun Windows App](detections.md#disabling-norun-windows-app)

* [Disabling Remote User Account Control](detections.md#disabling-remote-user-account-control)

* [Disabling SystemRestore In Registry](detections.md#disabling-systemrestore-in-registry)

* [Disabling Task Manager](detections.md#disabling-task-manager)

* [Eventvwr UAC Bypass](detections.md#eventvwr-uac-bypass)

* [Excessive number of service control start as disabled](detections.md#excessive-number-of-service-control-start-as-disabled)

* [FodHelper UAC Bypass](detections.md#fodhelper-uac-bypass)

* [Hiding Files And Directories With Attrib exe](detections.md#hiding-files-and-directories-with-attrib-exe)

* [SLUI RunAs Elevated](detections.md#slui-runas-elevated)

* [SLUI Spawning a Process](detections.md#slui-spawning-a-process)

* [Suspicious Reg exe Process](detections.md#suspicious-reg-exe-process)

* [System Process Running from Unexpected Location](detections.md#system-process-running-from-unexpected-location)

* [Windows DisableAntiSpyware Registry](detections.md#windows-disableantispyware-registry)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1562.001 | Disable or Modify Tools | Defense Evasion |
| T1564.001 | Hidden Files and Directories | Defense Evasion |
| T1548.002 | Bypass User Account Control | Privilege Escalation, Defense Evasion |
| T1112 | Modify Registry | Defense Evasion |
| T1222.001 | Windows File and Directory Permissions Modification | Defense Evasion |
| T1036 | Masquerading | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives

* Delivery

* Exploitation

* Privilege Escalation


#### Reference

* https://attack.mitre.org/wiki/Defense_Evasion


_version_: 1
</details>

---

### Windows Discovery Techniques
Monitors for behaviors associated with adversaries discovering objects in the environment that can be leveraged in the progression of the attack.

- **Product**: Splunk Behavioral Analytics, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1007](https://attack.mitre.org/techniques/T1007/), [T1012](https://attack.mitre.org/techniques/T1012/), [T1021.002](https://attack.mitre.org/techniques/T1021.002/), [T1039](https://attack.mitre.org/techniques/T1039/), [T1046](https://attack.mitre.org/techniques/T1046/), [T1047](https://attack.mitre.org/techniques/T1047/), [T1053](https://attack.mitre.org/techniques/T1053/), [T1055](https://attack.mitre.org/techniques/T1055/), [T1057](https://attack.mitre.org/techniques/T1057/), [T1068](https://attack.mitre.org/techniques/T1068/), [T1078](https://attack.mitre.org/techniques/T1078/), [T1083](https://attack.mitre.org/techniques/T1083/), [T1087](https://attack.mitre.org/techniques/T1087/), [T1098](https://attack.mitre.org/techniques/T1098/), [T1135](https://attack.mitre.org/techniques/T1135/), [T1199](https://attack.mitre.org/techniques/T1199/), [T1482](https://attack.mitre.org/techniques/T1482/), [T1484](https://attack.mitre.org/techniques/T1484/), [T1518](https://attack.mitre.org/techniques/T1518/), [T1543](https://attack.mitre.org/techniques/T1543/), [T1547](https://attack.mitre.org/techniques/T1547/), [T1574](https://attack.mitre.org/techniques/T1574/), [T1589.001](https://attack.mitre.org/techniques/T1589.001/), [T1590](https://attack.mitre.org/techniques/T1590/), [T1590.001](https://attack.mitre.org/techniques/T1590.001/), [T1590.003](https://attack.mitre.org/techniques/T1590.003/), [T1591](https://attack.mitre.org/techniques/T1591/), [T1592](https://attack.mitre.org/techniques/T1592/), [T1592.002](https://attack.mitre.org/techniques/T1592.002/), [T1595](https://attack.mitre.org/techniques/T1595/), [T1595.002](https://attack.mitre.org/techniques/T1595.002/)
- **Last Updated**: 2021-03-04

<details>
  <summary>details</summary>

#### Detection Profile

* [Reconnaissance and Access to Accounts Groups and Policies via PowerSploit modules](detections.md#reconnaissance-and-access-to-accounts-groups-and-policies-via-powersploit-modules)

* [Reconnaissance and Access to Accounts and Groups via Mimikatz modules](detections.md#reconnaissance-and-access-to-accounts-and-groups-via-mimikatz-modules)

* [Reconnaissance and Access to Active Directoty Infrastructure via PowerSploit modules](detections.md#reconnaissance-and-access-to-active-directoty-infrastructure-via-powersploit-modules)

* [Reconnaissance and Access to Computers and Domains via PowerSploit modules](detections.md#reconnaissance-and-access-to-computers-and-domains-via-powersploit-modules)

* [Reconnaissance and Access to Computers via Mimikatz modules](detections.md#reconnaissance-and-access-to-computers-via-mimikatz-modules)

* [Reconnaissance and Access to Operating System Elements via PowerSploit modules](detections.md#reconnaissance-and-access-to-operating-system-elements-via-powersploit-modules)

* [Reconnaissance and Access to Processes and Services via Mimikatz modules](detections.md#reconnaissance-and-access-to-processes-and-services-via-mimikatz-modules)

* [Reconnaissance and Access to Shared Resources via Mimikatz modules](detections.md#reconnaissance-and-access-to-shared-resources-via-mimikatz-modules)

* [Reconnaissance and Access to Shared Resources via PowerSploit modules](detections.md#reconnaissance-and-access-to-shared-resources-via-powersploit-modules)

* [Reconnaissance of Access and Persistence Opportunities via PowerSploit modules](detections.md#reconnaissance-of-access-and-persistence-opportunities-via-powersploit-modules)

* [Reconnaissance of Connectivity via PowerSploit modules](detections.md#reconnaissance-of-connectivity-via-powersploit-modules)

* [Reconnaissance of Credential Stores and Services via Mimikatz modules](detections.md#reconnaissance-of-credential-stores-and-services-via-mimikatz-modules)

* [Reconnaissance of Defensive Tools via PowerSploit modules](detections.md#reconnaissance-of-defensive-tools-via-powersploit-modules)

* [Reconnaissance of Privilege Escalation Opportunities via PowerSploit modules](detections.md#reconnaissance-of-privilege-escalation-opportunities-via-powersploit-modules)

* [Reconnaissance of Process or Service Hijacking Opportunities via Mimikatz modules](detections.md#reconnaissance-of-process-or-service-hijacking-opportunities-via-mimikatz-modules)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1078 | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |
| T1087 | Account Discovery | Discovery |
| T1484 | Domain Policy Modification | Defense Evasion, Privilege Escalation |
| T1199 | Trusted Relationship | Initial Access |
| T1482 | Domain Trust Discovery | Discovery |
| T1590 | Gather Victim Network Information | Reconnaissance |
| T1591 | Gather Victim Org Information | Reconnaissance |
| T1595 | Active Scanning | Reconnaissance |
| T1592 | Gather Victim Host Information | Reconnaissance |
| T1007 | System Service Discovery | Discovery |
| T1012 | Query Registry | Discovery |
| T1046 | Network Service Scanning | Discovery |
| T1047 | Windows Management Instrumentation | Execution |
| T1057 | Process Discovery | Discovery |
| T1083 | File and Directory Discovery | Discovery |
| T1518 | Software Discovery | Discovery |
| T1592.002 | Software | Reconnaissance |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| T1135 | Network Share Discovery | Discovery |
| T1039 | Data from Network Shared Drive | Collection |
| T1053 | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
| T1543 | Create or Modify System Process | Persistence, Privilege Escalation |
| T1547 | Boot or Logon Autostart Execution | Persistence, Privilege Escalation |
| T1574 | Hijack Execution Flow | Persistence, Privilege Escalation, Defense Evasion |
| T1589.001 | Credentials | Reconnaissance |
| T1590.001 | Domain Properties | Reconnaissance |
| T1590.003 | Network Trust Dependencies | Reconnaissance |
| T1098 | Account Manipulation | Persistence |
| T1595.002 | Vulnerability Scanning | Reconnaissance |
| T1055 | Process Injection | Defense Evasion, Privilege Escalation |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://attack.mitre.org/tactics/TA0007/

* https://cyberd.us/penetration-testing

* https://attack.mitre.org/software/S0521/


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

* [Illegal Deletion of Logs via Mimikatz modules](detections.md#illegal-deletion-of-logs-via-mimikatz-modules)

* [Suspicious Event Log Service Behavior](detections.md#suspicious-event-log-service-behavior)

* [Suspicious wevtutil Usage](detections.md#suspicious-wevtutil-usage)

* [USN Journal Deletion](detections.md#usn-journal-deletion)

* [WevtUtil Usage To Clear Logs](detections.md#wevtutil-usage-to-clear-logs)

* [Wevtutil Usage To Disable Logs](detections.md#wevtutil-usage-to-disable-logs)

* [Windows Event Log Cleared](detections.md#windows-event-log-cleared)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1490 | Inhibit System Recovery | Impact |
| T1070 | Indicator Removal on Host | Defense Evasion |
| T1070.001 | Clear Windows Event Logs | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives

* Exploitation


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
- **ATT&CK**: [T1053](https://attack.mitre.org/techniques/T1053/), [T1053.005](https://attack.mitre.org/techniques/T1053.005/), [T1068](https://attack.mitre.org/techniques/T1068/), [T1078](https://attack.mitre.org/techniques/T1078/), [T1098](https://attack.mitre.org/techniques/T1098/), [T1134](https://attack.mitre.org/techniques/T1134/), [T1207](https://attack.mitre.org/techniques/T1207/), [T1222.001](https://attack.mitre.org/techniques/T1222.001/), [T1484](https://attack.mitre.org/techniques/T1484/), [T1543.003](https://attack.mitre.org/techniques/T1543.003/), [T1546.011](https://attack.mitre.org/techniques/T1546.011/), [T1547.001](https://attack.mitre.org/techniques/T1547.001/), [T1547.010](https://attack.mitre.org/techniques/T1547.010/), [T1548](https://attack.mitre.org/techniques/T1548/), [T1574.009](https://attack.mitre.org/techniques/T1574.009/), [T1574.011](https://attack.mitre.org/techniques/T1574.011/), [T1585](https://attack.mitre.org/techniques/T1585/)
- **Last Updated**: 2018-05-31

<details>
  <summary>details</summary>

#### Detection Profile

* [Certutil exe certificate extraction](detections.md#certutil-exe-certificate-extraction)

* [Detect Path Interception By Creation Of program exe](detections.md#detect-path-interception-by-creation-of-program-exe)

* [Hiding Files And Directories With Attrib exe](detections.md#hiding-files-and-directories-with-attrib-exe)

* [Illegal Account Creation via PowerSploit modules](detections.md#illegal-account-creation-via-powersploit-modules)

* [Illegal Enabling or Disabling of Accounts via DSInternals modules](detections.md#illegal-enabling-or-disabling-of-accounts-via-dsinternals-modules)

* [Illegal Management of Active Directory Elements and Policies via DSInternals modules](detections.md#illegal-management-of-active-directory-elements-and-policies-via-dsinternals-modules)

* [Illegal Management of Computers and Active Directory Elements via PowerSploit modules](detections.md#illegal-management-of-computers-and-active-directory-elements-via-powersploit-modules)

* [Illegal Privilege Elevation and Persistence via PowerSploit modules](detections.md#illegal-privilege-elevation-and-persistence-via-powersploit-modules)

* [Monitor Registry Keys for Print Monitors](detections.md#monitor-registry-keys-for-print-monitors)

* [Reg exe Manipulating Windows Services Registry Keys](detections.md#reg-exe-manipulating-windows-services-registry-keys)

* [Registry Keys Used For Persistence](detections.md#registry-keys-used-for-persistence)

* [Registry Keys for Creating SHIM Databases](detections.md#registry-keys-for-creating-shim-databases)

* [Sc exe Manipulating Windows Services](detections.md#sc-exe-manipulating-windows-services)

* [Schedule Task with HTTP Command Arguments](detections.md#schedule-task-with-http-command-arguments)

* [Schedule Task with Rundll32 Command Trigger](detections.md#schedule-task-with-rundll32-command-trigger)

* [Schtasks used for forcing a reboot](detections.md#schtasks-used-for-forcing-a-reboot)

* [Setting Credentials via DSInternals modules](detections.md#setting-credentials-via-dsinternals-modules)

* [Setting Credentials via Mimikatz modules](detections.md#setting-credentials-via-mimikatz-modules)

* [Setting Credentials via PowerSploit modules](detections.md#setting-credentials-via-powersploit-modules)

* [Shim Database File Creation](detections.md#shim-database-file-creation)

* [Shim Database Installation With Suspicious Parameters](detections.md#shim-database-installation-with-suspicious-parameters)

* [Suspicious Scheduled Task from Public Directory](detections.md#suspicious-scheduled-task-from-public-directory)

* [WinEvent Scheduled Task Created Within Public Path](detections.md#winevent-scheduled-task-created-within-public-path)

* [WinEvent Scheduled Task Created to Spawn Shell](detections.md#winevent-scheduled-task-created-to-spawn-shell)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1574.009 | Path Interception by Unquoted Path | Persistence, Privilege Escalation, Defense Evasion |
| T1222.001 | Windows File and Directory Permissions Modification | Defense Evasion |
| T1585 | Establish Accounts | Resource Development |
| T1078 | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |
| T1098 | Account Manipulation | Persistence |
| T1207 | Rogue Domain Controller | Defense Evasion |
| T1484 | Domain Policy Modification | Defense Evasion, Privilege Escalation |
| T1053 | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |
| T1134 | Access Token Manipulation | Defense Evasion, Privilege Escalation |
| T1548 | Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion |
| T1547.010 | Port Monitors | Persistence, Privilege Escalation |
| T1574.011 | Services Registry Permissions Weakness | Persistence, Privilege Escalation, Defense Evasion |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation |
| T1546.011 | Application Shimming | Privilege Escalation, Persistence |
| T1543.003 | Windows Service | Persistence, Privilege Escalation |
| T1053.005 | Scheduled Task | Execution, Persistence, Privilege Escalation |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |

#### Kill Chain Phase

* Actions on Objectives

* Exploitation

* Installation

* Privilege Escalation


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
- **ATT&CK**: [T1068](https://attack.mitre.org/techniques/T1068/), [T1078](https://attack.mitre.org/techniques/T1078/), [T1098](https://attack.mitre.org/techniques/T1098/), [T1134](https://attack.mitre.org/techniques/T1134/), [T1546.008](https://attack.mitre.org/techniques/T1546.008/), [T1546.012](https://attack.mitre.org/techniques/T1546.012/), [T1548](https://attack.mitre.org/techniques/T1548/)
- **Last Updated**: 2020-02-04

<details>
  <summary>details</summary>

#### Detection Profile

* [Child Processes of Spoolsv exe](detections.md#child-processes-of-spoolsv-exe)

* [Illegal Privilege Elevation via Mimikatz modules](detections.md#illegal-privilege-elevation-via-mimikatz-modules)

* [Overwriting Accessibility Binaries](detections.md#overwriting-accessibility-binaries)

* [Probing Access with Stolen Credentials via PowerSploit modules](detections.md#probing-access-with-stolen-credentials-via-powersploit-modules)

* [Registry Keys Used For Privilege Escalation](detections.md#registry-keys-used-for-privilege-escalation)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
| T1134 | Access Token Manipulation | Defense Evasion, Privilege Escalation |
| T1548 | Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion |
| T1546.008 | Accessibility Features | Privilege Escalation, Persistence |
| T1078 | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |
| T1098 | Account Manipulation | Persistence |
| T1546.012 | Image File Execution Options Injection | Privilege Escalation, Persistence |

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
- **Datamodel**: Endpoint, Network_Resolution, Network_Traffic
- **ATT&CK**: [T1021](https://attack.mitre.org/techniques/T1021/), [T1021.001](https://attack.mitre.org/techniques/T1021.001/), [T1048](https://attack.mitre.org/techniques/T1048/), [T1048.003](https://attack.mitre.org/techniques/T1048.003/), [T1071.001](https://attack.mitre.org/techniques/T1071.001/), [T1189](https://attack.mitre.org/techniques/T1189/)
- **Last Updated**: 2017-09-11

<details>
  <summary>details</summary>

#### Detection Profile

* [Allow Inbound Traffic By Firewall Rule Registry](detections.md#allow-inbound-traffic-by-firewall-rule-registry)

* [Allow Inbound Traffic In Firewall Rule](detections.md#allow-inbound-traffic-in-firewall-rule)

* [Detect hosts connecting to dynamic domain providers](detections.md#detect-hosts-connecting-to-dynamic-domain-providers)

* [Enable RDP In Other Port Number](detections.md#enable-rdp-in-other-port-number)

* [Prohibited Network Traffic Allowed](detections.md#prohibited-network-traffic-allowed)

* [Protocol or Port Mismatch](detections.md#protocol-or-port-mismatch)

* [TOR Traffic](detections.md#tor-traffic)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1021.001 | Remote Desktop Protocol | Lateral Movement |
| T1189 | Drive-by Compromise | Initial Access |
| T1021 | Remote Services | Lateral Movement |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |
| T1048.003 | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |
| T1071.001 | Web Protocols | Command And Control |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Delivery

* Exploitation


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
| T1557.002 | ARP Cache Poisoning | Credential Access, Collection |
| T1557 | Man-in-the-Middle | Credential Access, Collection |
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
| T1078 | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |
| T1550 | Use Alternate Authentication Material | Defense Evasion, Lateral Movement |

#### Kill Chain Phase

* Lateral Movement


#### Reference

* https://aws.amazon.com/blogs/security/aws-cloudtrail-now-tracks-cross-account-activity-to-its-origin/


_version_: 1
</details>

---

### AWS IAM Privilege Escalation
This analytic story contains detections that query your AWS Cloudtrail for activities related to privilege escalation.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1069.003](https://attack.mitre.org/techniques/T1069.003/), [T1078.004](https://attack.mitre.org/techniques/T1078.004/), [T1098](https://attack.mitre.org/techniques/T1098/), [T1110](https://attack.mitre.org/techniques/T1110/), [T1136.003](https://attack.mitre.org/techniques/T1136.003/), [T1580](https://attack.mitre.org/techniques/T1580/)
- **Last Updated**: 2021-03-08

<details>
  <summary>details</summary>

#### Detection Profile

* [AWS Create Policy Version to allow all resources](detections.md#aws-create-policy-version-to-allow-all-resources)

* [AWS CreateAccessKey](detections.md#aws-createaccesskey)

* [AWS CreateLoginProfile](detections.md#aws-createloginprofile)

* [AWS IAM Assume Role Policy Brute Force](detections.md#aws-iam-assume-role-policy-brute-force)

* [AWS IAM Delete Policy](detections.md#aws-iam-delete-policy)

* [AWS IAM Failure Group Deletion](detections.md#aws-iam-failure-group-deletion)

* [AWS IAM Successful Group Deletion](detections.md#aws-iam-successful-group-deletion)

* [AWS SetDefaultPolicyVersion](detections.md#aws-setdefaultpolicyversion)

* [AWS UpdateLoginProfile](detections.md#aws-updateloginprofile)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1078.004 | Cloud Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |
| T1136.003 | Cloud Account | Persistence |
| T1580 | Cloud Infrastructure Discovery | Discovery |
| T1110 | Brute Force | Credential Access |
| T1098 | Account Manipulation | Persistence |
| T1069.003 | Cloud Groups | Discovery |

#### Kill Chain Phase

* Actions on Objectives

* Reconnaissance


#### Reference

* https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/

* https://www.cyberark.com/resources/threat-research-blog/the-cloud-shadow-admin-threat-10-permissions-to-protect

* https://labs.bishopfox.com/tech-blog/privilege-escalation-in-aws


_version_: 1
</details>

---

### AWS Network ACL Activity
Monitor your AWS network infrastructure for bad configurations and malicious activity. Investigative searches help you probe deeper, when the facts warrant it.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1562.007](https://attack.mitre.org/techniques/T1562.007/)
- **Last Updated**: 2018-05-21

<details>
  <summary>details</summary>

#### Detection Profile

* [AWS Network Access Control List Created with All Open Ports](detections.md#aws-network-access-control-list-created-with-all-open-ports)

* [AWS Network Access Control List Deleted](detections.md#aws-network-access-control-list-deleted)

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

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
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

### AWS User Monitoring
Detect and investigate dormant user accounts for your AWS environment that have become active again. Because inactive and ad-hoc accounts are common attack targets, it's critical to enable governance within your environment.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: [T1526](https://attack.mitre.org/techniques/T1526/)
- **Last Updated**: 2018-03-12

<details>
  <summary>details</summary>

#### Detection Profile

* [AWS Excessive Security Scanning](detections.md#aws-excessive-security-scanning)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1526 | Cloud Service Discovery | Discovery |

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

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
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
| T1078.004 | Cloud Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |
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

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1003.001](https://attack.mitre.org/techniques/T1003.001/), [T1078](https://attack.mitre.org/techniques/T1078/), [T1136.003](https://attack.mitre.org/techniques/T1136.003/), [T1546.012](https://attack.mitre.org/techniques/T1546.012/), [T1556](https://attack.mitre.org/techniques/T1556/)
- **Last Updated**: 2021-01-26

<details>
  <summary>details</summary>

#### Detection Profile

* [AWS SAML Access by Provider User and Principal](detections.md#aws-saml-access-by-provider-user-and-principal)

* [AWS SAML Update identity provider](detections.md#aws-saml-update-identity-provider)

* [Certutil exe certificate extraction](detections.md#certutil-exe-certificate-extraction)

* [Detect Mimikatz Using Loaded Images](detections.md#detect-mimikatz-using-loaded-images)

* [Detect Rare Executables](detections.md#detect-rare-executables)

* [O365 Add App Role Assignment Grant User](detections.md#o365-add-app-role-assignment-grant-user)

* [O365 Added Service Principal](detections.md#o365-added-service-principal)

* [O365 Excessive SSO logon errors](detections.md#o365-excessive-sso-logon-errors)

* [O365 New Federated Domain Added](detections.md#o365-new-federated-domain-added)

* [Registry Keys Used For Privilege Escalation](detections.md#registry-keys-used-for-privilege-escalation)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1078 | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |
| T1003.001 | LSASS Memory | Credential Access |
| T1136.003 | Cloud Account | Persistence |
| T1556 | Modify Authentication Process | Credential Access, Defense Evasion, Persistence |
| T1546.012 | Image File Execution Options Injection | Privilege Escalation, Persistence |

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

* [New container uploaded to AWS ECR](detections.md#new-container-uploaded-to-aws-ecr)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1525 | Implant Internal Image | Persistence |

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

* [GCP Detect gcploit framework](detections.md#gcp-detect-gcploit-framework)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1078 | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

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

* [Kubernetes AWS detect suspicious kubectl calls](detections.md#kubernetes-aws-detect-suspicious-kubectl-calls)


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

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
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
| T1556 | Modify Authentication Process | Credential Access, Defense Evasion, Persistence |
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

### Suspicious AWS Login Activities
Monitor your AWS authentication events using your CloudTrail logs. Searches within this Analytic Story will help you stay aware of and investigate suspicious logins. 

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Authentication
- **ATT&CK**: [T1535](https://attack.mitre.org/techniques/T1535/)
- **Last Updated**: 2019-05-01

<details>
  <summary>details</summary>

#### Detection Profile

* [Detect AWS Console Login by User from New City](detections.md#detect-aws-console-login-by-user-from-new-city)

* [Detect AWS Console Login by User from New Country](detections.md#detect-aws-console-login-by-user-from-new-country)

* [Detect AWS Console Login by User from New Region](detections.md#detect-aws-console-login-by-user-from-new-region)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1535 | Unused/Unsupported Cloud Regions | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html


_version_: 1
</details>

---

### Suspicious AWS S3 Activities
Use the searches in this Analytic Story to monitor your AWS S3 buckets for evidence of anomalous activity and suspicious behaviors, such as detecting open S3 buckets and buckets being accessed from a new IP. The contextual and investigative searches will give you more information, when required.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
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

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
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

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
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
| T1078.004 | Cloud Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

#### Kill Chain Phase

* Actions on Objectives


#### Reference

* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf


_version_: 1
</details>

---

### Suspicious Cloud Provisioning Activities
Monitor your cloud infrastructure provisioning activities for behaviors originating from unfamiliar or unusual locations. These behaviors may indicate that malicious activities are occurring somewhere within your cloud environment.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
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
| T1078 | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

#### Kill Chain Phase


#### Reference

* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf


_version_: 1
</details>

---

### Suspicious Cloud User Activities
Detect and investigate suspicious activities by users and roles in your cloud environments.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Change
- **ATT&CK**: [T1078](https://attack.mitre.org/techniques/T1078/), [T1078.004](https://attack.mitre.org/techniques/T1078.004/), [T1580](https://attack.mitre.org/techniques/T1580/)
- **Last Updated**: 2020-09-04

<details>
  <summary>details</summary>

#### Detection Profile

* [AWS IAM AccessDenied Discovery Events](detections.md#aws-iam-accessdenied-discovery-events)

* [Abnormally High Number Of Cloud Infrastructure API Calls](detections.md#abnormally-high-number-of-cloud-infrastructure-api-calls)

* [Abnormally High Number Of Cloud Security Group API Calls](detections.md#abnormally-high-number-of-cloud-security-group-api-calls)

* [Cloud API Calls From Previously Unseen User Roles](detections.md#cloud-api-calls-from-previously-unseen-user-roles)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1580 | Cloud Infrastructure Discovery | Discovery |
| T1078.004 | Cloud Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |
| T1078 | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

#### Kill Chain Phase

* Actions on Objectives

* Reconnaissance


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

</details>

## Lateral Movement
<details>
  <summary>details</summary>

### PrintNightmare CVE-2021-34527
The following analytic story identifies behaviors related PrintNightmare, or CVE-2021-34527 previously known as (CVE-2021-1675), to gain privilege escalation on the vulnerable machine.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1068](https://attack.mitre.org/techniques/T1068/), [T1218.011](https://attack.mitre.org/techniques/T1218.011/), [T1547.012](https://attack.mitre.org/techniques/T1547.012/)
- **Last Updated**: 2021-07-01

<details>
  <summary>details</summary>

#### Detection Profile

* [Print Spooler Adding A Printer Driver](detections.md#print-spooler-adding-a-printer-driver)

* [Print Spooler Failed to Load a Plug-in](detections.md#print-spooler-failed-to-load-a-plug-in)

* [Rundll32 with no Command Line Arguments with Network](detections.md#rundll32-with-no-command-line-arguments-with-network)

* [Spoolsv Spawning Rundll32](detections.md#spoolsv-spawning-rundll32)

* [Spoolsv Suspicious Loaded Modules](detections.md#spoolsv-suspicious-loaded-modules)

* [Spoolsv Suspicious Process Access](detections.md#spoolsv-suspicious-process-access)

* [Spoolsv Writing a DLL](detections.md#spoolsv-writing-a-dll)

* [Spoolsv Writing a DLL - Sysmon](detections.md#spoolsv-writing-a-dll---sysmon)

* [Suspicious Rundll32 no Command Line Arguments](detections.md#suspicious-rundll32-no-command-line-arguments)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1547.012 | Print Processors | Persistence, Privilege Escalation |
| T1218.011 | Rundll32 | Defense Evasion |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |

#### Kill Chain Phase

* Actions on Objectives

* Exploitation


#### Reference

* https://github.com/cube0x0/CVE-2021-1675/

* https://blog.truesec.com/2021/06/30/fix-for-printnightmare-cve-2021-1675-exploit-to-keep-your-print-servers-running-while-a-patch-is-not-available/

* https://blog.truesec.com/2021/06/30/exploitable-critical-rce-vulnerability-allows-regular-users-to-fully-compromise-active-directory-printnightmare-cve-2021-1675/

* https://www.reddit.com/r/msp/comments/ob6y02/critical_vulnerability_printnightmare_exposes


_version_: 1
</details>

---

</details>

## Malware
<details>
  <summary>details</summary>

### Clop Ransomware
Leverage searches that allow you to detect and investigate unusual activities that might relate to the Clop ransomware, including looking for file writes associated with Clope, encrypting network shares, deleting and resizing shadow volume storage, registry key modification, deleting of security logs, and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1003.002](https://attack.mitre.org/techniques/T1003.002/), [T1070.001](https://attack.mitre.org/techniques/T1070.001/), [T1204](https://attack.mitre.org/techniques/T1204/), [T1485](https://attack.mitre.org/techniques/T1485/), [T1486](https://attack.mitre.org/techniques/T1486/), [T1489](https://attack.mitre.org/techniques/T1489/), [T1490](https://attack.mitre.org/techniques/T1490/), [T1543](https://attack.mitre.org/techniques/T1543/), [T1569.001](https://attack.mitre.org/techniques/T1569.001/), [T1569.002](https://attack.mitre.org/techniques/T1569.002/)
- **Last Updated**: 2021-03-17

<details>
  <summary>details</summary>

#### Detection Profile

* [Clop Common Exec Parameter](detections.md#clop-common-exec-parameter)

* [Clop Ransomware Known Service Name](detections.md#clop-ransomware-known-service-name)

* [Common Ransomware Extensions](detections.md#common-ransomware-extensions)

* [Common Ransomware Notes](detections.md#common-ransomware-notes)

* [Create Service In Suspicious File Path](detections.md#create-service-in-suspicious-file-path)

* [Deleting Shadow Copies](detections.md#deleting-shadow-copies)

* [High File Deletion Frequency](detections.md#high-file-deletion-frequency)

* [High Process Termination Frequency](detections.md#high-process-termination-frequency)

* [Process Deleting Its Process File Path](detections.md#process-deleting-its-process-file-path)

* [Ransomware Notes bulk creation](detections.md#ransomware-notes-bulk-creation)

* [Resize ShadowStorage volume](detections.md#resize-shadowstorage-volume)

* [Resize Shadowstorage Volume](detections.md#resize-shadowstorage-volume)

* [Suspicious Event Log Service Behavior](detections.md#suspicious-event-log-service-behavior)

* [Suspicious wevtutil Usage](detections.md#suspicious-wevtutil-usage)

* [WevtUtil Usage To Clear Logs](detections.md#wevtutil-usage-to-clear-logs)

* [Windows Event Log Cleared](detections.md#windows-event-log-cleared)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1204 | User Execution | Execution |
| T1543 | Create or Modify System Process | Persistence, Privilege Escalation |
| T1485 | Data Destruction | Impact |
| T1569.001 | Launchctl | Execution |
| T1569.002 | Service Execution | Execution |
| T1490 | Inhibit System Recovery | Impact |
| T1486 | Data Encrypted for Impact | Impact |
| T1003.002 | Security Account Manager | Credential Access |
| T1489 | Service Stop | Impact |
| T1070.001 | Clear Windows Event Logs | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives

* Exploitation

* Obfuscation

* Privilege Escalation


#### Reference

* https://www.hhs.gov/sites/default/files/analyst-note-cl0p-tlp-white.pdf

* https://securityaffairs.co/wordpress/115250/data-breach/qualys-clop-ransomware.html

* https://www.darkreading.com/attacks-breaches/qualys-is-the-latest-victim-of-accellion-data-breach/d/d-id/1340323


_version_: 1
</details>

---

### ColdRoot MacOS RAT
Leverage searches that allow you to detect and investigate unusual activities that relate to the ColdRoot Remote Access Trojan that affects MacOS. An example of some of these activities are changing sensative binaries in the MacOS sub-system, detecting process names and executables associated with the RAT, detecting when a keyboard tab is installed on a MacOS machine and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **ATT&CK**: 
- **Last Updated**: 2019-01-09

<details>
  <summary>details</summary>

#### Detection Profile

* [Processes Tapping Keyboard Events](detections.md#processes-tapping-keyboard-events)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|

#### Kill Chain Phase

* Command and Control


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
- **ATT&CK**: [T1021.002](https://attack.mitre.org/techniques/T1021.002/), [T1053.005](https://attack.mitre.org/techniques/T1053.005/), [T1059.001](https://attack.mitre.org/techniques/T1059.001/), [T1071.002](https://attack.mitre.org/techniques/T1071.002/), [T1112](https://attack.mitre.org/techniques/T1112/), [T1136.001](https://attack.mitre.org/techniques/T1136.001/), [T1204.002](https://attack.mitre.org/techniques/T1204.002/), [T1543.003](https://attack.mitre.org/techniques/T1543.003/), [T1547.001](https://attack.mitre.org/techniques/T1547.001/), [T1562.004](https://attack.mitre.org/techniques/T1562.004/), [T1569.002](https://attack.mitre.org/techniques/T1569.002/)
- **Last Updated**: 2020-01-22

<details>
  <summary>details</summary>

#### Detection Profile

* [Create local admin accounts using net exe](detections.md#create-local-admin-accounts-using-net-exe)

* [Detect New Local Admin account](detections.md#detect-new-local-admin-account)

* [Detect Outbound SMB Traffic](detections.md#detect-outbound-smb-traffic)

* [Detect PsExec With accepteula Flag](detections.md#detect-psexec-with-accepteula-flag)

* [Detect Renamed PSExec](detections.md#detect-renamed-psexec)

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
| T1071.002 | File Transfer Protocols | Command And Control |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| T1569.002 | Service Execution | Execution |
| T1059.001 | PowerShell | Execution |
| T1562.004 | Disable or Modify System Firewall | Defense Evasion |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation |
| T1543.003 | Windows Service | Persistence, Privilege Escalation |
| T1053.005 | Scheduled Task | Execution, Persistence, Privilege Escalation |
| T1204.002 | Malicious File | Execution |
| T1112 | Modify Registry | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Execution

* Exploitation

* Installation

* Lateral Movement


#### Reference

* https://www.us-cert.gov/ncas/alerts/TA18-074A


_version_: 2
</details>

---

### DarkSide Ransomware
Leverage searches that allow you to detect and investigate unusual activities that might relate to the DarkSide Ransomware

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1003.001](https://attack.mitre.org/techniques/T1003.001/), [T1003.002](https://attack.mitre.org/techniques/T1003.002/), [T1020](https://attack.mitre.org/techniques/T1020/), [T1021.002](https://attack.mitre.org/techniques/T1021.002/), [T1055](https://attack.mitre.org/techniques/T1055/), [T1105](https://attack.mitre.org/techniques/T1105/), [T1197](https://attack.mitre.org/techniques/T1197/), [T1218.003](https://attack.mitre.org/techniques/T1218.003/), [T1486](https://attack.mitre.org/techniques/T1486/), [T1490](https://attack.mitre.org/techniques/T1490/), [T1548.002](https://attack.mitre.org/techniques/T1548.002/), [T1569.002](https://attack.mitre.org/techniques/T1569.002/)
- **Last Updated**: 2021-05-12

<details>
  <summary>details</summary>

#### Detection Profile

* [Attempted Credential Dump From Registry via Reg exe](detections.md#attempted-credential-dump-from-registry-via-reg-exe)

* [BITSAdmin Download File](detections.md#bitsadmin-download-file)

* [CMLUA Or CMSTPLUA UAC Bypass](detections.md#cmlua-or-cmstplua-uac-bypass)

* [CertUtil Download With URLCache and Split Arguments](detections.md#certutil-download-with-urlcache-and-split-arguments)

* [CertUtil Download With VerifyCtl and Split Arguments](detections.md#certutil-download-with-verifyctl-and-split-arguments)

* [Cobalt Strike Named Pipes](detections.md#cobalt-strike-named-pipes)

* [Delete ShadowCopy With PowerShell](detections.md#delete-shadowcopy-with-powershell)

* [Detect Mimikatz Using Loaded Images](detections.md#detect-mimikatz-using-loaded-images)

* [Detect PsExec With accepteula Flag](detections.md#detect-psexec-with-accepteula-flag)

* [Detect RClone Command-Line Usage](detections.md#detect-rclone-command-line-usage)

* [Detect Renamed PSExec](detections.md#detect-renamed-psexec)

* [Detect Renamed RClone](detections.md#detect-renamed-rclone)

* [Extract SAM from Registry](detections.md#extract-sam-from-registry)

* [Ransomware Notes bulk creation](detections.md#ransomware-notes-bulk-creation)

* [SLUI RunAs Elevated](detections.md#slui-runas-elevated)

* [SLUI Spawning a Process](detections.md#slui-spawning-a-process)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1003.002 | Security Account Manager | Credential Access |
| T1197 | BITS Jobs | Defense Evasion, Persistence |
| T1105 | Ingress Tool Transfer | Command And Control |
| T1218.003 | CMSTP | Defense Evasion |
| T1055 | Process Injection | Defense Evasion, Privilege Escalation |
| T1490 | Inhibit System Recovery | Impact |
| T1003.001 | LSASS Memory | Credential Access |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| T1020 | Automated Exfiltration | Exfiltration |
| T1569.002 | Service Execution | Execution |
| T1486 | Data Encrypted for Impact | Impact |
| T1548.002 | Bypass User Account Control | Privilege Escalation, Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives

* Execution

* Exfiltration

* Exploitation

* Lateral Movement

* Obfuscation


#### Reference

* https://www.splunk.com/en_us/blog/security/the-darkside-of-the-ransomware-pipeline.htmlbig-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/

* https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html


_version_: 1
</details>

---

### Dynamic DNS
Detect and investigate hosts in your environment that may be communicating with dynamic domain providers. Attackers may leverage these services to help them avoid firewall blocks and deny lists.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint, Network_Resolution
- **ATT&CK**: [T1048](https://attack.mitre.org/techniques/T1048/), [T1189](https://attack.mitre.org/techniques/T1189/)
- **Last Updated**: 2018-09-06

<details>
  <summary>details</summary>

#### Detection Profile

* [DNS Exfiltration Using Nslookup App](detections.md#dns-exfiltration-using-nslookup-app)

* [Detect hosts connecting to dynamic domain providers](detections.md#detect-hosts-connecting-to-dynamic-domain-providers)

* [Excessive Usage of NSLOOKUP App](detections.md#excessive-usage-of-nslookup-app)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |
| T1071.004 | DNS | Command And Control |
| T1048.003 | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |
| T1095 | Non-Application Layer Protocol | Command And Control |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1189 | Drive-by Compromise | Initial Access |
| T1114.001 | Local Email Collection | Collection |
| T1114 | Email Collection | Collection |
| T1114.003 | Email Forwarding Rule | Collection |
| T1071.001 | Web Protocols | Command And Control |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Exploitation


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
- **ATT&CK**: [T1021.001](https://attack.mitre.org/techniques/T1021.001/), [T1021.002](https://attack.mitre.org/techniques/T1021.002/), [T1048.003](https://attack.mitre.org/techniques/T1048.003/), [T1070.005](https://attack.mitre.org/techniques/T1070.005/), [T1071.002](https://attack.mitre.org/techniques/T1071.002/), [T1071.004](https://attack.mitre.org/techniques/T1071.004/)
- **Last Updated**: 2020-01-22

<details>
  <summary>details</summary>

#### Detection Profile

* [Create or delete windows shares using net exe](detections.md#create-or-delete-windows-shares-using-net-exe)

* [DNS Query Length Outliers - MLTK](detections.md#dns-query-length-outliers---mltk)

* [DNS Query Length With High Standard Deviation](detections.md#dns-query-length-with-high-standard-deviation)

* [Detect Outbound SMB Traffic](detections.md#detect-outbound-smb-traffic)

* [Remote Desktop Network Traffic](detections.md#remote-desktop-network-traffic)

* [Remote Desktop Process Running On System](detections.md#remote-desktop-process-running-on-system)

* [SMB Traffic Spike](detections.md#smb-traffic-spike)

* [SMB Traffic Spike - MLTK](detections.md#smb-traffic-spike---mltk)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1070.005 | Network Share Connection Removal | Defense Evasion |
| T1071.004 | DNS | Command And Control |
| T1048.003 | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |
| T1071.002 | File Transfer Protocols | Command And Control |
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
- **ATT&CK**: [T1543.003](https://attack.mitre.org/techniques/T1543.003/), [T1569.002](https://attack.mitre.org/techniques/T1569.002/)
- **Last Updated**: 2020-01-22

<details>
  <summary>details</summary>

#### Detection Profile

* [First Time Seen Running Windows Service](detections.md#first-time-seen-running-windows-service)

* [Sc exe Manipulating Windows Services](detections.md#sc-exe-manipulating-windows-services)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1569.002 | Service Execution | Execution |
| T1055 | Process Injection | Defense Evasion, Privilege Escalation |
| T1106 | Native API | Execution |
| T1569 | System Services | Execution |
| T1574.011 | Services Registry Permissions Weakness | Persistence, Privilege Escalation, Defense Evasion |
| T1543.003 | Windows Service | Persistence, Privilege Escalation |

#### Kill Chain Phase

* Actions on Objectives

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
- **ATT&CK**: [T1020](https://attack.mitre.org/techniques/T1020/), [T1021.002](https://attack.mitre.org/techniques/T1021.002/), [T1027.005](https://attack.mitre.org/techniques/T1027.005/), [T1036.003](https://attack.mitre.org/techniques/T1036.003/), [T1047](https://attack.mitre.org/techniques/T1047/), [T1048](https://attack.mitre.org/techniques/T1048/), [T1053.005](https://attack.mitre.org/techniques/T1053.005/), [T1059.005](https://attack.mitre.org/techniques/T1059.005/), [T1069.001](https://attack.mitre.org/techniques/T1069.001/), [T1069.002](https://attack.mitre.org/techniques/T1069.002/), [T1070](https://attack.mitre.org/techniques/T1070/), [T1070.001](https://attack.mitre.org/techniques/T1070.001/), [T1070.004](https://attack.mitre.org/techniques/T1070.004/), [T1071.001](https://attack.mitre.org/techniques/T1071.001/), [T1087.001](https://attack.mitre.org/techniques/T1087.001/), [T1087.002](https://attack.mitre.org/techniques/T1087.002/), [T1112](https://attack.mitre.org/techniques/T1112/), [T1204](https://attack.mitre.org/techniques/T1204/), [T1218.003](https://attack.mitre.org/techniques/T1218.003/), [T1222](https://attack.mitre.org/techniques/T1222/), [T1482](https://attack.mitre.org/techniques/T1482/), [T1485](https://attack.mitre.org/techniques/T1485/), [T1489](https://attack.mitre.org/techniques/T1489/), [T1490](https://attack.mitre.org/techniques/T1490/), [T1491](https://attack.mitre.org/techniques/T1491/), [T1531](https://attack.mitre.org/techniques/T1531/), [T1547.001](https://attack.mitre.org/techniques/T1547.001/), [T1548](https://attack.mitre.org/techniques/T1548/), [T1562.001](https://attack.mitre.org/techniques/T1562.001/), [T1562.007](https://attack.mitre.org/techniques/T1562.007/), [T1569.002](https://attack.mitre.org/techniques/T1569.002/), [T1574.002](https://attack.mitre.org/techniques/T1574.002/), [T1592](https://attack.mitre.org/techniques/T1592/)
- **Last Updated**: 2020-02-04

<details>
  <summary>details</summary>

#### Detection Profile

* [Allow File And Printing Sharing In Firewall](detections.md#allow-file-and-printing-sharing-in-firewall)

* [Allow Network Discovery In Firewall](detections.md#allow-network-discovery-in-firewall)

* [Allow Operation with Consent Admin](detections.md#allow-operation-with-consent-admin)

* [Attempt To Disable Services](detections.md#attempt-to-disable-services)

* [Attempt To delete Services](detections.md#attempt-to-delete-services)

* [BCDEdit Failure Recovery Modification](detections.md#bcdedit-failure-recovery-modification)

* [CMLUA Or CMSTPLUA UAC Bypass](detections.md#cmlua-or-cmstplua-uac-bypass)

* [Clear Unallocated Sector Using Cipher App](detections.md#clear-unallocated-sector-using-cipher-app)

* [Common Ransomware Extensions](detections.md#common-ransomware-extensions)

* [Common Ransomware Notes](detections.md#common-ransomware-notes)

* [Conti Common Exec parameter](detections.md#conti-common-exec-parameter)

* [Delete A Net User](detections.md#delete-a-net-user)

* [Delete ShadowCopy With PowerShell](detections.md#delete-shadowcopy-with-powershell)

* [Deleting Shadow Copies](detections.md#deleting-shadow-copies)

* [Detect RClone Command-Line Usage](detections.md#detect-rclone-command-line-usage)

* [Detect Renamed RClone](detections.md#detect-renamed-rclone)

* [Detect SharpHound Command-Line Arguments](detections.md#detect-sharphound-command-line-arguments)

* [Detect SharpHound File Modifications](detections.md#detect-sharphound-file-modifications)

* [Detect SharpHound Usage](detections.md#detect-sharphound-usage)

* [Disable AMSI Through Registry](detections.md#disable-amsi-through-registry)

* [Disable ETW Through Registry](detections.md#disable-etw-through-registry)

* [Disable Logs Using WevtUtil](detections.md#disable-logs-using-wevtutil)

* [Disable Net User Account](detections.md#disable-net-user-account)

* [Disable Windows Behavior Monitoring](detections.md#disable-windows-behavior-monitoring)

* [Excessive Service Stop Attempt](detections.md#excessive-service-stop-attempt)

* [Excessive Usage Of Net App](detections.md#excessive-usage-of-net-app)

* [Excessive Usage Of SC Service Utility](detections.md#excessive-usage-of-sc-service-utility)

* [Execute Javascript With Jscript COM CLSID](detections.md#execute-javascript-with-jscript-com-clsid)

* [ICACLS Grant Command](detections.md#icacls-grant-command)

* [Known Services Killed by Ransomware](detections.md#known-services-killed-by-ransomware)

* [Modification Of Wallpaper](detections.md#modification-of-wallpaper)

* [Msmpeng Application DLL Side Loading](detections.md#msmpeng-application-dll-side-loading)

* [Permission Modification using Takeown App](detections.md#permission-modification-using-takeown-app)

* [Powershell Disable Security Monitoring](detections.md#powershell-disable-security-monitoring)

* [Powershell Enable SMB1Protocol Feature](detections.md#powershell-enable-smb1protocol-feature)

* [Prevent Automatic Repair Mode using Bcdedit](detections.md#prevent-automatic-repair-mode-using-bcdedit)

* [Prohibited Network Traffic Allowed](detections.md#prohibited-network-traffic-allowed)

* [Recon AVProduct Through Pwh or WMI](detections.md#recon-avproduct-through-pwh-or-wmi)

* [Recursive Delete of Directory In Batch CMD](detections.md#recursive-delete-of-directory-in-batch-cmd)

* [Registry Keys Used For Persistence](detections.md#registry-keys-used-for-persistence)

* [Remote Process Instantiation via WMI](detections.md#remote-process-instantiation-via-wmi)

* [Resize Shadowstorage Volume](detections.md#resize-shadowstorage-volume)

* [Revil Common Exec Parameter](detections.md#revil-common-exec-parameter)

* [Revil Registry Entry](detections.md#revil-registry-entry)

* [SMB Traffic Spike](detections.md#smb-traffic-spike)

* [SMB Traffic Spike - MLTK](detections.md#smb-traffic-spike---mltk)

* [Schtasks used for forcing a reboot](detections.md#schtasks-used-for-forcing-a-reboot)

* [Spike in File Writes](detections.md#spike-in-file-writes)

* [Start Up During Safe Mode Boot](detections.md#start-up-during-safe-mode-boot)

* [Suspicious Event Log Service Behavior](detections.md#suspicious-event-log-service-behavior)

* [Suspicious Scheduled Task from Public Directory](detections.md#suspicious-scheduled-task-from-public-directory)

* [Suspicious wevtutil Usage](detections.md#suspicious-wevtutil-usage)

* [System Processes Run From Unexpected Locations](detections.md#system-processes-run-from-unexpected-locations)

* [TOR Traffic](detections.md#tor-traffic)

* [USN Journal Deletion](detections.md#usn-journal-deletion)

* [Unusually Long Command Line](detections.md#unusually-long-command-line)

* [Unusually Long Command Line - MLTK](detections.md#unusually-long-command-line---mltk)

* [WBAdmin Delete System Backups](detections.md#wbadmin-delete-system-backups)

* [Wbemprox COM Object Execution](detections.md#wbemprox-com-object-execution)

* [WevtUtil Usage To Clear Logs](detections.md#wevtutil-usage-to-clear-logs)

* [Wevtutil Usage To Disable Logs](detections.md#wevtutil-usage-to-disable-logs)

* [WinEvent Scheduled Task Created Within Public Path](detections.md#winevent-scheduled-task-created-within-public-path)

* [WinEvent Scheduled Task Created to Spawn Shell](detections.md#winevent-scheduled-task-created-to-spawn-shell)

* [Windows Event Log Cleared](detections.md#windows-event-log-cleared)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1562.007 | Disable or Modify Cloud Firewall | Defense Evasion |
| T1548 | Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion |
| T1489 | Service Stop | Impact |
| T1490 | Inhibit System Recovery | Impact |
| T1218.003 | CMSTP | Defense Evasion |
| T1070.004 | File Deletion | Defense Evasion |
| T1485 | Data Destruction | Impact |
| T1204 | User Execution | Execution |
| T1020 | Automated Exfiltration | Exfiltration |
| T1087.002 | Domain Account | Discovery |
| T1087.001 | Local Account | Discovery |
| T1482 | Domain Trust Discovery | Discovery |
| T1069.002 | Domain Groups | Discovery |
| T1069.001 | Local Groups | Discovery |
| T1562.001 | Disable or Modify Tools | Defense Evasion |
| T1070.001 | Clear Windows Event Logs | Defense Evasion |
| T1531 | Account Access Removal | Impact |
| T1569.002 | Service Execution | Execution |
| T1059.005 | Visual Basic | Execution |
| T1222 | File and Directory Permissions Modification | Defense Evasion |
| T1491 | Defacement | Impact |
| T1574.002 | DLL Side-Loading | Persistence, Privilege Escalation, Defense Evasion |
| T1027.005 | Indicator Removal from Tools | Defense Evasion |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |
| T1592 | Gather Victim Host Information | Reconnaissance |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation |
| T1047 | Windows Management Instrumentation | Execution |
| T1112 | Modify Registry | Defense Evasion |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| T1053.005 | Scheduled Task | Execution, Persistence, Privilege Escalation |
| T1036.003 | Rename System Utilities | Defense Evasion |
| T1071.001 | Web Protocols | Command And Control |
| T1070 | Indicator Removal on Host | Defense Evasion |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Delivery

* Exfiltration

* Exploitation

* Privilege Escalation

* Reconnaissance


#### Reference

* https://www.carbonblack.com/2017/06/28/carbon-black-threat-research-technical-analysis-petya-notpetya-ransomware/

* https://www.splunk.com/blog/2017/06/27/closing-the-detection-to-mitigation-gap-or-to-petya-or-notpetya-whocares-.html


_version_: 1
</details>

---

### Ransomware Cloud
Leverage searches that allow you to detect and investigate unusual activities that might relate to ransomware. These searches include cloud related objects that may be targeted by malicious actors via cloud providers own encryption features.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
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

### Revil Ransomware
Leverage searches that allow you to detect and investigate unusual activities that might relate to the Revil ransomware, including looking for file writes associated with Revil, encrypting network shares, deleting shadow volume storage, registry key modification, deleting of security logs, and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1112](https://attack.mitre.org/techniques/T1112/), [T1204](https://attack.mitre.org/techniques/T1204/), [T1218.003](https://attack.mitre.org/techniques/T1218.003/), [T1490](https://attack.mitre.org/techniques/T1490/), [T1491](https://attack.mitre.org/techniques/T1491/), [T1562.001](https://attack.mitre.org/techniques/T1562.001/), [T1562.007](https://attack.mitre.org/techniques/T1562.007/), [T1574.002](https://attack.mitre.org/techniques/T1574.002/)
- **Last Updated**: 2021-06-04

<details>
  <summary>details</summary>

#### Detection Profile

* [Allow Network Discovery In Firewall](detections.md#allow-network-discovery-in-firewall)

* [Delete ShadowCopy With PowerShell](detections.md#delete-shadowcopy-with-powershell)

* [Disable Windows Behavior Monitoring](detections.md#disable-windows-behavior-monitoring)

* [Modification Of Wallpaper](detections.md#modification-of-wallpaper)

* [Msmpeng Application DLL Side Loading](detections.md#msmpeng-application-dll-side-loading)

* [Powershell Disable Security Monitoring](detections.md#powershell-disable-security-monitoring)

* [Revil Common Exec Parameter](detections.md#revil-common-exec-parameter)

* [Revil Registry Entry](detections.md#revil-registry-entry)

* [Wbemprox COM Object Execution](detections.md#wbemprox-com-object-execution)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1562.007 | Disable or Modify Cloud Firewall | Defense Evasion |
| T1490 | Inhibit System Recovery | Impact |
| T1562.001 | Disable or Modify Tools | Defense Evasion |
| T1491 | Defacement | Impact |
| T1574.002 | DLL Side-Loading | Persistence, Privilege Escalation, Defense Evasion |
| T1204 | User Execution | Execution |
| T1112 | Modify Registry | Defense Evasion |
| T1218.003 | CMSTP | Defense Evasion |

#### Kill Chain Phase

* Exploitation


#### Reference

* https://krebsonsecurity.com/2021/05/a-closer-look-at-the-darkside-ransomware-gang/

* https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-what-the-code-tells-us/


_version_: 1
</details>

---

### Ryuk Ransomware
Leverage searches that allow you to detect and investigate unusual activities that might relate to the Ryuk ransomware, including looking for file writes associated with Ryuk, Stopping Security Access Manager, DisableAntiSpyware registry key modification, suspicious psexec use, and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint, Network_Traffic
- **ATT&CK**: [T1021.001](https://attack.mitre.org/techniques/T1021.001/), [T1053.005](https://attack.mitre.org/techniques/T1053.005/), [T1059.003](https://attack.mitre.org/techniques/T1059.003/), [T1482](https://attack.mitre.org/techniques/T1482/), [T1485](https://attack.mitre.org/techniques/T1485/), [T1486](https://attack.mitre.org/techniques/T1486/), [T1489](https://attack.mitre.org/techniques/T1489/), [T1490](https://attack.mitre.org/techniques/T1490/), [T1562.001](https://attack.mitre.org/techniques/T1562.001/)
- **Last Updated**: 2020-11-06

<details>
  <summary>details</summary>

#### Detection Profile

* [BCDEdit Failure Recovery Modification](detections.md#bcdedit-failure-recovery-modification)

* [Common Ransomware Extensions](detections.md#common-ransomware-extensions)

* [Common Ransomware Notes](detections.md#common-ransomware-notes)

* [NLTest Domain Trust Discovery](detections.md#nltest-domain-trust-discovery)

* [Remote Desktop Network Bruteforce](detections.md#remote-desktop-network-bruteforce)

* [Remote Desktop Network Traffic](detections.md#remote-desktop-network-traffic)

* [Ryuk Test Files Detected](detections.md#ryuk-test-files-detected)

* [Ryuk Wake on LAN Command](detections.md#ryuk-wake-on-lan-command)

* [Spike in File Writes](detections.md#spike-in-file-writes)

* [Suspicious Scheduled Task from Public Directory](detections.md#suspicious-scheduled-task-from-public-directory)

* [WBAdmin Delete System Backups](detections.md#wbadmin-delete-system-backups)

* [WinEvent Scheduled Task Created Within Public Path](detections.md#winevent-scheduled-task-created-within-public-path)

* [WinEvent Scheduled Task Created to Spawn Shell](detections.md#winevent-scheduled-task-created-to-spawn-shell)

* [Windows DisableAntiSpyware Registry](detections.md#windows-disableantispyware-registry)

* [Windows Security Account Manager Stopped](detections.md#windows-security-account-manager-stopped)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1490 | Inhibit System Recovery | Impact |
| T1485 | Data Destruction | Impact |
| T1482 | Domain Trust Discovery | Discovery |
| T1021.001 | Remote Desktop Protocol | Lateral Movement |
| T1486 | Data Encrypted for Impact | Impact |
| T1059.003 | Windows Command Shell | Execution |
| T1053.005 | Scheduled Task | Execution, Persistence, Privilege Escalation |
| T1562.001 | Disable or Modify Tools | Defense Evasion |
| T1489 | Service Stop | Impact |

#### Kill Chain Phase

* Actions on Objectives

* Delivery

* Exploitation

* Lateral Movement

* Privilege Escalation

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
- **ATT&CK**: [T1021.001](https://attack.mitre.org/techniques/T1021.001/), [T1021.002](https://attack.mitre.org/techniques/T1021.002/), [T1082](https://attack.mitre.org/techniques/T1082/), [T1204.002](https://attack.mitre.org/techniques/T1204.002/), [T1485](https://attack.mitre.org/techniques/T1485/), [T1486](https://attack.mitre.org/techniques/T1486/), [T1490](https://attack.mitre.org/techniques/T1490/), [T1569.002](https://attack.mitre.org/techniques/T1569.002/)
- **Last Updated**: 2018-12-13

<details>
  <summary>details</summary>

#### Detection Profile

* [Batch File Write to System32](detections.md#batch-file-write-to-system32)

* [Common Ransomware Extensions](detections.md#common-ransomware-extensions)

* [Common Ransomware Notes](detections.md#common-ransomware-notes)

* [Deleting Shadow Copies](detections.md#deleting-shadow-copies)

* [Detect PsExec With accepteula Flag](detections.md#detect-psexec-with-accepteula-flag)

* [Detect Renamed PSExec](detections.md#detect-renamed-psexec)

* [Detect attackers scanning for vulnerable JBoss servers](detections.md#detect-attackers-scanning-for-vulnerable-jboss-servers)

* [Detect malicious requests to exploit JBoss servers](detections.md#detect-malicious-requests-to-exploit-jboss-servers)

* [File with Samsam Extension](detections.md#file-with-samsam-extension)

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
| T1569.002 | Service Execution | Execution |
| T1082 | System Information Discovery | Discovery |
| T1021.001 | Remote Desktop Protocol | Lateral Movement |
| T1486 | Data Encrypted for Impact | Impact |

#### Kill Chain Phase

* Actions on Objectives

* Delivery

* Execution

* Exploitation

* Installation

* Lateral Movement

* Reconnaissance


#### Reference

* https://www.crowdstrike.com/blog/an-in-depth-analysis-of-samsam-ransomware-and-boss-spider/

* https://nakedsecurity.sophos.com/2018/07/31/samsam-the-almost-6-million-ransomware/

* https://thehackernews.com/2018/07/samsam-ransomware-attacks.html


_version_: 1
</details>

---

### Trickbot
Leverage searches that allow you to detect and investigate unusual activities that might relate to the trickbot banking trojan, including looking for file writes associated with its payload, process injection, shellcode execution and data collection even in LDAP environment.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1021.002](https://attack.mitre.org/techniques/T1021.002/), [T1027](https://attack.mitre.org/techniques/T1027/), [T1053](https://attack.mitre.org/techniques/T1053/), [T1055](https://attack.mitre.org/techniques/T1055/), [T1059](https://attack.mitre.org/techniques/T1059/), [T1087.002](https://attack.mitre.org/techniques/T1087.002/), [T1218.011](https://attack.mitre.org/techniques/T1218.011/), [T1562.001](https://attack.mitre.org/techniques/T1562.001/), [T1566.001](https://attack.mitre.org/techniques/T1566.001/), [T1590.005](https://attack.mitre.org/techniques/T1590.005/)
- **Last Updated**: 2021-04-20

<details>
  <summary>details</summary>

#### Detection Profile

* [Account Discovery With Net App](detections.md#account-discovery-with-net-app)

* [Attempt To Stop Security Service](detections.md#attempt-to-stop-security-service)

* [Cobalt Strike Named Pipes](detections.md#cobalt-strike-named-pipes)

* [Office Application Spawn rundll32 process](detections.md#office-application-spawn-rundll32-process)

* [Office Document Executing Macro Code](detections.md#office-document-executing-macro-code)

* [Powershell Remote Thread To Known Windows Process](detections.md#powershell-remote-thread-to-known-windows-process)

* [Schedule Task with Rundll32 Command Trigger](detections.md#schedule-task-with-rundll32-command-trigger)

* [Suspicious Rundll32 StartW](detections.md#suspicious-rundll32-startw)

* [Trickbot Named Pipe](detections.md#trickbot-named-pipe)

* [Wermgr Process Connecting To IP Check Web Services](detections.md#wermgr-process-connecting-to-ip-check-web-services)

* [Wermgr Process Create Executable File](detections.md#wermgr-process-create-executable-file)

* [Wermgr Process Spawned CMD Or Powershell Process](detections.md#wermgr-process-spawned-cmd-or-powershell-process)

* [Write Executable in SMB Share](detections.md#write-executable-in-smb-share)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1087.002 | Domain Account | Discovery |
| T1562.001 | Disable or Modify Tools | Defense Evasion |
| T1055 | Process Injection | Defense Evasion, Privilege Escalation |
| T1566.001 | Spearphishing Attachment | Initial Access |
| T1053 | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |
| T1218.011 | Rundll32 | Defense Evasion |
| T1590.005 | IP Addresses | Reconnaissance |
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1059 | Command and Scripting Interpreter | Execution |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |

#### Kill Chain Phase

* Actions on Objectives

* Exploitation

* Installation

* Lateral Movement


#### Reference

* https://en.wikipedia.org/wiki/Trickbot

* https://blog.checkpoint.com/2021/03/11/february-2021s-most-wanted-malware-trickbot-takes-over-following-emotet-shutdown/


_version_: 1
</details>

---

### Unusual Processes
Quickly identify systems running new or unusual processes in your environment that could be indicators of suspicious activity. Processes run from unusual locations, those with conspicuously long command lines, and rare executables are all examples of activities that may warrant deeper investigation.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1003](https://attack.mitre.org/techniques/T1003/), [T1016](https://attack.mitre.org/techniques/T1016/), [T1036.003](https://attack.mitre.org/techniques/T1036.003/), [T1053](https://attack.mitre.org/techniques/T1053/), [T1059](https://attack.mitre.org/techniques/T1059/), [T1072](https://attack.mitre.org/techniques/T1072/), [T1117](https://attack.mitre.org/techniques/T1117/), [T1190](https://attack.mitre.org/techniques/T1190/), [T1202](https://attack.mitre.org/techniques/T1202/), [T1203](https://attack.mitre.org/techniques/T1203/), [T1218.011](https://attack.mitre.org/techniques/T1218.011/)
- **Last Updated**: 2020-02-04

<details>
  <summary>details</summary>

#### Detection Profile

* [Credential Extraction indicative of FGDump and CacheDump with s option](detections.md#credential-extraction-indicative-of-fgdump-and-cachedump-with-s-option)

* [Credential Extraction indicative of FGDump and CacheDump with v option](detections.md#credential-extraction-indicative-of-fgdump-and-cachedump-with-v-option)

* [Credential Extraction indicative of use of Mimikatz modules](detections.md#credential-extraction-indicative-of-use-of-mimikatz-modules)

* [Credential Extraction native Microsoft debuggers peek into the kernel](detections.md#credential-extraction-native-microsoft-debuggers-peek-into-the-kernel)

* [Credential Extraction native Microsoft debuggers via z command line option](detections.md#credential-extraction-native-microsoft-debuggers-via-z-command-line-option)

* [Detect Rare Executables](detections.md#detect-rare-executables)

* [Detect processes used for System Network Configuration Discovery](detections.md#detect-processes-used-for-system-network-configuration-discovery)

* [First time seen command line argument](detections.md#first-time-seen-command-line-argument)

* [More than usual number of LOLBAS applications in short time period](detections.md#more-than-usual-number-of-lolbas-applications-in-short-time-period)

* [Rare Parent-Child Process Relationship](detections.md#rare-parent-child-process-relationship)

* [RunDLL Loading DLL By Ordinal](detections.md#rundll-loading-dll-by-ordinal)

* [System Processes Run From Unexpected Locations](detections.md#system-processes-run-from-unexpected-locations)

* [Unusually Long Command Line](detections.md#unusually-long-command-line)

* [Unusually Long Command Line - MLTK](detections.md#unusually-long-command-line---mltk)

* [WinRM Spawning a Process](detections.md#winrm-spawning-a-process)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1003 | OS Credential Dumping | Credential Access |
| T1016 | System Network Configuration Discovery | Discovery |
| T1059 | Command and Scripting Interpreter | Execution |
| T1117 | Regsvr32 |  |
| T1202 | Indirect Command Execution | Defense Evasion |
| T1053 | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |
| T1203 | Exploitation for Client Execution | Execution |
| T1072 | Software Deployment Tools | Execution, Lateral Movement |
| T1218.011 | Rundll32 | Defense Evasion |
| T1036.003 | Rename System Utilities | Defense Evasion |
| T1190 | Exploit Public-Facing Application | Initial Access |

#### Kill Chain Phase

* Actions on Objectives

* Command and Control

* Denial of Service

* Exploitation

* Installation

* Privilege Escalation


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
- **ATT&CK**: [T1036.003](https://attack.mitre.org/techniques/T1036.003/)
- **Last Updated**: 2018-01-26

<details>
  <summary>details</summary>

#### Detection Profile

* [Execution of File with Multiple Extensions](detections.md#execution-of-file-with-multiple-extensions)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1036.003 | Rename System Utilities | Defense Evasion |
| T1127.001 | MSBuild | Defense Evasion |
| T1218.011 | Rundll32 | Defense Evasion |
| T1127 | Trusted Developer Utilities Proxy Execution | Defense Evasion |
| T1036 | Masquerading | Defense Evasion |

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
- **ATT&CK**: [T1055](https://attack.mitre.org/techniques/T1055/), [T1106](https://attack.mitre.org/techniques/T1106/), [T1543.003](https://attack.mitre.org/techniques/T1543.003/), [T1569](https://attack.mitre.org/techniques/T1569/), [T1569.002](https://attack.mitre.org/techniques/T1569.002/), [T1574.011](https://attack.mitre.org/techniques/T1574.011/)
- **Last Updated**: 2017-11-02

<details>
  <summary>details</summary>

#### Detection Profile

* [First Time Seen Running Windows Service](detections.md#first-time-seen-running-windows-service)

* [Illegal Service and Process Control via Mimikatz modules](detections.md#illegal-service-and-process-control-via-mimikatz-modules)

* [Illegal Service and Process Control via PowerSploit modules](detections.md#illegal-service-and-process-control-via-powersploit-modules)

* [Reg exe Manipulating Windows Services Registry Keys](detections.md#reg-exe-manipulating-windows-services-registry-keys)

* [Sc exe Manipulating Windows Services](detections.md#sc-exe-manipulating-windows-services)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1569.002 | Service Execution | Execution |
| T1055 | Process Injection | Defense Evasion, Privilege Escalation |
| T1106 | Native API | Execution |
| T1569 | System Services | Execution |
| T1574.011 | Services Registry Permissions Weakness | Persistence, Privilege Escalation, Defense Evasion |
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

### XMRig
Leverage searches that allow you to detect and investigate unusual activities that might relate to the xmrig monero, including looking for file writes associated with its payload, process command-line, defense evasion (killing services, deleting users, modifying files or folder permission, killing other malware or other coin miner) and hacking tools including Telegram as mean of command and control (C2) to download other files. Adversaries may leverage the resources of co-opted systems in order to solve resource intensive problems which may impact system and/or hosted service availability. One common purpose for Resource Hijacking is to validate transactions of cryptocurrency networks and earn virtual currency. Adversaries may consume enough system resources to negatively impact and/or cause affected machines to become unresponsive. (1) Servers and cloud-based (2) systems are common targets because of the high potential for available resources, but user endpoint systems may also be compromised and used for Resource Hijacking and cryptocurrency mining.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: Endpoint
- **ATT&CK**: [T1036](https://attack.mitre.org/techniques/T1036/), [T1053](https://attack.mitre.org/techniques/T1053/), [T1087](https://attack.mitre.org/techniques/T1087/), [T1105](https://attack.mitre.org/techniques/T1105/), [T1222](https://attack.mitre.org/techniques/T1222/), [T1489](https://attack.mitre.org/techniques/T1489/), [T1531](https://attack.mitre.org/techniques/T1531/), [T1543](https://attack.mitre.org/techniques/T1543/), [T1543.003](https://attack.mitre.org/techniques/T1543.003/), [T1562.001](https://attack.mitre.org/techniques/T1562.001/)
- **Last Updated**: 2021-05-07

<details>
  <summary>details</summary>

#### Detection Profile

* [Attempt To Disable Services](detections.md#attempt-to-disable-services)

* [Attempt To delete Services](detections.md#attempt-to-delete-services)

* [Delete A Net User](detections.md#delete-a-net-user)

* [Deleting Of Net Users](detections.md#deleting-of-net-users)

* [Deny Permission using Cacls Utility](detections.md#deny-permission-using-cacls-utility)

* [Disable Net User Account](detections.md#disable-net-user-account)

* [Disable Windows App Hotkeys](detections.md#disable-windows-app-hotkeys)

* [Disabling Net User Account](detections.md#disabling-net-user-account)

* [Download Files Using Telegram](detections.md#download-files-using-telegram)

* [Enumerate Users Local Group Using Telegram](detections.md#enumerate-users-local-group-using-telegram)

* [Excessive Attempt To Disable Services](detections.md#excessive-attempt-to-disable-services)

* [Excessive Service Stop Attempt](detections.md#excessive-service-stop-attempt)

* [Excessive Usage Of Cacls App](detections.md#excessive-usage-of-cacls-app)

* [Excessive Usage Of Net App](detections.md#excessive-usage-of-net-app)

* [Excessive Usage Of Taskkill](detections.md#excessive-usage-of-taskkill)

* [Executables Or Script Creation In Suspicious Path](detections.md#executables-or-script-creation-in-suspicious-path)

* [Grant Permission Using Cacls Utility](detections.md#grant-permission-using-cacls-utility)

* [Hide User Account From Sign-In Screen](detections.md#hide-user-account-from-sign-in-screen)

* [ICACLS Grant Command](detections.md#icacls-grant-command)

* [Icacls Deny Command](detections.md#icacls-deny-command)

* [Modify ACL permission To Files Or Folder](detections.md#modify-acl-permission-to-files-or-folder)

* [Modify ACLs Permission Of Files Or Folders](detections.md#modify-acls-permission-of-files-or-folders)

* [Process Kill Base On File Path](detections.md#process-kill-base-on-file-path)

* [Schtasks Run Task On Demand](detections.md#schtasks-run-task-on-demand)

* [Suspicious Driver Loaded Path](detections.md#suspicious-driver-loaded-path)

* [Suspicious Process File Path](detections.md#suspicious-process-file-path)

* [XMRIG Driver Loaded](detections.md#xmrig-driver-loaded)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1489 | Service Stop | Impact |
| T1531 | Account Access Removal | Impact |
| T1222 | File and Directory Permissions Modification | Defense Evasion |
| T1562.001 | Disable or Modify Tools | Defense Evasion |
| T1105 | Ingress Tool Transfer | Command And Control |
| T1087 | Account Discovery | Discovery |
| T1036 | Masquerading | Defense Evasion |
| T1053 | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |
| T1543.003 | Windows Service | Persistence, Privilege Escalation |
| T1543 | Create or Modify System Process | Persistence, Privilege Escalation |

#### Kill Chain Phase

* Exploitation


#### Reference

* https://github.com/xmrig/xmrig

* https://www.getmonero.org/resources/user-guides/mine-to-pool.html

* https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/

* https://blog.checkpoint.com/2021/03/11/february-2021s-most-wanted-malware-trickbot-takes-over-following-emotet-shutdown/


_version_: 1
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

</details>
