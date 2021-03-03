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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2017-12-19

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2016-09-13

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://www.us-cert.gov/ncas/alerts/TA13-088A

* https://www.imperva.com/learn/application-security/dns-amplification/


_version_: 1
</details>

---

### Data Protection
Fortify your data-protection arsenal--while continuing to ensure data confidentiality and integrity--with searches that monitor for and help you investigate possible signs of data exfiltration.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2017-09-14

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2017-09-14

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://blog.malwarebytes.com/cybercrime/2016/09/hosts-file-hijacks/


_version_: 1
</details>

---

### Netsh Abuse
Detect activities and various techniques associated with the abuse of `netsh.exe`, which can disable local firewall settings or set up a remote connection to a host from an infected system.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2017-01-05

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **ATT&CK**: 
- **Last Updated**: 2018-10-08

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **ATT&CK**: 
- **Last Updated**: 2021-01-27

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit


_version_: 1
</details>

---

### Cobalt Strike
Cobalt Strike is threat emulation software. Red teams and penetration testers use Cobalt Strike to demonstrate the risk of a breach and evaluate mature security programs. Most recently, Cobalt Strike has become the choice tool by threat groups due to its ease of use and extensibility.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2021-02-16

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-02-03

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://attack.mitre.org/wiki/Collection

* https://attack.mitre.org/wiki/Technique/T1074


_version_: 1
</details>

---

### Command and Control
Detect and investigate tactics, techniques, and procedures leveraged by attackers to establish and operate command and control channels. Implants installed by attackers on compromised endpoints use these channels to receive instructions and send data back to the malicious operators.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2018-06-01

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://attack.mitre.org/wiki/Command_and_Control

* https://searchsecurity.techtarget.com/feature/Command-and-control-servers-The-puppet-masters-that-govern-malware


_version_: 1
</details>

---

### Common Phishing Frameworks
Detect DNS and web requests to fake websites generated by the EvilGinx2 toolkit. These websites are designed to fool unwitting users who have clicked on a malicious link in a phishing email. 

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2019-04-29

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-02-04

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://attack.mitre.org/wiki/Technique/T1003

* https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html


_version_: 3
</details>

---

### DNS Hijacking
Secure your environment against DNS hijacks with searches that help you detect and investigate unauthorized changes to DNS records.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-02-04

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **ATT&CK**: 
- **Last Updated**: 2020-10-21

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://attack.mitre.org/tactics/TA0010/


_version_: 1
</details>

---

### Detect Zerologon Attack
Uncover activity related to the execution of Zerologon CVE-2020-11472, a technique wherein attackers target a Microsoft Windows Domain Controller to reset its computer account password. The result from this attack is attackers can now provide themselves high privileges and take over Domain Controller. The included searches in this Analytic Story are designed to identify attempts to reset Domain Controller Computer Account via exploit code remotely or via the use of tool Mimikatz as payload carrier.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-09-18

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-02-04

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **ATT&CK**: 
- **Last Updated**: 2020-08-02

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-02-04

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://www.fireeye.com/blog/executive-perspective/2015/08/malware_lateral_move.html


_version_: 2
</details>

---

### Malicious PowerShell
Attackers are finding stealthy ways "live off the land," leveraging utilities and tools that come standard on the endpoint--such as PowerShell--to achieve their goals without downloading binary files. These searches can help you detect and investigate PowerShell command-line options that may be indicative of malicious intent.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2017-08-23

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **ATT&CK**: 
- **Last Updated**: 2019-04-29

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://www.fireeye.com/blog/threat-research/2019/04/spear-phishing-campaign-targets-ukraine-government.html


_version_: 1
</details>

---

### Possible Backdoor Activity Associated With MUDCARP Espionage Campaigns
Monitor your environment for suspicious behaviors that resemble the techniques employed by the MUDCARP threat group.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-01-22

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://www.infosecurity-magazine.com/news/scope-of-mudcarp-attacks-highlight-1/

* http://blog.amossys.fr/badflick-is-not-so-bad.html


_version_: 1
</details>

---

### SQL Injection
Use the searches in this Analytic Story to help you detect structured query language (SQL) injection attempts characterized by long URLs that contain malicious parameters.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2017-09-19

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://capec.mitre.org/data/definitions/66.html

* https://www.incapsula.com/web-application-security/sql-injection.html


_version_: 1
</details>

---

### Sunburst Malware
Sunburst is a trojanized updates to SolarWinds Orion IT monitoring and management software. It was discovered by FireEye in December 2020. The actors behind this campaign gained access to numerous public and private organizations around the world.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-12-14

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html

* https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/


_version_: 1
</details>

---

### Suspicious Command-Line Executions
Leveraging the Windows command-line interface (CLI) is one of the most common attack techniques--one that is also detailed in the MITRE ATT&CK framework. Use this Analytic Story to help you identify unusual or suspicious use of the CLI on Windows systems.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-02-03

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2021-02-11

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2017-09-18

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-01-27

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://www.splunk.com/blog/2015/06/26/phishing-hits-a-new-level-of-quality/


_version_: 1
</details>

---

### Suspicious MSHTA Activity
Monitor and detect techniques used by attackers who leverage the mshta.exe process to execute malicious code.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2021-01-20

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **ATT&CK**: 
- **Last Updated**: 2020-04-02

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2021-02-11

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2021-01-29

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2021-02-03

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2018-10-23

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf

* https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html


_version_: 2
</details>

---

### Suspicious Windows Registry Activities
Monitor and detect registry changes initiated from remote locations, which can be a sign that an attacker has infiltrated your system.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2018-05-31

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://redcanary.com/blog/windows-registry-attacks-threat-detection/

* https://attack.mitre.org/wiki/Technique/T1112


_version_: 1
</details>

---

### Suspicious Zoom Child Processes
Attackers are using Zoom as an vector to increase privileges on a sytems. This story detects new child processes of zoom and provides investigative actions for this detection.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-04-13

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://blog.rapid7.com/2020/04/02/dispelling-zoom-bugbears-what-you-need-to-know-about-the-latest-zoom-vulnerabilities/

* https://threatpost.com/two-zoom-zero-day-flaws-uncovered/154337/


_version_: 1
</details>

---

### Trusted Developer Utilities Proxy Execution
Monitor and detect behaviors used by attackers who leverage trusted developer utilities to execute malicious code.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2021-01-12

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2021-01-21

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-07-28

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://research.checkpoint.com/2020/resolving-your-way-into-domain-admin-exploiting-a-17-year-old-bug-in-windows-dns-servers/

* https://support.microsoft.com/en-au/help/4569509/windows-dns-server-remote-code-execution-vulnerability


_version_: 1
</details>

---

### Windows Defense Evasion Tactics
Detect tactics used by malware to evade defenses on Windows endpoints. A few of these include suspicious `reg.exe` processes, files hidden with `attrib.exe` and disabling user-account control, among many others 

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2018-05-31

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://attack.mitre.org/wiki/Defense_Evasion


_version_: 1
</details>

---

### Windows Log Manipulation
Adversaries often try to cover their tracks by manipulating Windows logs. Use these searches to help you monitor for suspicious activity surrounding log files--an essential component of an effective defense.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2017-09-12

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2018-05-31

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-02-04

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2017-09-13

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2017-09-15

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/


_version_: 1
</details>

---

### Monitor for Updates
Monitor your enterprise to ensure that your endpoints are being patched and updated. Adversaries notoriously exploit known vulnerabilities that could be mitigated by applying routine security patches.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2017-09-15

<details>
  <summary>details</summary>

#### Detection Profile

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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2017-09-11

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* http://www.novetta.com/2015/02/advanced-methods-to-detect-advanced-cyber-attacks-protocol-abuse/


_version_: 1
</details>

---

### Router and Infrastructure Security
Validate the security configuration of network infrastructure and verify that only authorized users and systems are accessing critical assets. Core routing and switching infrastructure are common strategic targets for attackers.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2017-09-12

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://www.fireeye.com/blog/executive-perspective/2015/09/the_new_route_toper.html

* https://www.cisco.com/c/en/us/about/security-center/event-response/synful-knock.html


_version_: 1
</details>

---

### Use of Cleartext Protocols
Leverage searches that detect cleartext network protocols that may leak credentials or should otherwise be encrypted.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2017-09-15

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **ATT&CK**: 
- **Last Updated**: 2018-06-04

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://aws.amazon.com/blogs/security/aws-cloudtrail-now-tracks-cross-account-activity-to-its-origin/


_version_: 1
</details>

---

### AWS Cryptomining
Monitor your AWS EC2 instances for activities related to cryptojacking/cryptomining. New instances that originate from previously unseen regions, users who launch abnormally high numbers of instances, or EC2 instances started by previously unseen users are just a few examples of potentially malicious behavior.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2018-03-08

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf


_version_: 1
</details>

---

### AWS Network ACL Activity
Monitor your AWS network infrastructure for bad configurations and malicious activity. Investigative searches help you probe deeper, when the facts warrant it.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2018-05-21

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **ATT&CK**: 
- **Last Updated**: 2018-03-16

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


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
- **ATT&CK**: 
- **Last Updated**: 2018-03-12

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf

* https://redlock.io/blog/cryptojacking-tesla


_version_: 1
</details>

---

### Cloud Cryptomining
Monitor your cloud compute instances for activities related to cryptojacking/cryptomining. New instances that originate from previously unseen regions, users who launch abnormally high numbers of instances, or compute instances started by previously unseen users are just a few examples of potentially malicious behavior.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2019-10-02

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf


_version_: 1
</details>

---

### Cloud Federated Credential Abuse
This analytical story addresses events that indicate abuse of cloud federated credentials. These credentials are usually extracted from endpoint desktop or servers specially those servers that provide federation services such as Windows Active Directory Federation Services. Identity Federation relies on objects such as Oauth2 tokens, cookies or SAML assertions in order to provide seamless access between cloud and perimeter environments. If these objects are either hijacked or forged then attackers will be able to pivot into victim's cloud environements.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2021-01-26

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **ATT&CK**: 
- **Last Updated**: 2020-02-20

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


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
- **ATT&CK**: 
- **Last Updated**: 2020-09-01

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://cloud.google.com/iam/docs/understanding-service-accounts


_version_: 1
</details>

---

### Kubernetes Scanning Activity
This story addresses detection against Kubernetes cluster fingerprint scan and attack by providing information on items such as source ip, user agent, cluster names.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-04-15

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://www.splunk.com/en_us/blog/security/approaching-kubernetes-security-detecting-kubernetes-scan-with-splunk.html


_version_: 1
</details>

---

### Office 365 Detections
This story is focused around detecting Office 365 Attacks.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-12-16

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://i.blackhat.com/USA-20/Thursday/us-20-Bienstock-My-Cloud-Is-APTs-Cloud-Investigating-And-Defending-Office-365.pdf


_version_: 1
</details>

---

### Suspicious AWS EC2 Activities
Use the searches in this Analytic Story to monitor your AWS EC2 instances for evidence of anomalous activity and suspicious behaviors, such as EC2 instances that originate from unusual locations or those launched by previously unseen users (among others). Included investigative searches will help you probe more deeply, when the information warrants it.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2018-02-09

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf


_version_: 1
</details>

---

### Suspicious AWS Login Activities
Monitor your AWS authentication events using your CloudTrail logs. Searches within this Analytic Story will help you stay aware of and investigate suspicious logins. 

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2019-05-01

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html


_version_: 1
</details>

---

### Suspicious AWS S3 Activities
Use the searches in this Analytic Story to monitor your AWS S3 buckets for evidence of anomalous activity and suspicious behaviors, such as detecting open S3 buckets and buckets being accessed from a new IP. The contextual and investigative searches will give you more information, when required.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2018-07-24

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://rhinosecuritylabs.com/aws/hiding-cloudcobalt-strike-beacon-c2-using-amazon-apis/


_version_: 1
</details>

---

### Suspicious Cloud Authentication Activities
Monitor your cloud authentication events. Searches within this Analytic Story leverage the recent cloud updates to the Authentication data model to help you stay aware of and investigate suspicious login activity. 

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-06-04

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://aws.amazon.com/blogs/security/aws-cloudtrail-now-tracks-cross-account-activity-to-its-origin/

* https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html


_version_: 1
</details>

---

### Suspicious Cloud Instance Activities
Monitor your cloud infrastructure provisioning activities for behaviors originating from unfamiliar or unusual locations. These behaviors may indicate that malicious activities are occurring somewhere within your cloud environment.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-08-25

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf


_version_: 1
</details>

---

### Suspicious Cloud Provisioning Activities
Monitor your cloud infrastructure provisioning activities for behaviors originating from unfamiliar or unusual locations. These behaviors may indicate that malicious activities are occurring somewhere within your cloud environment.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2018-08-20

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf


_version_: 1
</details>

---

### Suspicious Cloud User Activities
Detect and investigate suspicious activities by users and roles in your cloud environments.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-09-04

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **ATT&CK**: 
- **Last Updated**: 2020-08-05

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **ATT&CK**: 
- **Last Updated**: 2018-04-09

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


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

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-01-22

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://www.us-cert.gov/ncas/alerts/TA18-074A


_version_: 2
</details>

---

### Dynamic DNS
Detect and investigate hosts in your environment that may be communicating with dynamic domain providers. Attackers may leverage these services to help them avoid firewall blocks and deny lists.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2018-09-06

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-01-27

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-01-22

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity

* https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Destructive-Malware-Report.pdf


_version_: 2
</details>

---

### Orangeworm Attack Group
Detect activities and various techniques associated with the Orangeworm Attack Group, a group that frequently targets the healthcare industry.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-01-22

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia

* https://www.infosecurity-magazine.com/news/healthcare-targeted-by-hacker/


_version_: 2
</details>

---

### Ransomware
Leverage searches that allow you to detect and investigate unusual activities that might relate to ransomware--spikes in SMB traffic, suspicious wevtutil usage, the presence of common ransomware extensions, and system processes run from unexpected locations, and many others.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-02-04

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **ATT&CK**: 
- **Last Updated**: 2020-10-27

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-11-06

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2018-12-13

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2020-02-04

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2018-01-26

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://blog.malwarebytes.com/cybercrime/2013/12/file-extensions-2/

* https://attack.mitre.org/wiki/Technique/T1042


_version_: 1
</details>

---

### Windows Service Abuse
Windows services are often used by attackers for persistence and the ability to load drivers or otherwise interact with the Windows kernel. This Analytic Story helps you monitor your environment for indications that Windows services are being modified or created in a suspicious manner.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2017-11-02

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2018-12-06

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.2/dev/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf


_version_: 1
</details>

---

### JBoss Vulnerability
In March of 2016, adversaries were seen using JexBoss--an open-source utility used for testing and exploiting JBoss application servers. These searches help detect evidence of these attacks, such as network connections to external resources or web services spawning atypical child processes, among others.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2017-09-14

<details>
  <summary>details</summary>

#### Detection Profile

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* http://www.deependresearch.org/2016/04/jboss-exploits-view-from-victim.html


_version_: 1
</details>

---

### Spectre And Meltdown Vulnerabilities
Assess and mitigate your systems' vulnerability to Spectre and Meltdown exploitation with the searches in this Analytic Story.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: 
- **Last Updated**: 2018-01-08

<details>
  <summary>details</summary>

#### Detection Profile

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

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


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

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|


#### Kill Chain Phase


#### Reference

* https://nvd.nist.gov/vuln/detail/CVE-2018-11409

* https://www.splunk.com/view/SP-CAAAP5E#VulnerabilityDescriptionsandRatings

* https://www.exploit-db.com/exploits/44865/


_version_: 1
</details>

---

</details>
