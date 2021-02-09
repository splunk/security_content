
# Categories
Analytics stories organized by categories

* [Abuse](#Abuse)

* [Adversary Tactics](#Adversary-Tactics)

* [Best Practices](#Best-Practices)

* [Cloud Security](#Cloud-Security)

* [Malware](#Malware)

* [Vulnerability](#Vulnerability)


## Abuse

* [Brand Monitoring](#Brand-Monitoring)

* [Data Protection](#Data-Protection)

* [DNS Amplification Attacks](#DNS-Amplification-Attacks)

* [Host Redirection](#Host-Redirection)

* [Netsh Abuse](#Netsh-Abuse)

* [Web Fraud Detection](#Web-Fraud-Detection)

### Brand Monitoring
* id = 91c676cf-0b23-438d-abee-f6335e1fce78
* date = 2017-12-19
* version = 1

#### Description
Detect and investigate activity that may indicate that an adversary is using faux domains to mislead users into interacting with malicious infrastructure. Monitor DNS, email, and web traffic for permutations of your brand name.

#### Narrative
While you can educate your users and customers about the risks and threats posed by typosquatting, phishing, and corporate espionage, human error is a persistent fact of life. Of course, your adversaries are all too aware of this reality and will happily leverage it for nefarious purposes whenever possible&#51;phishing with lookalike addresses, embedding faux command-and-control domains in malware, and hosting malicious content on domains that closely mimic your corporate servers. This is where brand monitoring comes in.\
You can use our adaptation of `DNSTwist`, together with the support searches in this Analytic Story, to generate permutations of specified brands and external domains. Splunk can monitor email, DNS requests, and web traffic for these permutations and provide you with early warnings and situational awareness--powerful elements of an effective defense.\
Notable events will include IP addresses, URLs, and user data. Drilling down can provide you with even more actionable intelligence, including likely geographic information, contextual searches to help you scope the problem, and investigative searches.

#### Detections
* Monitor DNS For Brand Abuse
* Monitor Email For Brand Abuse
* Monitor Web Traffic For Brand Abuse

#### Data Models
* Email
* Network_Resolution
* Web

#### Mappings

##### ATT&CK

##### Kill Chain Phases
* Actions on Objectives
* Delivery

###### CIS
* CIS 7

##### NIST
* PR.IP

##### References
* https://www.zerofox.com/blog/what-is-digital-risk-monitoring/
* https://securingtomorrow.mcafee.com/consumer/family-safety/what-is-typosquatting/
* https://blog.malwarebytes.com/cybercrime/2016/06/explained-typosquatting/

### Data Protection
* id = 91c676cf-0b23-438d-abee-f6335e1fce33
* date = 2017-09-14
* version = 1

#### Description
Fortify your data-protection arsenal--while continuing to ensure data confidentiality and integrity--with searches that monitor for and help you investigate possible signs of data exfiltration.

#### Narrative
Attackers can leverage a variety of resources to compromise or exfiltrate enterprise data. Common exfiltration techniques include remote-access channels via low-risk, high-payoff active-collections operations and close-access operations using insiders and removable media. While this Analytic Story is not a comprehensive listing of all the methods by which attackers can exfiltrate data, it provides a useful starting point.

#### Detections
* Detect USB device insertion
* Detect hosts connecting to dynamic domain providers
* Detection of DNS Tunnels

#### Data Models
* Change_Analysis
* Network_Resolution

#### Mappings

##### ATT&CK
* T1048.003
* T1189

##### Kill Chain Phases
* Actions on Objectives
* Command and Control
* Installation

###### CIS
* CIS 12
* CIS 13
* CIS 8

##### NIST
* DE.AE
* DE.CM
* PR.DS
* PR.PT

##### References
* https://www.cisecurity.org/controls/data-protection/
* https://www.sans.org/reading-room/whitepapers/dns/splunk-detect-dns-tunneling-37022
* https://umbrella.cisco.com/blog/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/

### DNS Amplification Attacks
* id = e8afd39e-3294-11e6-b39d-a45e60c6700
* date = 2016-09-13
* version = 1

#### Description
DNS poses a serious threat as a Denial of Service (DOS) amplifier, if it responds to `ANY` queries. This Analytic Story can help you detect attackers who may be abusing your company's DNS infrastructure to launch amplification attacks, causing Denial of Service to other victims.

#### Narrative
The Domain Name System (DNS) is the protocol used to map domain names to IP addresses. It has been proven to work very well for its intended function. However if DNS is misconfigured, servers can be abused by attackers to levy amplification or redirection attacks against victims. Because DNS responses to `ANY` queries are so much larger than the queries themselves--and can be made with a UDP packet, which does not require a handshake--attackers can spoof the source address of the packet and cause much more data to be sent to the victim than if they sent the traffic themselves. The `ANY` requests are will be larger than normal DNS server requests, due to the fact that the server provides significant details, such as MX records and associated IP addresses. A large volume of this traffic can result in a DOS on the victim's machine. This misconfiguration leads to two possible victims, the first being the DNS servers participating in an attack and the other being the hosts that are the targets of the DOS attack.\
The search in this story can help you to detect if attackers are abusing your company's DNS infrastructure to launch DNS amplification attacks causing Denial of Service to other victims.

#### Detections
* Large Volume of DNS ANY Queries

#### Data Models
* Network_Resolution

#### Mappings

##### ATT&CK
* T1498.002

##### Kill Chain Phases
* Actions on Objectives

###### CIS
* CIS 11
* CIS 12

##### NIST
* DE.AE
* PR.IP
* PR.PT

##### References
* https://www.us-cert.gov/ncas/alerts/TA13-088A
* https://www.imperva.com/learn/application-security/dns-amplification/

### Host Redirection
* id = 2e8948a5-5239-406b-b56b-6c50fe268af4
* date = 2017-09-14
* version = 1

#### Description
Detect evidence of tactics used to redirect traffic from a host to a destination other than the one intended--potentially one that is part of an adversary's attack infrastructure. An example is redirecting communications regarding patches and updates or misleading users into visiting a malicious website.

#### Narrative
Attackers will often attempt to manipulate client communications for nefarious purposes. In some cases, an attacker may endeavor to modify a local host file to redirect communications with resources (such as antivirus or system-update services) to prevent clients from receiving patches or updates. In other cases, an attacker might use this tactic to have the client connect to a site that looks like the intended site, but instead installs malware or collects information from the victim. Additionally, an attacker may redirect a victim in order to execute a MITM attack and observe communications.

#### Detections
* Clients Connecting to Multiple DNS Servers
* DNS Query Requests Resolved by Unauthorized DNS Servers
* Windows hosts file modification

#### Data Models
* Network_Resolution

#### Mappings

##### ATT&CK
* T1048.003
* T1071.004

##### Kill Chain Phases
* Command and Control

###### CIS
* CIS 1
* CIS 12
* CIS 13
* CIS 3
* CIS 8
* CIS 9

##### NIST
* DE.AE
* DE.CM
* ID.AM
* PR.AC
* PR.DS
* PR.IP
* PR.PT

##### References
* https://blog.malwarebytes.com/cybercrime/2016/09/hosts-file-hijacks/

### Netsh Abuse
* id = 2b1800dd-92f9-47ec-a981-fdf1351e5f65
* date = 2017-01-05
* version = 1

#### Description
Detect activities and various techniques associated with the abuse of `netsh.exe`, which can disable local firewall settings or set up a remote connection to a host from an infected system.

#### Narrative
It is a common practice for attackers of all types to leverage native Windows tools and functionality to execute commands for malicious reasons. One such tool on Windows OS is `netsh.exe`,a command-line scripting utility that allows you to--either locally or remotely--display or modify the network configuration of a computer that is currently running. `Netsh.exe` can be used to discover and disable local firewall settings. It can also be used to set up a remote connection to a host from an infected system.\
To get started, run the detection search to identify parent processes of `netsh.exe`.

#### Detections
* Processes created by netsh
* Processes launching netsh

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK
* T1562.004

##### Kill Chain Phases
* Actions on Objectives

###### CIS
* CIS 8

##### NIST
* DE.CM
* PR.PT

##### References
* https://docs.microsoft.com/en-us/previous-versions/tn-archive/bb490939(v=technet.10)
* https://htmlpreview.github.io/?https://github.com/MatthewDemaske/blogbackup/blob/master/netshell.html
* http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html

### Web Fraud Detection
* id = 31337aaa-bc22-4752-b599-ef112dq1dq7a
* date = 2018-10-08
* version = 1

#### Description
Monitor your environment for activity consistent with common attack techniques bad actors use when attempting to compromise web servers or other web-related assets.

#### Narrative
The Federal Bureau of Investigations (FBI) defines Internet fraud as the use of Internet services or software with Internet access to defraud victims or to otherwise take advantage of them. According to the Bureau, Internet crime schemes are used to steal millions of dollars each year from victims and continue to plague the Internet through various methods. The agency includes phishing scams, data breaches, Denial of Service (DOS) attacks, email account compromise, malware, spoofing, and ransomware in this category.\
These crimes are not the fraud itself, but rather the attack techniques commonly employed by fraudsters in their pursuit of data that enables them to commit malicious actssuch as obtaining and using stolen credit cards. They represent a serious problem that is steadily increasing and not likely to go away anytime soon.\
When developing a strategy for preventing fraud in your environment, its important to  look across all of your web services for evidence that attackers are abusing enterprise resources to enumerate systems, harvest data for secondary fraudulent activity, or abuse terms of service.This Analytic Story looks for evidence of common Internet attack techniques that could be indicative of web fraud in your environmentincluding account harvesting, anomalous user clickspeed, and password sharing across accounts, to name just a few.\
The account-harvesting search focuses on web pages used for user-account registration. It detects the creation of a large number of user accounts using the same email domain name, a type of activity frequently seen in advance of a fraud campaign.\
The anomalous clickspeed search looks for users who are moving through your website at a faster-than-normal speed or with a perfect click cadence (high periodicity or low standard deviation), which could indicate that the user is a script, not an actual human.\
Another search detects incidents wherein a single password is used across multiple accounts, which may indicate that a fraudster has infiltrated your environment and embedded a common password within a script.

#### Detections
* Web Fraud - Account Harvesting
* Web Fraud - Anomalous User Clickspeed
* Web Fraud - Password Sharing Across Accounts

#### Data Models

#### Mappings

##### ATT&CK
* T1078
* T1136

##### Kill Chain Phases
* Actions on Objectives

###### CIS
* CIS 16
* CIS 6

##### NIST
* DE.AE
* DE.CM
* DE.DP

##### References
* https://www.fbi.gov/scams-and-safety/common-fraud-schemes/internet-fraud
* https://www.fbi.gov/news/stories/2017-internet-crime-report-released-050718


## Adversary Tactics

* [Baron Samedit CVE-2021-3156](#Baron-Samedit-CVE-2021-3156)

* [Collection and Staging](#Collection-and-Staging)

* [Command and Control](#Command-and-Control)

* [Common Phishing Frameworks](#Common-Phishing-Frameworks)

* [Credential Dumping](#Credential-Dumping)

* [Data Exfiltration](#Data-Exfiltration)

* [Detect Zerologon Attack](#Detect-Zerologon-Attack)

* [Disabling Security Tools](#Disabling-Security-Tools)

* [DNS Hijacking](#DNS-Hijacking)

* [F5 TMUI RCE CVE-2020-5902](#F5-TMUI-RCE-CVE-2020-5902)

* [Lateral Movement](#Lateral-Movement)

* [Malicious PowerShell](#Malicious-PowerShell)

* [Phishing Payloads](#Phishing-Payloads)

* [Possible Backdoor Activity Associated With MUDCARP Espionage Campaigns](#Possible-Backdoor-Activity-Associated-With-MUDCARP-Espionage-Campaigns)

* [SQL Injection](#SQL-Injection)

* [Sunburst Malware](#Sunburst-Malware)

* [Suspicious Command-Line Executions](#Suspicious-Command-Line-Executions)

* [Suspicious DNS Traffic](#Suspicious-DNS-Traffic)

* [Suspicious Emails](#Suspicious-Emails)

* [Suspicious MSHTA Activity](#Suspicious-MSHTA-Activity)

* [Suspicious Okta Activity](#Suspicious-Okta-Activity)

* [Suspicious Windows Registry Activities](#Suspicious-Windows-Registry-Activities)

* [Suspicious WMI Use](#Suspicious-WMI-Use)

* [Suspicious Zoom Child Processes](#Suspicious-Zoom-Child-Processes)

* [Trusted Developer Utilities Proxy Execution](#Trusted-Developer-Utilities-Proxy-Execution)

* [Trusted Developer Utilities Proxy Execution MSBuild](#Trusted-Developer-Utilities-Proxy-Execution-MSBuild)

* [Windows Defense Evasion Tactics](#Windows-Defense-Evasion-Tactics)

* [Windows DNS SIGRed CVE-2020-1350](#Windows-DNS-SIGRed-CVE-2020-1350)

* [Windows Log Manipulation](#Windows-Log-Manipulation)

* [Windows Persistence Techniques](#Windows-Persistence-Techniques)

* [Windows Privilege Escalation](#Windows-Privilege-Escalation)

### Baron Samedit CVE-2021-3156
* id = 817b0dfc-23ba-4bcc-96cc-2cb77e428fbe
* date = 2021-01-27
* version = 1

#### Description
Uncover activity consistent with CVE-2021-3156. Discovered by the Qualys Research Team, this vulnerability has been found to affect sudo across multiple Linux distributions (Ubuntu 20.04 and prior, Debian 10 and prior, Fedora 33 and prior). As this vulnerability was committed to code in July 2011, there will be many distributions affected. Successful exploitation of this vulnerability allows any unprivileged user to gain root privileges on the vulnerable host.

#### Narrative
A non-privledged user is able to execute the sudoedit command to trigger a buffer overflow. After the successful buffer overflow, they are then able to gain root privileges on the affected host. The conditions needed to be run are a trailing "\" along with shell and edit flags. Monitoring the /var/log directory on Linux hosts using the Splunk Universal Forwarder will allow you to pick up this behavior when using the provided detection.

#### Detections
* Detect Baron Samedit CVE-2021-3156
* Detect Baron Samedit CVE-2021-3156 Segfault
* Detect Baron Samedit CVE-2021-3156 via OSQuery

#### Data Models

#### Mappings

##### ATT&CK
* T1068

##### Kill Chain Phases
* Exploitation

###### CIS
* CIS 12
* CIS 16
* CIS 8

##### NIST
* DE.CM

##### References
* https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit

### Collection and Staging
* id = 8e03c61e-13c4-4dcd-bfbe-5ce5a8dc031a
* date = 2020-02-03
* version = 1

#### Description
Monitor for and investigate activities--such as suspicious writes to the Windows Recycling Bin or email servers sending high amounts of traffic to specific hosts, for example--that may indicate that an adversary is harvesting and exfiltrating sensitive data. 

#### Narrative
A common adversary goal is to identify and exfiltrate data of value from a target organization. This data may include email conversations and addresses, confidential company information, links to network design/infrastructure, important dates, and so on.\
 Attacks are composed of three activities: identification, collection, and staging data for exfiltration. Identification typically involves scanning systems and observing user activity. Collection can involve the transfer of large amounts of data from various repositories. Staging/preparation includes moving data to a central location and compressing (and optionally encoding and/or encrypting) it. All of these activities provide opportunities for defenders to identify their presence. \
Use the searches to detect and monitor suspicious behavior related to these activities.

#### Detections
* Email files written outside of the Outlook directory
* Email servers sending high volume traffic to hosts
* Hosts receiving high volume of network traffic from email server
* Suspicious writes to System Volume Information
* Suspicious writes to windows Recycle Bin

#### Data Models
* Endpoint
* Network_Traffic

#### Mappings

##### ATT&CK
* T1036
* T1114.001
* T1114.002

##### Kill Chain Phases
* Actions on Objectives

###### CIS
* CIS 7
* CIS 8

##### NIST
* DE.AE
* DE.CM
* PR.PT

##### References
* https://attack.mitre.org/wiki/Collection
* https://attack.mitre.org/wiki/Technique/T1074

### Command and Control
* id = 943773c6-c4de-4f38-89a8-0b92f98804d8
* date = 2018-06-01
* version = 1

#### Description
Detect and investigate tactics, techniques, and procedures leveraged by attackers to establish and operate command and control channels. Implants installed by attackers on compromised endpoints use these channels to receive instructions and send data back to the malicious operators.

#### Narrative
Threat actors typically architect and implement an infrastructure to use in various ways during the course of their attack campaigns. In some cases, they leverage this infrastructure for scanning and performing reconnaissance activities. In others, they may use this infrastructure to launch actual attacks. One of the most important functions of this infrastructure is to establish servers that will communicate with implants on compromised endpoints. These servers establish a command and control channel that is used to proxy data between the compromised endpoint and the attacker. These channels relay commands from the attacker to the compromised endpoint and the output of those commands back to the attacker.\
Because this communication is so critical for an adversary, they often use techniques designed to hide the true nature of the communications. There are many different techniques used to establish and communicate over these channels. This Analytic Story provides searches that look for a variety of the techniques used for these channels, as well as indications that these channels are active, by examining logs associated with border control devices and network-access control lists.

#### Detections
* Clients Connecting to Multiple DNS Servers
* DNS Query Length Outliers - MLTK
* DNS Query Length With High Standard Deviation
* DNS Query Requests Resolved by Unauthorized DNS Servers
* Detect Large Outbound ICMP Packets
* Detect Long DNS TXT Record Response
* Detect Spike in blocked Outbound Traffic from your AWS
* Detect hosts connecting to dynamic domain providers
* Detection of DNS Tunnels
* Excessive DNS Failures
* Prohibited Network Traffic Allowed
* Protocol or Port Mismatch
* TOR Traffic

#### Data Models
* Network_Resolution
* Network_Traffic

#### Mappings

##### ATT&CK
* T1048
* T1048.003
* T1071.001
* T1071.004
* T1095
* T1189

##### Kill Chain Phases
* Actions on Objectives
* Command and Control
* Delivery

###### CIS
* CIS 1
* CIS 11
* CIS 12
* CIS 13
* CIS 3
* CIS 8
* CIS 9

##### NIST
* DE.AE
* DE.CM
* ID.AM
* PR.AC
* PR.DS
* PR.IP
* PR.PT

##### References
* https://attack.mitre.org/wiki/Command_and_Control
* https://searchsecurity.techtarget.com/feature/Command-and-control-servers-The-puppet-masters-that-govern-malware

### Common Phishing Frameworks
* id = 9a64ab44-9214-4639-8163-7eaa2621bd61
* date = 2019-04-29
* version = 1

#### Description
Detect DNS and web requests to fake websites generated by the EvilGinx2 toolkit. These websites are designed to fool unwitting users who have clicked on a malicious link in a phishing email. 

#### Narrative
As most people know, these emails use fraudulent domains, [email scraping](https://www.cyberscoop.com/emotet-trojan-phishing-scraping-templates-cofense-geodo/), familiar contact names inserted as senders, and other tactics to lure targets into clicking a malicious link, opening an attachment with a [nefarious payload](https://www.cyberscoop.com/emotet-trojan-phishing-scraping-templates-cofense-geodo/), or entering sensitive personal information that perpetrators may intercept. This attack technique requires a relatively low level of skill and allows adversaries to easily cast a wide net. Because phishing is a technique that relies on human psychology, you will never be able to eliminate this vulnerability 100%. But you can use automated detection to significantly reduce the risks.\
This Analytic Story focuses on detecting signs of MiTM attacks enabled by [EvilGinx2](https://github.com/kgretzky/evilginx2), a toolkit that sets up a transparent proxy between the targeted site and the user. In this way, the attacker is able to intercept credentials and two-factor identification tokens. It employs a proxy template to allow a registered domain to impersonate targeted sites, such as Linkedin, Amazon, Okta, Github, Twitter, Instagram, Reddit, Office 365, and others. It can even register SSL certificates and camouflage them via a URL shortener, making them difficult to detect. Searches in this story look for signs of MiTM attacks enabled by EvilGinx2.

#### Detections
* Detect DNS requests to Phishing Sites leveraging EvilGinx2

#### Data Models
* Network_Resolution

#### Mappings

##### ATT&CK
* T1566.003

##### Kill Chain Phases
* Command and Control
* Delivery

###### CIS
* CIS 7
* CIS 8

##### NIST
* DE.AE
* DE.CM
* ID.AM
* PR.DS
* PR.IP

##### References
* https://github.com/kgretzky/evilginx2
* https://attack.mitre.org/techniques/T1192/
* https://breakdev.org/evilginx-advanced-phishing-with-two-factor-authentication-bypass/

### Credential Dumping
* id = 854d78bf-d0e2-4f4e-b05c-640905f86d7a
* date = 2020-02-04
* version = 3

#### Description
Uncover activity consistent with credential dumping, a technique wherein attackers compromise systems and attempt to obtain and exfiltrate passwords. The threat actors use these pilfered credentials to further escalate privileges and spread throughout a target environment. The included searches in this Analytic Story are designed to identify attempts to credential dumping.

#### Narrative
Credential dumping&#151;gathering credentials from a target system, often hashed or encrypted&#151;is a common attack technique. Even though the credentials may not be in plain text, an attacker can still exfiltrate the data and set to cracking it offline, on their own systems. The threat actors target a variety of sources to extract them, including the Security Accounts Manager (SAM), Local Security Authority (LSA), NTDS from Domain Controllers, or the Group Policy Preference (GPP) files.\
Once attackers obtain valid credentials, they use them to move throughout a target network with ease, discovering new systems and identifying assets of interest. Credentials obtained in this manner typically include those of privileged users, which may provide access to more sensitive information and system operations.\
The detection searches in this Analytic Story monitor access to the Local Security Authority Subsystem Service (LSASS) process, the usage of shadowcopies for credential dumping and some other techniques for credential dumping.

#### Detections
* Access LSASS Memory for Dump Creation
* Attempt To Set Default PowerShell Execution Policy To Unrestricted or Bypass
* Attempted Credential Dump From Registry via Reg exe
* Attempted Credential Dump From Registry via Reg exe - SSA
* Create Remote Thread into LSASS
* Creation of Shadow Copy
* Creation of Shadow Copy with wmic and powershell
* Credential Dumping via Copy Command from Shadow Copy
* Credential Dumping via Symlink to Shadow Copy
* Detect Credential Dumping through LSASS access
* Detect Dump LSASS Memory using comsvcs - SSA
* Detect Mimikatz Using Loaded Images
* Dump LSASS via comsvcs DLL
* Unsigned Image Loaded by LSASS

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK
* T1003
* T1003.001
* T1003.002
* T1003.003
* T1059.001

##### Kill Chain Phases
* Actions on Objectives
* Installation

###### CIS
* CIS 16
* CIS 3
* CIS 5
* CIS 6
* CIS 8

##### NIST
* DE.AE
* DE.CM
* PR.AC
* PR.IP

##### References
* https://attack.mitre.org/wiki/Technique/T1003
* https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html

### Data Exfiltration
* id = 66b0fe0c-1351-11eb-adc1-0242ac120002
* date = 2020-10-21
* version = 1

#### Description
The stealing of data by an adversary.

#### Narrative
Exfiltration comes in many flavors.  Adversaries can collect data over encrypted or non-encrypted channels.  They can utilise Command and Control channels that are already in place to exfiltrate data.  They can use both standard data transfer protocols such as FTP, SCP, etc to exfiltrate data.  Or they can use non-standard protocols such as DNS, ICMP, etc with specially crafted fields to try and circumvent security technologies in place.

#### Detections
* Detect SNICat SNI Exfiltration

#### Data Models

#### Mappings

##### ATT&CK
* T1041

##### Kill Chain Phases
* Actions on Objectives

###### CIS
* CIS 13

##### NIST
* DE.AE
* DE.CM
* PR.DS

##### References
* https://attack.mitre.org/tactics/TA0010/

### Detect Zerologon Attack
* id = 5d14a962-569e-4578-939f-f386feb63ce4
* date = 2020-09-18
* version = 1

#### Description
Uncover activity related to the execution of Zerologon CVE-2020-11472, a technique wherein attackers target a Microsoft Windows Domain Controller to reset its computer account password. The result from this attack is attackers can now provide themselves high privileges and take over Domain Controller. The included searches in this Analytic Story are designed to identify attempts to reset Domain Controller Computer Account via exploit code remotely or via the use of tool Mimikatz as payload carrier.

#### Narrative
This attack is a privilege escalation technique, where attacker targets a Netlogon secure channel connection to a domain controller, using Netlogon Remote Protocol (MS-NRPC). This vulnerability exposes vulnerable Windows Domain Controllers to be targeted via unaunthenticated RPC calls which eventually reset Domain Contoller computer account ($) providing the attacker the opportunity to exfil domain controller credential secrets and assign themselve high privileges that can lead to domain controller and potentially complete network takeover. The detection searches in this Analytic Story use Windows Event viewer events and Sysmon events to detect attack execution, these searches monitor access to the Local Security Authority Subsystem Service (LSASS) process which is an indicator of the use of Mimikatz tool which has bee updated to carry this attack payload.

#### Detections
* Detect Computer Changed with Anonymous Account
* Detect Credential Dumping through LSASS access
* Detect Mimikatz Using Loaded Images
* Detect Zerologon via Zeek

#### Data Models

#### Mappings

##### ATT&CK
* T1003.001
* T1190
* T1210

##### Kill Chain Phases
* Actions on Objectives
* Exploitation

###### CIS
* CIS 11
* CIS 16
* CIS 3
* CIS 5
* CIS 6
* CIS 8

##### NIST
* DE.AE
* DE.CM
* PR.AC
* PR.IP

##### References
* https://attack.mitre.org/wiki/Technique/T1003
* https://github.com/SecuraBV/CVE-2020-1472
* https://www.secura.com/blog/zero-logon
* https://nvd.nist.gov/vuln/detail/CVE-2020-1472

### Disabling Security Tools
* id = fcc27099-46a0-46b0-a271-5c7dab56b6f1
* date = 2020-02-04
* version = 2

#### Description
Looks for activities and techniques associated with the disabling of security tools on a Windows system, such as suspicious `reg.exe` processes, processes launching netsh, and many others.

#### Narrative
Attackers employ a variety of tactics in order to avoid detection and operate without barriers. This often involves modifying the configuration of security tools to get around them or explicitly disabling them to prevent them from running. This Analytic Story includes searches that look for activity consistent with attackers attempting to disable various security mechanisms. Such activity may involve monitoring for suspicious registry activity, as this is where much of the configuration for Windows and various other programs reside, or explicitly attempting to shut down security-related services. Other times, attackers attempt various tricks to prevent specific programs from running, such as adding the certificates with which the security tools are signed to a block list (which would prevent them from running).

#### Detections
* Attempt To Add Certificate To Untrusted Store
* Attempt To Stop Security Service
* Processes launching netsh
* Sc exe Manipulating Windows Services
* Suspicious Reg exe Process
* Unload Sysmon Filter Driver

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK
* T1112
* T1543.003
* T1553.004
* T1562.001
* T1562.004

##### Kill Chain Phases
* Actions on Objectives
* Installation

###### CIS
* CIS 3
* CIS 5
* CIS 8

##### NIST
* DE.CM
* PR.AC
* PR.AT
* PR.IP
* PR.PT

##### References
* https://attack.mitre.org/wiki/Technique/T1089
* https://blog.malwarebytes.com/cybercrime/2015/11/vonteera-adware-uses-certificates-to-disable-anti-malware/
* https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Tools-Report.pdf

### DNS Hijacking
* id = 8169f17b-ef68-4b59-aa28-586907301221
* date = 2020-02-04
* version = 1

#### Description
Secure your environment against DNS hijacks with searches that help you detect and investigate unauthorized changes to DNS records.

#### Narrative
Dubbed the Achilles heel of the Internet (see https://www.f5.com/labs/articles/threat-intelligence/dns-is-still-the-achilles-heel-of-the-internet-25613), DNS plays a critical role in routing web traffic but is notoriously vulnerable to attack. One reason is its distributed nature. It relies on unstructured connections between millions of clients and servers over inherently insecure protocols.\
The gravity and extent of the importance of securing DNS from attacks is undeniable. The fallout of compromised DNS can be disastrous. Not only can hackers bring down an entire business, they can intercept confidential information, emails, and login credentials, as well. \
On January 22, 2019, the US Department of Homeland Security 2019's Cybersecurity and Infrastructure Security Agency (CISA) raised awareness of some high-profile DNS hijacking attacks against infrastructure, both in the United States and abroad. It issued Emergency Directive 19-01 (see https://cyber.dhs.gov/ed/19-01/), which summarized the activity and required government agencies to take the following four actions, all within 10 days: \
1. For all .gov or other agency-managed domains, audit public DNS records on all authoritative and secondary DNS servers, verify that they resolve to the intended location or report them to CISA.\
1. Update the passwords for all accounts on systems that can make changes to each agency 2019's DNS records.\
1. Implement multi-factor authentication (MFA) for all accounts on systems that can make changes to each agency's 2019 DNS records or, if impossible, provide CISA with the names of systems, the reasons why MFA cannot be enabled within the required timeline, and an ETA for when it can be enabled.\
1. CISA will begin regular delivery of newly added certificates to Certificate Transparency (CT) logs for agency domains via the Cyber Hygiene service. Upon receipt, agencies must immediately begin monitoring CT log data for certificates issued that they did not request. If an agency confirms that a certificate was unauthorized, it must report the certificate to the issuing certificate authority and to CISA. Of course, it makes sense to put equivalent actions in place within your environment, as well. \
In DNS hijacking, the attacker assumes control over an account or makes use of a DNS service exploit to make changes to DNS records. Once they gain access, attackers can substitute their own MX records, name-server records, and addresses, redirecting emails and traffic through their infrastructure, where they can read, copy, or modify information seen. They can also generate valid encryption certificates to help them avoid browser-certificate checks. In one notable attack on the Internet service provider, GoDaddy, the hackers altered Sender Policy Framework (SPF) records a relatively minor change that did not inflict excessive damage but allowed for more effective spam campaigns.\
The searches in this Analytic Story help you detect and investigate activities that may indicate that DNS hijacking has taken place within your environment.

#### Detections
* Clients Connecting to Multiple DNS Servers
* DNS Query Requests Resolved by Unauthorized DNS Servers
* DNS record changed
* Detect hosts connecting to dynamic domain providers

#### Data Models
* Network_Resolution

#### Mappings

##### ATT&CK
* T1048.003
* T1071.004
* T1189

##### Kill Chain Phases
* Actions on Objectives
* Command and Control

###### CIS
* CIS 1
* CIS 12
* CIS 13
* CIS 3
* CIS 8
* CIS 9

##### NIST
* DE.AE
* DE.CM
* ID.AM
* PR.DS
* PR.IP
* PR.PT

##### References
* https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html
* https://umbrella.cisco.com/blog/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/
* http://www.noip.com/blog/2014/07/11/dynamic-dns-can-use-2/
* https://www.splunk.com/blog/2015/08/04/detecting-dynamic-dns-domains-in-splunk.html

### F5 TMUI RCE CVE-2020-5902
* id = 7678c968-d46e-11ea-87d0-0242ac130003
* date = 2020-08-02
* version = 1

#### Description
Uncover activity consistent with CVE-2020-5902. Discovered by Positive Technologies researchers, this vulnerability affects F5 BIG-IP, BIG-IQ. and Traffix SDC devices (vulnerable versions in F5 support link below). This vulnerability allows unauthenticated users, along with authenticated users, who have access to the configuration utility to execute system commands, create/delete files, disable services, and/or execute Java code.  This vulnerability can result in full system compromise.

#### Narrative
A client is able to perform a remote code execution on an exposed and vulnerable system. The detection search in this Analytic Story uses syslog to detect the malicious behavior. Syslog is going to be the best detection method, as any systems using SSL to protect their management console will make detection via wire data difficult.  The searches included used Splunk Connect For Syslog (https://splunkbase.splunk.com/app/4740/), and used a custom destination port to help define the data as F5 data (covered in https://splunk-connect-for-syslog.readthedocs.io/en/master/sources/F5/)

#### Detections
* Detect F5 TMUI RCE CVE-2020-5902

#### Data Models

#### Mappings

##### ATT&CK
* T1190

##### Kill Chain Phases
* Exploitation

###### CIS
* CIS 11
* CIS 8

##### NIST
* DE.CM

##### References
* https://www.ptsecurity.com/ww-en/about/news/f5-fixes-critical-vulnerability-discovered-by-positive-technologies-in-big-ip-application-delivery-controller/
* https://support.f5.com/csp/article/K52145254
* https://blog.cloudflare.com/cve-2020-5902-helping-to-protect-against-the-f5-tmui-rce-vulnerability/

### Lateral Movement
* id = 399d65dc-1f08-499b-a259-aad9051f38ad
* date = 2020-02-04
* version = 2

#### Description
Detect and investigate tactics, techniques, and procedures around how attackers move laterally within the enterprise. Because lateral movement can expose the adversary to detection, it should be an important focus for security analysts.

#### Narrative
Once attackers gain a foothold within an enterprise, they will seek to expand their accesses and leverage techniques that facilitate lateral movement. Attackers will often spend quite a bit of time and effort moving laterally. Because lateral movement renders an attacker the most vulnerable to detection, it's an excellent focus for detection and investigation.\
Indications of lateral movement can include the abuse of system utilities (such as `psexec.exe`), unauthorized use of remote desktop services, `file/admin$` shares, WMI, PowerShell, pass-the-hash, or the abuse of scheduled tasks. Organizations must be extra vigilant in detecting lateral movement techniques and look for suspicious activity in and around high-value strategic network assets, such as Active Directory, which are often considered the primary target or "crown jewels" to a persistent threat actor.\
An adversary can use lateral movement for multiple purposes, including remote execution of tools, pivoting to additional systems, obtaining access to specific information or files, access to additional credentials, exfiltrating data, or delivering a secondary effect. Adversaries may use legitimate credentials alongside inherent network and operating-system functionality to remotely connect to other systems and remain under the radar of network defenders.\
If there is evidence of lateral movement, it is imperative for analysts to collect evidence of the associated offending hosts. For example, an attacker might leverage host A to gain access to host B. From there, the attacker may try to move laterally to host C. In this example, the analyst should gather as much information as possible from all three hosts. \
 It is also important to collect authentication logs for each host, to ensure that the offending accounts are well-documented. Analysts should account for all processes to ensure that the attackers did not install unauthorized software.

#### Detections
* Detect Activity Related to Pass the Hash Attacks
* Kerberoasting spn request with RC4 encryption
* Remote Desktop Network Traffic
* Remote Desktop Process Running On System
* Schtasks scheduling job on remote system

#### Data Models
* Endpoint
* Network_Traffic

#### Mappings

##### ATT&CK
* T1021.001
* T1053.005
* T1550.002
* T1558.003

##### Kill Chain Phases
* Actions on Objectives

###### CIS
* CIS 16
* CIS 3
* CIS 5
* CIS 8
* CIS 9

##### NIST
* DE.AE
* DE.CM
* PR.AC
* PR.AT
* PR.IP
* PR.PT

##### References
* https://www.fireeye.com/blog/executive-perspective/2015/08/malware_lateral_move.html

### Malicious PowerShell
* id = 2c8ff66e-0b57-42af-8ad7-912438a403fc
* date = 2017-08-23
* version = 4

#### Description
Attackers are finding stealthy ways "live off the land," leveraging utilities and tools that come standard on the endpoint--such as PowerShell--to achieve their goals without downloading binary files. These searches can help you detect and investigate PowerShell command-line options that may be indicative of malicious intent.

#### Narrative
The searches in this Analytic Story monitor for parameters often used for malicious purposes. It is helpful to understand how often the notable events generated by this story occur, as well as the commonalities between some of these events. These factors may provide clues about whether this is a common occurrence of minimal concern or a rare event that may require more extensive investigation. Likewise, it is important to determine whether the issue is restricted to a single user/system or is broader in scope.\
The following factors may assist you in determining whether the event is malicious: \
1. Country of origin\
1. Responsible party\
1. Fully qualified domain names associated with the external IP address\
1. Registration of fully qualified domain names associated with external IP addressDetermining whether it is a dynamic domain frequently visited by others and/or how third parties categorize it can also help you answer some questions surrounding the attacker and details related to the external system. In addition, there are various sources--such as VirusTotal&#151; that can provide some reputation information on the IP address or domain name, which can assist in determining whether the event is malicious. Finally, determining whether there are other events associated with the IP address may help connect data points or show other events that should be brought into scope.\
Gathering data on the system of interest can sometimes help you quickly determine whether something suspicious is happening. Some of these items include finding out who else may have recently logged into the system, whether any unusual scheduled tasks exist, whether the system is communicating on suspicious ports, whether there are modifications to sensitive registry keys, and whether there are any known vulnerabilities on the system. This information can often highlight other activity commonly seen in attack scenarios or give more information about how the system may have been targeted.\
Often, a simple inspection of the process name and path can tell you if the system has been compromised. For example, if `svchost.exe` is found running from a location other than `C:\Windows\System32`, it is likely something malicious designed to hide in plain sight when cursorily reviewing process names. Similarly, if the process itself seems legitimate, but the parent process is running from the temporary browser cache, that could be indicative of activity initiated via a compromised website a user visited.\
It can also be very helpful to examine various behaviors of the process of interest or the parent of the process of interest. For example, if it turns out the process of interest is malicious, it would be good to see if the parent to that process spawned other processes that might be worth further scrutiny. If a process is suspect, a review of the network connections made in and around the time of the event and/or whether the process spawned any child processes could be helpful, as well.\
In the event a system is suspected of having been compromised via a malicious website, we suggest reviewing the browsing activity from that system around the time of the event. If categories are given for the URLs visited, that can help you zero in on possible malicious sites.

#### Detections
* Attempt To Set Default PowerShell Execution Policy To Unrestricted or Bypass
* Malicious PowerShell Process - Connect To Internet With Hidden Window
* Malicious PowerShell Process - Encoded Command
* Malicious PowerShell Process - Multiple Suspicious Command-Line Arguments
* Malicious PowerShell Process With Obfuscation Techniques

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK
* T1027
* T1059.001

##### Kill Chain Phases
* Actions on Objectives
* Command and Control
* Installation

###### CIS
* CIS 3
* CIS 7
* CIS 8

##### NIST
* DE.CM
* PR.IP
* PR.PT

##### References
* https://blogs.mcafee.com/mcafee-labs/malware-employs-powershell-to-infect-systems/
* https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/

### Phishing Payloads
* id = 57226b40-94f3-4ce5-b101-a75f67759c27
* date = 2019-04-29
* version = 1

#### Description
Detect signs of malicious payloads that may indicate that your environment has been breached via a phishing attack.

#### Narrative
Despite its simplicity, phishing remains the most pervasive and dangerous cyberthreat. In fact, research shows that as many as [91% of all successful attacks](https://digitalguardian.com/blog/91-percent-cyber-attacks-start-phishing-email-heres-how-protect-against-phishing) are initiated via a phishing email. \
As most people know, these emails use fraudulent domains, [email scraping](https://www.cyberscoop.com/emotet-trojan-phishing-scraping-templates-cofense-geodo/), familiar contact names inserted as senders, and other tactics to lure targets into clicking a malicious link, opening an attachment with a [nefarious payload](https://www.cyberscoop.com/emotet-trojan-phishing-scraping-templates-cofense-geodo/), or entering sensitive personal information that perpetrators may intercept. This attack technique requires a relatively low level of skill and allows adversaries to easily cast a wide net. Worse, because its success relies on the gullibility of humans, it's impossible to completely "automate" it out of your environment. However, you can use ES and ESCU to detect and investigate potentially malicious payloads injected into your environment subsequent to a phishing attack. \
While any kind of file may contain a malicious payload, some are more likely to be perceived as benign (and thus more often escape notice) by the average victim&#151;especially when the attacker sends an email that seems to be from one of their contacts. An example is Microsoft Office files. Most corporate users are familiar with documents with the following suffixes: .doc/.docx (MS Word), .xls/.xlsx (MS Excel), and .ppt/.pptx (MS PowerPoint), so they may click without a second thought, slashing a hole in their organizations' security. \
Following is a typical series of events, according to an [article by Trend Micro](https://blog.trendmicro.com/trendlabs-security-intelligence/rising-trend-attackers-using-lnk-files-download-malware/):\
1. Attacker sends a phishing email. Recipient downloads the attached file, which is typically a .docx or .zip file with an embedded .lnk file\
1. The .lnk file executes a PowerShell script\
1. Powershell executes a reverse shell, rendering the exploit successful </ol>As a side note, adversaries are likely to use a tool like Empire to craft and obfuscate payloads and their post-injection activities, such as [exfiltration, lateral movement, and persistence](https://github.com/EmpireProject/Empire).\
This Analytic Story focuses on detecting signs that a malicious payload has been injected into your environment. For example, one search detects outlook.exe writing a .zip file. Another looks for suspicious .lnk files launching processes.

#### Detections
* Detect Oulook exe writing a  zip file
* Process Creating LNK file in Suspicious Location

#### Data Models

#### Mappings

##### ATT&CK
* T1566.001
* T1566.002

##### Kill Chain Phases
* Actions on Objectives
* Installation

###### CIS
* CIS 7
* CIS 8

##### NIST
* ID.AM
* PR.DS

##### References
* https://www.fireeye.com/blog/threat-research/2019/04/spear-phishing-campaign-targets-ukraine-government.html

### Possible Backdoor Activity Associated With MUDCARP Espionage Campaigns
* id = 988C59C5-0A1C-45B6-A555-0C62276E327E
* date = 2020-01-22
* version = 1

#### Description
Monitor your environment for suspicious behaviors that resemble the techniques employed by the MUDCARP threat group.

#### Narrative
This story was created as a joint effort between iDefense and Splunk.\
iDefense analysts have recently discovered a Windows executable file that, upon execution, spoofs a decryption tool and then drops a file that appears to be the custom-built javascript backdoor, "Orz," which is associated with the threat actors known as MUDCARP (as well as "temp.Periscope" and "Leviathan"). The file is executed using Wscript.\
The MUDCARP techniques include the use of the compressed-folders module from Microsoft, zipfldr.dll, with RouteTheCall export to run the malicious process or command. After a successful reboot, the malware is made persistent by a manipulating `[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]'help'='c:\\windows\\system32\\rundll32.exe c:\\windows\\system32\\zipfldr.dll,RouteTheCall c:\\programdata\\winapp.exe'`. Though this technique is not exclusive to MUDCARP, it has been spotted in the group's arsenal of advanced techniques seen in the wild.\
This Analytic Story searches for evidence of tactics, techniques, and procedures (TTPs) that allow for the use of a endpoint detection-and-response (EDR) bypass technique to mask the true parent of a malicious process. It can also be set as a registry key for further sandbox evasion and to allow the malware to launch only after reboot.\
If behavioral searches included in this story yield positive hits, iDefense recommends conducting IOC searches for the following:\
\
1. www.chemscalere[.]com\
1. chemscalere[.]com\
1. about.chemscalere[.]com\
1. autoconfig.chemscalere[.]com\
1. autodiscover.chemscalere[.]com\
1. catalog.chemscalere[.]com\
1. cpanel.chemscalere[.]com\
1. db.chemscalere[.]com\
1. ftp.chemscalere[.]com\
1. mail.chemscalere[.]com\
1. news.chemscalere[.]com\
1. update.chemscalere[.]com\
1. webmail.chemscalere[.]com\
1. www.candlelightparty[.]org\
1. candlelightparty[.]org\
1. newapp.freshasianews[.]comIn addition, iDefense also recommends that organizations review their environments for activity related to the following hashes:\
\
1. cd195ee448a3657b5c2c2d13e9c7a2e2\
1. b43ad826fe6928245d3c02b648296b43\
1. 889a9b52566448231f112a5ce9b5dfaf\
1. b8ec65dab97cdef3cd256cc4753f0c54\
1. 04d83cd3813698de28cfbba326d7647c

#### Detections
* First time seen command line argument
* Malicious PowerShell Process - Connect To Internet With Hidden Window
* Registry Keys Used For Persistence
* Unusually Long Command Line
* Unusually Long Command Line - MLTK

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK
* T1059.001
* T1059.003
* T1547.001

##### Kill Chain Phases
* Actions on Objectives
* Command and Control

###### CIS
* CIS 3
* CIS 7
* CIS 8

##### NIST
* DE.AE
* DE.CM
* PR.IP
* PR.PT

##### References
* https://www.infosecurity-magazine.com/news/scope-of-mudcarp-attacks-highlight-1/
* http://blog.amossys.fr/badflick-is-not-so-bad.html

### SQL Injection
* id = 4f6632f5-449c-4686-80df-57625f59bab3
* date = 2017-09-19
* version = 1

#### Description
Use the searches in this Analytic Story to help you detect structured query language (SQL) injection attempts characterized by long URLs that contain malicious parameters.

#### Narrative
It is very common for attackers to inject SQL parameters into vulnerable web applications, which then interpret the malicious SQL statements.\
This Analytic Story contains a search designed to identify attempts by attackers to leverage this technique to compromise a host and gain a foothold in the target environment.

#### Detections
* SQL Injection with Long URLs

#### Data Models
* Web

#### Mappings

##### ATT&CK
* T1190

##### Kill Chain Phases
* Delivery

###### CIS
* CIS 13
* CIS 18
* CIS 4

##### NIST
* DE.CM
* ID.RA
* PR.DS
* PR.IP
* PR.PT

##### References
* https://capec.mitre.org/data/definitions/66.html
* https://www.incapsula.com/web-application-security/sql-injection.html

### Sunburst Malware
* id = 758196b5-2e21-424f-a50c-6e421ce926c2
* date = 2020-12-14
* version = 1

#### Description
Sunburst is a trojanized updates to SolarWinds Orion IT monitoring and management software. It was discovered by FireEye in December 2020. The actors behind this campaign gained access to numerous public and private organizations around the world.

#### Narrative
This Analytic Story supports you to detect Tactics, Techniques and Procedures (TTPs) from the Sunburst malware. The threat actor behind sunburst compromised the SolarWinds.Orion.Core.BusinessLayer.dll, is a SolarWinds digitally-signed component of the Orion software framework that contains a backdoor that communicates via HTTP to third party servers. The detections in this Analytic Story are focusing on the dll loading events, file create events and network events to detect This malware.

#### Detections
* Detect Outbound SMB Traffic
* Detect Prohibited Applications Spawning cmd exe
* First Time Seen Running Windows Service
* Malicious PowerShell Process - Encoded Command
* Sc exe Manipulating Windows Services
* Scheduled Task Deleted Or Created via CMD
* Schtasks scheduling job on remote system
* Sunburst Correlation DLL and Network Event
* Supernova Webshell
* TOR Traffic
* Windows AdFind Exe

#### Data Models
* Endpoint
* Network_Traffic
* Web

#### Mappings

##### ATT&CK
* T1018
* T1027
* T1053.005
* T1059.003
* T1071.001
* T1071.002
* T1203
* T1505.003
* T1543.003
* T1569.002

##### Kill Chain Phases
* Actions on Objectives
* Command and Control
* Exfiltration
* Exploitation
* Installation

###### CIS
* CIS 12
* CIS 13
* CIS 18
* CIS 2
* CIS 3
* CIS 4
* CIS 5
* CIS 6
* CIS 7
* CIS 8
* CIS 9

##### NIST
* DE.AE
* DE.CM
* ID.AM
* ID.RA
* PR.AC
* PR.AT
* PR.DS
* PR.IP
* PR.PT

##### References
* https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
* https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/

### Suspicious Command-Line Executions
* id = f4368ddf-d59f-4192-84f6-778ac5a3ffc7
* date = 2020-02-03
* version = 2

#### Description
Leveraging the Windows command-line interface (CLI) is one of the most common attack techniques--one that is also detailed in the MITRE ATT&CK framework. Use this Analytic Story to help you identify unusual or suspicious use of the CLI on Windows systems.

#### Narrative
The ability to execute arbitrary commands via the Windows CLI is a primary goal for the adversary. With access to the shell, an attacker can easily run scripts and interact with the target system. Often, attackers may only have limited access to the shell or may obtain access in unusual ways. In addition, malware may execute and interact with the CLI in ways that would be considered unusual and inconsistent with typical user activity. This provides defenders with opportunities to identify suspicious use and investigate, as appropriate. This Analytic Story contains various searches to help identify this suspicious activity, as well as others to aid you in deeper investigation.

#### Detections
* Detect Prohibited Applications Spawning cmd exe
* Detect Use of cmd exe to Launch Script Interpreters
* First time seen command line argument
* System Processes Run From Unexpected Locations
* Unusually Long Command Line
* Unusually Long Command Line - MLTK

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK
* T1036.003
* T1059.001
* T1059.003

##### Kill Chain Phases
* Actions on Objectives
* Command and Control
* Exploitation

###### CIS
* CIS 3
* CIS 8

##### NIST
* DE.CM
* PR.IP
* PR.PT

##### References
* https://attack.mitre.org/wiki/Technique/T1059
* https://www.microsoft.com/en-us/wdsi/threats/macro-malware
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf

### Suspicious DNS Traffic
* id = 3c3835c0-255d-4f9e-ab84-e29ec9ec9b56
* date = 2017-09-18
* version = 1

#### Description
Attackers often attempt to hide within or otherwise abuse the domain name system (DNS). You can thwart attempts to manipulate this omnipresent protocol by monitoring for these types of abuses.

#### Narrative
Although DNS is one of the fundamental underlying protocols that make the Internet work, it is often ignored (perhaps because of its complexity and effectiveness).  However, attackers have discovered ways to abuse the protocol to meet their objectives. One potential abuse involves manipulating DNS to hijack traffic and redirect it to an IP address under the attacker's control. This could inadvertently send users intending to visit google.com, for example, to an unrelated malicious website. Another technique involves using the DNS protocol for command-and-control activities with the attacker's malicious code or to covertly exfiltrate data. The searches within this Analytic Story look for these types of abuses.

#### Detections
* Clients Connecting to Multiple DNS Servers
* DNS Query Length Outliers - MLTK
* DNS Query Length With High Standard Deviation
* DNS Query Requests Resolved by Unauthorized DNS Servers
* Detect Long DNS TXT Record Response
* Detect hosts connecting to dynamic domain providers
* Detection of DNS Tunnels
* Excessive DNS Failures

#### Data Models
* Network_Resolution

#### Mappings

##### ATT&CK
* T1048.003
* T1071.004
* T1189

##### Kill Chain Phases
* Actions on Objectives
* Command and Control

###### CIS
* CIS 1
* CIS 12
* CIS 13
* CIS 3
* CIS 8
* CIS 9

##### NIST
* DE.AE
* DE.CM
* ID.AM
* PR.DS
* PR.IP
* PR.PT

##### References
* http://blogs.splunk.com/2015/10/01/random-words-on-entropy-and-dns/
* http://www.darkreading.com/analytics/security-monitoring/got-malware-three-signs-revealed-in-dns-traffic/d/d-id/1139680
* https://live.paloaltonetworks.com/t5/Threat-Vulnerability-Articles/What-are-suspicious-DNS-queries/ta-p/71454

### Suspicious Emails
* id = 2b1800dd-92f9-47ec-a981-fdf1351e5d55
* date = 2020-01-27
* version = 1

#### Description
Email remains one of the primary means for attackers to gain an initial foothold within the modern enterprise. Detect and investigate suspicious emails in your environment with the help of the searches in this Analytic Story.

#### Narrative
It is a common practice for attackers of all types to leverage targeted spearphishing campaigns and mass mailers to deliver weaponized email messages and attachments. Fortunately, there are a number of ways to monitor email data in Splunk to detect suspicious content.\
Once a phishing message has been detected, the next steps are to answer the following questions: \
1. Which users have received this or a similar message in the past?\
1. When did the targeted campaign begin?\
1. Have any users interacted with the content of the messages (by downloading an attachment or clicking on a malicious URL)?This Analytic Story provides detection searches to identify suspicious emails, as well as contextual and investigative searches to help answer some of these questions.

#### Detections
* Email Attachments With Lots Of Spaces
* Monitor Email For Brand Abuse
* Suspicious Email - UBA Anomaly
* Suspicious Email Attachment Extensions

#### Data Models
* Email
* UEBA

#### Mappings

##### ATT&CK
* T1566
* T1566.001

##### Kill Chain Phases
* Delivery

###### CIS
* CIS 12
* CIS 3
* CIS 7

##### NIST
* DE.AE
* PR.IP

##### References
* https://www.splunk.com/blog/2015/06/26/phishing-hits-a-new-level-of-quality/

### Suspicious MSHTA Activity
* id = 2b1800dd-92f9-47dd-a981-fdf13w1q5d55
* date = 2021-01-20
* version = 2

#### Description
Monitor and detect techniques used by attackers who leverage the mshta.exe process to execute malicious code.

#### Narrative
One common adversary tactic is to bypass application white-listing solutions via the mshta.exe process, which loads Microsoft HTML applications (mshtml.dll) with the .hta suffix. In these cases, attackers use the trusted Windows utility to proxy execution of malicious files, whether an .hta application, javascript, or VBScript.\
The searches in this story help you detect and investigate suspicious activity that may indicate that an attacker is leveraging mshta.exe to execute malicious code. \
Triage \ Validate execution \ 1. Determine if MSHTA.exe executed. Validate the OriginalFileName of MSHTA.exe and further PE metadata. If executed outside of c:\windows\system32 or c:\windows\syswow64, it should be highly suspect. 2. Determine if script code was executed with MSHTA. \ Situational Awareness \ The objective of this step is meant to identify suspicious behavioral indicators related to executed of Script code by MSHTA.exe. \ 1. Parent process. Is the parent process a known LOLBin? Is the parent process an Office Application? 2. Module loads. Are the known MSHTA.exe modules being loaded by a non-standard application? Is MSHTA loading any suspicious .DLLs? 3. Network connections. Any network connections? Review the reputation of the remote IP or domain. \ Retrieval of script code \ The objective of this step is to confirm the executed script code is benign or malicious.

#### Detections
* Detect MSHTA Url in Command Line
* Detect Prohibited Applications Spawning cmd exe
* Detect Rundll32 Inline HTA Execution
* Detect mshta inline hta execution
* Detect mshta renamed
* Registry Keys Used For Persistence
* Suspicious mshta child process
* Suspicious mshta spawn

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK
* T1059.003
* T1218.005
* T1547.001

##### Kill Chain Phases
* Actions on Objectives
* Exploitation

###### CIS
* CIS 8

##### NIST
* DE.AE
* DE.CM
* PR.PT

##### References
* https://redcanary.com/blog/introducing-atomictestharnesses/
* https://redcanary.com/blog/windows-registry-attacks-threat-detection/
* https://attack.mitre.org/techniques/T1218/005/
* https://medium.com/@mbromileyDFIR/malware-monday-aebb456356c5

### Suspicious Okta Activity
* id = 9cbd34af-8f39-4476-a423-bacd126c750b
* date = 2020-04-02
* version = 1

#### Description
Monitor your Okta environment for suspicious activities. Due to the Covid outbreak, many users are migrating over to leverage cloud services more and more. Okta is a popular tool to manage multiple users and the web-based applications they need to stay productive. The searches in this story will help monitor your Okta environment for suspicious activities and associated user behaviors.

#### Narrative
Okta is the leading single sign on (SSO) provider, allowing users to authenticate once to Okta, and from there access a variety of web-based applications. These applications are assigned to users and allow administrators to centrally manage which users are allowed to access which applications. It also provides centralized logging to help understand how the applications are used and by whom. \
While SSO is a major convenience for users, it also provides attackers with an opportunity. If the attacker can gain access to Okta, they can access a variety of applications. As such monitoring the environment is important. \
With people moving quickly to adopt web-based applications and ways to manage them, many are still struggling to understand how best to monitor these environments. This analytic story provides searches to help monitor this environment, and identify events and activity that warrant further investigation such as credential stuffing or password spraying attacks, and users logging in from multiple locations when travel is disallowed.

#### Detections
* Multiple Okta Users With Invalid Credentails From The Same IP
* Okta Account Lockout Events
* Okta Failed SSO Attempts
* Okta User Logins From Multiple Cities

#### Data Models

#### Mappings

##### ATT&CK
* T1078.001

##### Kill Chain Phases

###### CIS
* CIS 16

##### NIST
* DE.CM

##### References
* https://attack.mitre.org/wiki/Technique/T1078
* https://owasp.org/www-community/attacks/Credential_stuffing
* https://searchsecurity.techtarget.com/answer/What-is-a-password-spraying-attack-and-how-does-it-work

### Suspicious Windows Registry Activities
* id = 2b1800dd-92f9-47dd-a981-fdf1351e5d55
* date = 2018-05-31
* version = 1

#### Description
Monitor and detect registry changes initiated from remote locations, which can be a sign that an attacker has infiltrated your system.

#### Narrative
Attackers are developing increasingly sophisticated techniques for hijacking target servers, while evading detection. One such technique that has become progressively more common is registry modification.\
 The registry is a key component of the Windows operating system. It has a hierarchical database called "registry" that contains settings, options, and values for executables. Once the threat actor gains access to a machine, they can use reg.exe to modify their account to obtain administrator-level privileges, maintain persistence, and move laterally within the environment.\
 The searches in this story are designed to help you detect behaviors associated with manipulation of the Windows registry.

#### Detections
* Disabling Remote User Account Control
* Monitor Registry Keys for Print Monitors
* Reg exe used to hide files directories via registry keys
* Registry Keys Used For Persistence
* Registry Keys Used For Privilege Escalation
* Registry Keys for Creating SHIM Databases
* Remote Registry Key modifications
* Suspicious Changes to File Associations

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK
* T1546.001
* T1546.011
* T1546.012
* T1547.001
* T1547.010
* T1548.002
* T1564.001

##### Kill Chain Phases
* Actions on Objectives

###### CIS
* CIS 3
* CIS 5
* CIS 8

##### NIST
* DE.AE
* DE.CM
* PR.AC
* PR.IP
* PR.PT

##### References
* https://redcanary.com/blog/windows-registry-attacks-threat-detection/
* https://attack.mitre.org/wiki/Technique/T1112

### Suspicious WMI Use
* id = c8ddc5be-69bc-4202-b3ab-4010b27d7ad5
* date = 2018-10-23
* version = 2

#### Description
Attackers are increasingly abusing Windows Management Instrumentation (WMI), a framework and associated utilities available on all modern Windows operating systems. Because WMI can be leveraged to manage both local and remote systems, it is important to identify the processes executed and the user context within which the activity occurred.

#### Narrative
WMI is a Microsoft infrastructure for management data and operations on Windows operating systems. It includes of a set of utilities that can be leveraged to manage both local and remote Windows systems. Attackers are increasingly turning to WMI abuse in their efforts to conduct nefarious tasks, such as reconnaissance, detection of antivirus and virtual machines, code execution, lateral movement, persistence, and data exfiltration. \
The detection searches included in this Analytic Story are used to look for suspicious use of WMI commands that attackers may leverage to interact with remote systems. The searches specifically look for the use of WMI to run processes on remote systems.\
In the event that unauthorized WMI execution occurs, it will be important for analysts and investigators to determine the context of the event. These details may provide insights related to how WMI was used and to what end.

#### Detections
* Process Execution via WMI
* Remote Process Instantiation via WMI
* Remote WMI Command Attempt
* Script Execution via WMI
* WMI Permanent Event Subscription
* WMI Permanent Event Subscription - Sysmon
* WMI Temporary Event Subscription

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK
* T1047
* T1546.003

##### Kill Chain Phases
* Actions on Objectives

###### CIS
* CIS 3
* CIS 5

##### NIST
* PR.AC
* PR.AT
* PR.IP
* PR.PT

##### References
* https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf
* https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html

### Suspicious Zoom Child Processes
* id = aa3749a6-49c7-491e-a03f-4eaee5fe0258
* date = 2020-04-13
* version = 1

#### Description
Attackers are using Zoom as an vector to increase privileges on a sytems. This story detects new child processes of zoom and provides investigative actions for this detection.

#### Narrative
Zoom is a leader in modern enterprise video communications and its usage has increased dramatically with a large amount of the population under stay-at-home orders due to the COVID-19 pandemic. With increased usage has come increased scrutiny and several security flaws have been found with this application on both Windows and macOS systems.\
Current detections focus on finding new child processes of this application on a per host basis. Investigative searches are included to gather information needed during an investigation.

#### Detections
* Detect Prohibited Applications Spawning cmd exe
* First Time Seen Child Process of Zoom

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK
* T1059.003
* T1068

##### Kill Chain Phases
* Actions on Objectives
* Exploitation

###### CIS
* CIS 3
* CIS 8

##### NIST
* DE.CM
* PR.IP
* PR.PT

##### References
* https://blog.rapid7.com/2020/04/02/dispelling-zoom-bugbears-what-you-need-to-know-about-the-latest-zoom-vulnerabilities/
* https://threatpost.com/two-zoom-zero-day-flaws-uncovered/154337/

### Trusted Developer Utilities Proxy Execution
* id = 270a67a6-55d8-11eb-ae93-0242ac130002
* date = 2021-01-12
* version = 1

#### Description
Monitor and detect behaviors used by attackers who leverage trusted developer utilities to execute malicious code.

#### Narrative
Adversaries may take advantage of trusted developer utilities to proxy execution of malicious payloads. There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering. These utilities may often be signed with legitimate certificates that allow them to execute on a system and proxy execution of malicious code through a trusted process that effectively bypasses application control solutions.\
The searches in this story help you detect and investigate suspicious activity that may indicate that an adversary is leveraging microsoft.workflow.compiler.exe to execute malicious code.

#### Detections
* Suspicious microsoft workflow compiler rename
* Suspicious microsoft workflow compiler usage

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK
* T1127
* T1127, T1036.003

##### Kill Chain Phases
* Exploitation

###### CIS
* CIS 8

##### NIST
* DE.CM
* PR.PT

##### References
* https://attack.mitre.org/techniques/T1127/
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md
* https://lolbas-project.github.io/lolbas/Binaries/Microsoft.Workflow.Compiler/

### Trusted Developer Utilities Proxy Execution MSBuild
* id = be3418e2-551b-11eb-ae93-0242ac130002
* date = 2021-01-21
* version = 1

#### Description
Monitor and detect techniques used by attackers who leverage the msbuild.exe process to execute malicious code.

#### Narrative
Adversaries may use MSBuild to proxy execution of code through a trusted Windows utility. MSBuild.exe (Microsoft Build Engine) is a software build platform used by Visual Studio and is native to Windows. It handles XML formatted project files that define requirements for loading and building various platforms and configurations. \
The inline task capability of MSBuild that was introduced in .NET version 4 allows for C# code to be inserted into an XML project file. MSBuild will compile and execute the inline task. MSBuild.exe is a signed Microsoft binary, so when it is used this way it can execute arbitrary code and bypass application control defenses that are configured to allow MSBuild.exe execution. \
The searches in this story help you detect and investigate suspicious activity that may indicate that an adversary is leveraging msbuild.exe to execute malicious code. \
Triage \ Validate execution \ 1. Determine if MSBuild.exe executed. Validate the OriginalFileName of MSBuild.exe and further PE metadata. 2. Determine if script code was executed with MSBuild. Situational Awareness \ The objective of this step is meant to identify suspicious behavioral indicators related to executed of Script code by MSBuild.exe. \ 1. Parent process. Is the parent process a known LOLBin? Is the parent process an Office Application? 2. Module loads. Are the known MSBuild.exe modules being loaded by a non-standard application? Is MSbuild loading any suspicious .DLLs? 3. Network connections. Any network connections? Review the reputation of the remote IP or domain. \ Retrieval of script code \ The objective of this step is to confirm the executed script code is benign or malicious.

#### Detections
* Suspicious MSBuild Rename
* Suspicious MSBuild Spawn
* Suspicious msbuild path

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK
* T1036.003
* T1127.001

##### Kill Chain Phases
* Exploitation

###### CIS
* CIS 8

##### NIST
* DE.CM
* PR.PT

##### References
* https://attack.mitre.org/techniques/T1127/001/
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1127.001/T1127.001.md
* https://github.com/infosecn1nja/MaliciousMacroMSBuild
* https://github.com/xorrior/RandomPS-Scripts/blob/master/Invoke-ExecuteMSBuild.ps1
* https://lolbas-project.github.io/lolbas/Binaries/Msbuild/
* https://github.com/MHaggis/CBR-Queries/blob/master/msbuild.md

### Windows Defense Evasion Tactics
* id = 56e24a28-5003-4047-b2db-e8f3c4618064
* date = 2018-05-31
* version = 1

#### Description
Detect tactics used by malware to evade defenses on Windows endpoints. A few of these include suspicious `reg.exe` processes, files hidden with `attrib.exe` and disabling user-account control, among many others 

#### Narrative
Defense evasion is a tactic--identified in the MITRE ATT&CK framework--that adversaries employ in a variety of ways to bypass or defeat defensive security measures. There are many techniques enumerated by the MITRE ATT&CK framework that are applicable in this context. This Analytic Story includes searches designed to identify the use of such techniques on Windows platforms.

#### Detections
* Disabling Remote User Account Control
* Hiding Files And Directories With Attrib exe
* Reg exe used to hide files directories via registry keys
* Remote Registry Key modifications
* Suspicious Reg exe Process

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK
* T1112
* T1222.001
* T1548.002
* T1564.001

##### Kill Chain Phases
* Actions on Objectives

###### CIS
* CIS 8

##### NIST
* DE.CM
* PR.PT

##### References
* https://attack.mitre.org/wiki/Defense_Evasion

### Windows DNS SIGRed CVE-2020-1350
* id = 36dbb206-d073-11ea-87d0-0242ac130003
* date = 2020-07-28
* version = 1

#### Description
Uncover activity consistent with CVE-2020-1350, or SIGRed. Discovered by Checkpoint researchers, this vulnerability affects Windows 2003 to 2019, and is triggered by a malicious DNS response (only affects DNS over TCP). An attacker can use the malicious payload to cause a buffer overflow on the vulnerable system, leading to compromise.  The included searches in this Analytic Story are designed to identify the large response payload for SIG and KEY DNS records which can be used for the exploit.

#### Narrative
When a client requests a DNS record for a particular domain, that request gets routed first through the client's locally configured DNS server, then to any DNS server(s) configured as forwarders, and then onto the target domain's own DNS server(s).  If a attacker wanted to, they could host a malicious DNS server that responds to the initial request with a specially crafted large response (~65KB).  This response would flow through to the client's local DNS server, which if not patched for CVE-2020-1350, would cause the buffer overflow. The detection searches in this Analytic Story use wire data to detect the malicious behavior. Searches for Splunk Stream and Zeek are included.  The Splunk Stream search correlates across stream:dns and stream:tcp, while the Zeek search correlates across bro:dns:json and bro:conn:json.  These correlations are required to pick up both the DNS record types (SIG and KEY) along with the payload size (>65KB).

#### Detections
* Detect Windows DNS SIGRed via Splunk Stream
* Detect Windows DNS SIGRed via Zeek

#### Data Models
* Network_Resolution

#### Mappings

##### ATT&CK
* T1203

##### Kill Chain Phases
* Exploitation

###### CIS
* CIS 12
* CIS 16
* CIS 8

##### NIST
* DE.CM

##### References
* https://research.checkpoint.com/2020/resolving-your-way-into-domain-admin-exploiting-a-17-year-old-bug-in-windows-dns-servers/
* https://support.microsoft.com/en-au/help/4569509/windows-dns-server-remote-code-execution-vulnerability

### Windows Log Manipulation
* id = b6db2c60-a281-48b4-95f1-2cd99ed56835
* date = 2017-09-12
* version = 2

#### Description
Adversaries often try to cover their tracks by manipulating Windows logs. Use these searches to help you monitor for suspicious activity surrounding log files--an essential component of an effective defense.

#### Narrative
Because attackers often modify system logs to cover their tracks and/or to thwart the investigative process, log monitoring is an industry-recognized best practice. While there are legitimate reasons to manipulate system logs, it is still worthwhile to keep track of who manipulated the logs, when they manipulated them, and in what way they manipulated them (determining which accesses, tools, or utilities were employed). Even if no malicious activity is detected, the knowledge of an attempt to manipulate system logs may be indicative of a broader security risk that should be thoroughly investigated.\
The Analytic Story gives users two different ways to detect manipulation of Windows Event Logs and one way to detect deletion of the Update Sequence Number (USN) Change Journal. The story helps determine the history of the host and the users who have accessed it. Finally, the story aides in investigation by retrieving all the information on the process that caused these events (if the process has been identified).

#### Detections
* Deleting Shadow Copies
* Suspicious wevtutil Usage
* USN Journal Deletion
* Windows Event Log Cleared

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK
* T1070
* T1070.001
* T1490

##### Kill Chain Phases
* Actions on Objectives

###### CIS
* CIS 10
* CIS 3
* CIS 5
* CIS 6
* CIS 8

##### NIST
* DE.AE
* DE.CM
* DE.DP
* PR.AC
* PR.AT
* PR.IP
* PR.PT

##### References
* https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/
* https://zeltser.com/security-incident-log-review-checklist/
* http://journeyintoir.blogspot.com/2013/01/re-introducing-usnjrnl.html

### Windows Persistence Techniques
* id = 30874d4f-20a1-488f-85ec-5d52ef74e3f9
* date = 2018-05-31
* version = 2

#### Description
Monitor for activities and techniques associated with maintaining persistence on a Windows system--a sign that an adversary may have compromised your environment.

#### Narrative
Maintaining persistence is one of the first steps taken by attackers after the initial compromise. Attackers leverage various custom and built-in tools to ensure survivability and persistent access within a compromised enterprise. This Analytic Story provides searches to help you identify various behaviors used by attackers to maintain persistent access to a Windows environment.

#### Detections
* Detect Path Interception By Creation Of program exe
* Hiding Files And Directories With Attrib exe
* Monitor Registry Keys for Print Monitors
* Reg exe Manipulating Windows Services Registry Keys
* Reg exe used to hide files directories via registry keys
* Registry Keys Used For Persistence
* Registry Keys for Creating SHIM Databases
* Remote Registry Key modifications
* Sc exe Manipulating Windows Services
* Schtasks used for forcing a reboot
* Shim Database File Creation
* Shim Database Installation With Suspicious Parameters

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK
* T1053.005
* T1222.001
* T1543.003
* T1546.011
* T1547.001
* T1547.010
* T1564.001
* T1574.009
* T1574.011

##### Kill Chain Phases
* Actions on Objectives
* Installation

###### CIS
* CIS 3
* CIS 5
* CIS 8

##### NIST
* DE.AE
* DE.CM
* PR.AC
* PR.AT
* PR.IP
* PR.PT

##### References
* http://www.fuzzysecurity.com/tutorials/19.html
* https://www.fireeye.com/blog/threat-research/2010/07/malware-persistence-windows-registry.html
* http://resources.infosecinstitute.com/common-malware-persistence-mechanisms/
* https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html
* https://www.youtube.com/watch?v=dq2Hv7J9fvk

### Windows Privilege Escalation
* id = 644e22d3-598a-429c-a007-16fdb802cae5
* date = 2020-02-04
* version = 2

#### Description
Monitor for and investigate activities that may be associated with a Windows privilege-escalation attack, including unusual processes running on endpoints, modified registry keys, and more.

#### Narrative
Privilege escalation is a "land-and-expand" technique, wherein an adversary gains an initial foothold on a host and then exploits its weaknesses to increase his privileges. The motivation is simple: certain actions on a Windows machine--such as installing software--may require higher-level privileges than those the attacker initially acquired. By increasing his privilege level, the attacker can gain the control required to carry out his malicious ends. This Analytic Story provides searches to detect and investigate behaviors that attackers may use to elevate their privileges in your environment.

#### Detections
* Child Processes of Spoolsv exe
* Overwriting Accessibility Binaries
* Registry Keys Used For Privilege Escalation
* Uncommon Processes On Endpoint

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK
* T1068
* T1204.002
* T1546.008
* T1546.012

##### Kill Chain Phases
* Actions on Objectives
* Exploitation

###### CIS
* CIS 2
* CIS 5
* CIS 8

##### NIST
* DE.CM
* ID.AM
* PR.AC
* PR.DS
* PR.PT

##### References
* https://attack.mitre.org/tactics/TA0004/


## Best Practices

* [Asset Tracking](#Asset-Tracking)

* [Monitor Backup Solution](#Monitor-Backup-Solution)

* [Monitor for Unauthorized Software](#Monitor-for-Unauthorized-Software)

* [Monitor for Updates](#Monitor-for-Updates)

* [Prohibited Traffic Allowed or Protocol Mismatch](#Prohibited-Traffic-Allowed-or-Protocol-Mismatch)

* [Router and Infrastructure Security](#Router-and-Infrastructure-Security)

* [Use of Cleartext Protocols](#Use-of-Cleartext-Protocols)

### Asset Tracking
* id = 91c676cf-0b23-438d-abee-f6335e1fce77
* date = 2017-09-13
* version = 1

#### Description
Keep a careful inventory of every asset on your network to make it easier to detect rogue devices. Unauthorized/unmanaged devices could be an indication of malicious behavior that should be investigated further.

#### Narrative
This Analytic Story is designed to help you develop a better understanding of what authorized and unauthorized devices are part of your enterprise. This story can help you better categorize and classify assets, providing critical business context and awareness of their assets during an incident. Information derived from this Analytic Story can be used to better inform and support other analytic stories. For successful detection, you will need to leverage the Assets and Identity Framework from Enterprise Security to populate your known assets.

#### Detections
* Detect Unauthorized Assets by MAC address

#### Data Models
* Network_Sessions

#### Mappings

##### ATT&CK

##### Kill Chain Phases
* Actions on Objectives
* Delivery
* Reconnaissance

###### CIS
* CIS 1

##### NIST
* ID.AM
* PR.DS

##### References
* https://www.cisecurity.org/controls/inventory-of-authorized-and-unauthorized-devices/

### Monitor Backup Solution
* id = abe807c7-1eb6-4304-ac32-6e7aacdb891d
* date = 2017-09-12
* version = 1

#### Description
Address common concerns when monitoring your backup processes. These searches can help you reduce risks from ransomware, device theft, or denial of physical access to a host by backing up data on endpoints.

#### Narrative
Having backups is a standard best practice that helps ensure continuity of business operations.  Having mature backup processes can also help you reduce the risks of many security-related incidents and streamline your response processes. The detection searches in this Analytic Story will help you identify systems that have backup failures, as well as systems that have not been backed up for an extended period of time. The story will also return the notable event history and all of the backup logs for an endpoint.

#### Detections
* Extended Period Without Successful Netbackup Backups
* Unsuccessful Netbackup backups

#### Data Models

#### Mappings

##### ATT&CK

##### Kill Chain Phases

###### CIS
* CIS 10

##### NIST
* PR.IP

##### References
* https://www.carbonblack.com/2016/03/04/tracking-locky-ransomware-using-carbon-black/

### Monitor for Unauthorized Software
* id = 8892a655-6205-43f7-abba-06460e38c8ae
* date = 2017-09-15
* version = 1

#### Description
Identify and investigate prohibited/unauthorized software or processes that may be concealing malicious behavior within your environment. 

#### Narrative
It is critical to identify unauthorized software and processes running on enterprise endpoints and determine whether they are likely to be malicious. This Analytic Story requires the user to populate the Interesting Processes table within Enterprise Security with prohibited processes. An included support search will augment this data, adding information on processes thought to be malicious. This search requires data from endpoint detection-and-response solutions, endpoint data sources (such as Sysmon), or Windows Event Logs--assuming that the Active Directory administrator has enabled process tracking within the System Event Audit Logs.\
It is important to investigate any software identified as suspicious, in order to understand how it was installed or executed. Analyzing authentication logs or any historic notable events might elicit additional investigative leads of interest. For best results, schedule the search to run every two weeks. 

#### Detections
* Prohibited Software On Endpoint

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK

##### Kill Chain Phases
* Actions on Objectives
* Command and Control
* Installation

###### CIS
* CIS 2

##### NIST
* ID.AM
* PR.DS

##### References
* https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/

### Monitor for Updates
* id = 9ef8d677-7b52-4213-a038-99cfc7acc2d8
* date = 2017-09-15
* version = 1

#### Description
Monitor your enterprise to ensure that your endpoints are being patched and updated. Adversaries notoriously exploit known vulnerabilities that could be mitigated by applying routine security patches.

#### Narrative
It is a common best practice to ensure that endpoints are being patched and updated in a timely manner, in order to reduce the risk of compromise via a publicly disclosed vulnerability. Timely application of updates/patches is important to eliminate known vulnerabilities that may be exploited by various threat actors.\
Searches in this analytic story are designed to help analysts monitor endpoints for system patches and/or updates. This helps analysts identify any systems that are not successfully updated in a timely matter.\
Microsoft releases updates for Windows systems on a monthly cadence. They should be installed as soon as possible after following internal testing and validation procedures. Patches and updates for other systems or applications are typically released as needed.

#### Detections
* No Windows Updates in a time frame

#### Data Models
* Updates

#### Mappings

##### ATT&CK

##### Kill Chain Phases

###### CIS
* CIS 18

##### NIST
* PR.MA
* PR.PT

##### References
* https://learn.cisecurity.org/20-controls-download

### Prohibited Traffic Allowed or Protocol Mismatch
* id = 6d13121c-90f3-446d-8ac3-27efbbc65218
* date = 2017-09-11
* version = 1

#### Description
Detect instances of prohibited network traffic allowed in the environment, as well as protocols running on non-standard ports. Both of these types of behaviors typically violate policy and can be leveraged by attackers.

#### Narrative
A traditional security best practice is to control the ports, protocols, and services allowed within your environment. By limiting the services and protocols to those explicitly approved by policy, administrators can minimize the attack surface. The combined effect allows both network defenders and security controls to focus and not be mired in superfluous traffic or data types. Looking for deviations to policy can identify attacker activity that abuses services and protocols to run on alternate or non-standard ports in the attempt to avoid detection or frustrate forensic analysts.

#### Detections
* Detect hosts connecting to dynamic domain providers
* Prohibited Network Traffic Allowed
* Protocol or Port Mismatch
* TOR Traffic

#### Data Models
* Network_Resolution
* Network_Traffic

#### Mappings

##### ATT&CK
* T1048
* T1048.003
* T1071.001
* T1189

##### Kill Chain Phases
* Actions on Objectives
* Command and Control
* Delivery

###### CIS
* CIS 12
* CIS 13
* CIS 8
* CIS 9

##### NIST
* DE.AE
* DE.CM
* PR.AC
* PR.DS
* PR.PT

##### References
* http://www.novetta.com/2015/02/advanced-methods-to-detect-advanced-cyber-attacks-protocol-abuse/

### Router and Infrastructure Security
* id = 91c676cf-0b23-438d-abee-f6335e177e77
* date = 2017-09-12
* version = 1

#### Description
Validate the security configuration of network infrastructure and verify that only authorized users and systems are accessing critical assets. Core routing and switching infrastructure are common strategic targets for attackers.

#### Narrative
Networking devices, such as routers and switches, are often overlooked as resources that attackers will leverage to subvert an enterprise. Advanced threats actors have shown a proclivity to target these critical assets as a means to siphon and redirect network traffic, flash backdoored operating systems, and implement cryptographic weakened algorithms to more easily decrypt network traffic.\
This Analytic Story helps you gain a better understanding of how your network devices are interacting with your hosts. By compromising your network devices, attackers can obtain direct access to the company's internal infrastructure&#151; effectively increasing the attack surface and accessing private services/data.

#### Detections
* Detect ARP Poisoning
* Detect IPv6 Network Infrastructure Threats
* Detect New Login Attempts to Routers
* Detect Port Security Violation
* Detect Rogue DHCP Server
* Detect Software Download To Network Device
* Detect Traffic Mirroring

#### Data Models
* Authentication
* Network_Traffic

#### Mappings

##### ATT&CK
* T1020.001
* T1200
* T1498
* T1542.005
* T1557
* T1557.002

##### Kill Chain Phases
* Actions on Objectives
* Delivery
* Exploitation
* Reconnaissance

###### CIS
* CIS 1
* CIS 11

##### NIST
* ID.AM
* PR.AC
* PR.DS
* PR.IP
* PR.PT

##### References
* https://www.fireeye.com/blog/executive-perspective/2015/09/the_new_route_toper.html
* https://www.cisco.com/c/en/us/about/security-center/event-response/synful-knock.html

### Use of Cleartext Protocols
* id = 826e6431-aeef-41b4-9fc0-6d0985d65a21
* date = 2017-09-15
* version = 1

#### Description
Leverage searches that detect cleartext network protocols that may leak credentials or should otherwise be encrypted.

#### Narrative
Various legacy protocols operate by default in the clear, without the protections of encryption. This potentially leaks sensitive information that can be exploited by passively sniffing network traffic. Depending on the protocol, this information could be highly sensitive, or could allow for session hijacking. In addition, these protocols send authentication information, which would allow for the harvesting of usernames and passwords that could potentially be used to authenticate and compromise secondary systems.

#### Detections
* Protocols passing authentication in cleartext

#### Data Models
* Network_Traffic

#### Mappings

##### ATT&CK

##### Kill Chain Phases
* Actions on Objectives
* Reconnaissance

###### CIS
* CIS 14
* CIS 9

##### NIST
* DE.AE
* PR.AC
* PR.DS
* PR.PT

##### References
* https://www.monkey.org/~dugsong/dsniff/


## Cloud Security

* [AWS Cross Account Activity](#AWS-Cross-Account-Activity)

* [AWS Cryptomining](#AWS-Cryptomining)

* [AWS Network ACL Activity](#AWS-Network-ACL-Activity)

* [AWS Security Hub Alerts](#AWS-Security-Hub-Alerts)

* [AWS Suspicious Provisioning Activities](#AWS-Suspicious-Provisioning-Activities)

* [AWS User Monitoring](#AWS-User-Monitoring)

* [Cloud Cryptomining](#Cloud-Cryptomining)

* [Container Implantation Monitoring and Investigation](#Container-Implantation-Monitoring-and-Investigation)

* [GCP Cross Account Activity](#GCP-Cross-Account-Activity)

* [Kubernetes Scanning Activity](#Kubernetes-Scanning-Activity)

* [Kubernetes Sensitive Object Access Activity](#Kubernetes-Sensitive-Object-Access-Activity)

* [Kubernetes Sensitive Role Activity](#Kubernetes-Sensitive-Role-Activity)

* [Office 365 Detections](#Office-365-Detections)

* [Suspicious AWS EC2 Activities](#Suspicious-AWS-EC2-Activities)

* [Suspicious AWS Login Activities](#Suspicious-AWS-Login-Activities)

* [Suspicious AWS S3 Activities](#Suspicious-AWS-S3-Activities)

* [Suspicious AWS Traffic](#Suspicious-AWS-Traffic)

* [Suspicious Cloud Authentication Activities](#Suspicious-Cloud-Authentication-Activities)

* [Suspicious Cloud Instance Activities](#Suspicious-Cloud-Instance-Activities)

* [Suspicious Cloud Provisioning Activities](#Suspicious-Cloud-Provisioning-Activities)

* [Suspicious Cloud User Activities](#Suspicious-Cloud-User-Activities)

* [Suspicious GCP Storage Activities](#Suspicious-GCP-Storage-Activities)

* [Unusual AWS EC2 Modifications](#Unusual-AWS-EC2-Modifications)

### AWS Cross Account Activity
* id = 2f2f610a-d64d-48c2-b57c-967a2b49ab5a
* date = 2018-06-04
* version = 1

#### Description
Track when a user assumes an IAM role in another AWS account to obtain cross-account access to services and resources in that account. Accessing new roles could be an indication of malicious activity.

#### Narrative
Amazon Web Services (AWS) admins manage access to AWS resources and services across the enterprise using AWS's Identity and Access Management (IAM) functionality. IAM provides the ability to create and manage AWS users, groups, and roles-each with their own unique set of privileges and defined access to specific resources (such as EC2 instances, the AWS Management Console, API, or the command-line interface). Unlike conventional (human) users, IAM roles are assumable by anyone in the organization. They provide users with dynamically created temporary security credentials that expire within a set time period.\
Herein lies the rub. In between the time between when the temporary credentials are issued and when they expire is a period of opportunity, where a user could leverage the temporary credentials to wreak havoc-spin up or remove instances, create new users, elevate privileges, and other malicious activities-throughout the environment.\
This Analytic Story includes searches that will help you monitor your AWS CloudTrail logs for evidence of suspicious cross-account activity.  For example, while accessing multiple AWS accounts and roles may be perfectly valid behavior, it may be suspicious when an account requests privileges of an account it has not accessed in the past. After identifying suspicious activities, you can use the provided investigative searches to help you probe more deeply.

#### Detections
* aws detect attach to role policy
* aws detect permanent key creation
* aws detect role creation
* aws detect sts assume role abuse
* aws detect sts get session token abuse

#### Data Models

#### Mappings

##### ATT&CK
* T1078
* T1550

##### Kill Chain Phases
* Lateral Movement

###### CIS

##### NIST

##### References
* https://aws.amazon.com/blogs/security/aws-cloudtrail-now-tracks-cross-account-activity-to-its-origin/

### AWS Cryptomining
* id = ced74200-8465-4bc3-bd2c-9a782eec6750
* date = 2018-03-08
* version = 1

#### Description
Monitor your AWS EC2 instances for activities related to cryptojacking/cryptomining. New instances that originate from previously unseen regions, users who launch abnormally high numbers of instances, or EC2 instances started by previously unseen users are just a few examples of potentially malicious behavior.

#### Narrative
Cryptomining is an intentionally difficult, resource-intensive business. Its complexity was designed into the process to ensure that the number of blocks mined each day would remain steady. So, it's par for the course that ambitious, but unscrupulous, miners make amassing the computing power of large enterprises--a practice known as cryptojacking--a top priority. \
Cryptojacking has attracted an increasing amount of media attention since its explosion in popularity in the fall of 2017. The attacks have moved from in-browser exploits and mobile phones to enterprise cloud services, such as Amazon Web Services (AWS). It's difficult to determine exactly how widespread the practice has become, since bad actors continually evolve their ability to escape detection, including employing unlisted endpoints, moderating their CPU usage, and hiding the mining pool's IP address behind a free CDN. \
When malicious miners appropriate a cloud instance, often spinning up hundreds of new instances, the costs can become astronomical for the account holder. So, it is critically important to monitor your systems for suspicious activities that could indicate that your network has been infiltrated. \
This Analytic Story is focused on detecting suspicious new instances in your EC2 environment to help prevent such a disaster. It contains detection searches that will detect when a previously unused instance type or AMI is used. It also contains support searches to build lookup files to ensure proper execution of the detection searches.

#### Detections
* Abnormally High AWS Instances Launched by User
* Abnormally High AWS Instances Launched by User - MLTK
* EC2 Instance Started In Previously Unseen Region
* EC2 Instance Started With Previously Unseen AMI
* EC2 Instance Started With Previously Unseen Instance Type
* EC2 Instance Started With Previously Unseen User

#### Data Models

#### Mappings

##### ATT&CK
* T1078.004
* T1535

##### Kill Chain Phases
* Actions on Objectives

###### CIS
* CIS 1
* CIS 12
* CIS 13

##### NIST
* DE.AE
* DE.DP
* ID.AM

##### References
* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf

### AWS Network ACL Activity
* id = 2e8948a5-5239-406b-b56b-6c50ff268af4
* date = 2018-05-21
* version = 2

#### Description
Monitor your AWS network infrastructure for bad configurations and malicious activity. Investigative searches help you probe deeper, when the facts warrant it.

#### Narrative
AWS CloudTrail is an AWS service that helps you enable governance, compliance, and operational/risk auditing of your AWS account. Actions taken by a user, role, or an AWS service are recorded as events in CloudTrail. It is crucial for a company to monitor events and actions taken in the AWS Management Console, AWS Command Line Interface, and AWS SDKs and APIs to ensure that your servers are not vulnerable to attacks. This analytic story contains detection searches that leverage CloudTrail logs from AWS to check for bad configurations and malicious activity in your AWS network access controls.

#### Detections
* AWS Network Access Control List Created with All Open Ports
* AWS Network Access Control List Deleted
* Detect Spike in Network ACL Activity
* Detect Spike in blocked Outbound Traffic from your AWS

#### Data Models

#### Mappings

##### ATT&CK
* T1562.007

##### Kill Chain Phases
* Actions on Objectives
* Command and Control

###### CIS
* CIS 11
* CIS 12

##### NIST
* DE.AE
* DE.CM
* DE.DP
* PR.AC

##### References
* https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Appendix_NACLs.html
* https://aws.amazon.com/blogs/security/how-to-help-prepare-for-ddos-attacks-by-reducing-your-attack-surface/

### AWS Security Hub Alerts
* id = 2f2f610a-d64d-48c2-b57c-96722b49ab5a
* date = 2020-08-04
* version = 1

#### Description
This story is focused around detecting Security Hub alerts generated from AWS

#### Narrative
AWS Security Hub collects and consolidates findings from AWS security services enabled in your environment, such as intrusion detection findings from Amazon GuardDuty, vulnerability scans from Amazon Inspector, S3 bucket policy findings from Amazon Macie, publicly accessible and cross-account resources from IAM Access Analyzer, and resources lacking WAF coverage from AWS Firewall Manager.

#### Detections
* Detect Spike in AWS Security Hub Alerts for EC2 Instance
* Detect Spike in AWS Security Hub Alerts for User

#### Data Models

#### Mappings

##### ATT&CK

##### Kill Chain Phases

###### CIS
* CIS 13

##### NIST
* DE.AE
* DE.DP

##### References
* https://aws.amazon.com/security-hub/features/

### AWS Suspicious Provisioning Activities
* id = 3338b567-3804-4261-9889-cf0ca4753c7f
* date = 2018-03-16
* version = 1

#### Description
Monitor your AWS provisioning activities for behaviors originating from unfamiliar or unusual locations. These behaviors may indicate that malicious activities are occurring somewhere within your network.

#### Narrative
Because most enterprise AWS activities originate from familiar geographic locations, monitoring for activity from unknown or unusual regions is an important security measure. This indicator can be especially useful in environments where it is impossible to add specific IPs to an allow list because they vary. \
This Analytic Story was designed to provide you with flexibility in the precision you employ in specifying legitimate geographic regions. It can be as specific as an IP address or a city, or as broad as a region (think state) or an entire country. By determining how precise you want your geographical locations to be and monitoring for new locations that haven't previously accessed your environment, you can detect adversaries as they begin to probe your environment. Since there are legitimate reasons for activities from unfamiliar locations, this is not a standalone indicator. Nevertheless, location can be a relevant piece of information that you may wish to investigate further.

#### Detections
* AWS Cloud Provisioning From Previously Unseen City
* AWS Cloud Provisioning From Previously Unseen Country
* AWS Cloud Provisioning From Previously Unseen IP Address
* AWS Cloud Provisioning From Previously Unseen Region

#### Data Models

#### Mappings

##### ATT&CK
* T1535

##### Kill Chain Phases

###### CIS
* CIS 1

##### NIST
* ID.AM

##### References
* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf

### AWS User Monitoring
* id = 2e8948a5-5239-406b-b56b-6c50f1269af3
* date = 2018-03-12
* version = 1

#### Description
Detect and investigate dormant user accounts for your AWS environment that have become active again. Because inactive and ad-hoc accounts are common attack targets, it's critical to enable governance within your environment.

#### Narrative
It seems obvious that it is critical to monitor and control the users who have access to your cloud infrastructure. Nevertheless, it's all too common for enterprises to lose track of ad-hoc accounts, leaving their servers vulnerable to attack. In fact, this was the very oversight that led to Tesla's cryptojacking attack in February, 2018.\
In addition to compromising the security of your data, when bad actors leverage your compute resources, it can incur monumental costs, since you will be billed for any new EC2 instances and increased bandwidth usage. \
Fortunately, you can leverage Amazon Web Services (AWS) CloudTrail--a tool that helps you enable governance, compliance, and risk auditing of your AWS account--to give you increased visibility into your user and resource activity by recording AWS Management Console actions and API calls. You can identify which users and accounts called AWS, the source IP address from which the calls were made, and when the calls occurred.\
The detection searches in this Analytic Story are designed to help you uncover AWS API activities from users not listed in the identity table, as well as similar activities from disabled accounts.

#### Detections
* Detect API activity from users without MFA
* Detect AWS API Activities From Unapproved Accounts
* Detect Spike in AWS API Activity
* Detect Spike in Security Group Activity
* Detect new API calls from user roles

#### Data Models

#### Mappings

##### ATT&CK
* T1078.004

##### Kill Chain Phases
* Actions on Objectives

###### CIS
* CIS 1
* CIS 16

##### NIST
* DE.CM
* DE.DP
* ID.AM
* PR.AC

##### References
* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf
* https://redlock.io/blog/cryptojacking-tesla

### Cloud Cryptomining
* id = 3b96d13c-fdc7-45dd-b3ad-c132b31cdd2a
* date = 2019-10-02
* version = 1

#### Description
Monitor your cloud compute instances for activities related to cryptojacking/cryptomining. New instances that originate from previously unseen regions, users who launch abnormally high numbers of instances, or compute instances started by previously unseen users are just a few examples of potentially malicious behavior.

#### Narrative
Cryptomining is an intentionally difficult, resource-intensive business. Its complexity was designed into the process to ensure that the number of blocks mined each day would remain steady. So, it's par for the course that ambitious, but unscrupulous, miners make amassing the computing power of large enterprises--a practice known as cryptojacking--a top priority. \
Cryptojacking has attracted an increasing amount of media attention since its explosion in popularity in the fall of 2017. The attacks have moved from in-browser exploits and mobile phones to enterprise cloud services, such as Amazon Web Services (AWS), Google Cloud Platform (GCP), and Azure. It's difficult to determine exactly how widespread the practice has become, since bad actors continually evolve their ability to escape detection, including employing unlisted endpoints, moderating their CPU usage, and hiding the mining pool's IP address behind a free CDN. \
When malicious miners appropriate a cloud instance, often spinning up hundreds of new instances, the costs can become astronomical for the account holder. So it is critically important to monitor your systems for suspicious activities that could indicate that your network has been infiltrated. \
This Analytic Story is focused on detecting suspicious new instances in your cloud environment to help prevent cryptominers from gaining a foothold. It contains detection searches that will detect when a previously unused instance type or AMI is used. It also contains support searches to build lookup files to ensure proper execution of the detection searches.

#### Detections
* Abnormally High Number Of Cloud Instances Launched
* Cloud Compute Instance Created By Previously Unseen User
* Cloud Compute Instance Created In Previously Unused Region
* Cloud Compute Instance Created With Previously Unseen Image
* Cloud Compute Instance Created With Previously Unseen Instance Type

#### Data Models
* Change

#### Mappings

##### ATT&CK
* T1078.004
* T1535

##### Kill Chain Phases
* Actions on Objectives

###### CIS
* CIS 1
* CIS 12
* CIS 13

##### NIST
* DE.AE
* DE.DP
* ID.AM

##### References
* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf

### Container Implantation Monitoring and Investigation
* id = aa0e28b1-0521-4b6f-9d2a-7b87e34af246
* date = 2020-02-20
* version = 1

#### Description
Use the searches in this story to monitor your Kubernetes registry repositories for upload, and deployment of potentially vulnerable, backdoor, or implanted containers. These searches provide information on source users, destination path, container names and repository names. The searches provide context to address Mitre T1525 which refers to container implantation upload to a company's repository either in Amazon Elastic Container Registry, Google Container Registry and Azure Container Registry.

#### Narrative
Container Registrys provide a way for organizations to keep customized images of their development and infrastructure environment in private. However if these repositories are misconfigured or priviledge users credentials are compromise, attackers can potentially upload implanted containers which can be deployed across the organization. These searches allow operator to monitor who, when and what was uploaded to container registry.

#### Detections
* GCP GCR container uploaded
* New container uploaded to AWS ECR

#### Data Models

#### Mappings

##### ATT&CK
* T1525

##### Kill Chain Phases

###### CIS

##### NIST

##### References
* https://github.com/splunk/cloud-datamodel-security-research

### GCP Cross Account Activity
* id = 0432039c-ef41-4b03-b157-450c25dad1e6
* date = 2020-09-01
* version = 1

#### Description
Track when a user assumes an IAM role in another GCP account to obtain cross-account access to services and resources in that account. Accessing new roles could be an indication of malicious activity.

#### Narrative
Google Cloud Platform (GCP) admins manage access to GCP resources and services across the enterprise using GCP Identity and Access Management (IAM) functionality. IAM provides the ability to create and manage GCP users, groups, and roles-each with their own unique set of privileges and defined access to specific resources (such as Compute instances, the GCP Management Console, API, or the command-line interface). Unlike conventional (human) users, IAM roles are potentially assumable by anyone in the organization. They provide users with dynamically created temporary security credentials that expire within a set time period.\
In between the time between when the temporary credentials are issued and when they expire is a period of opportunity, where a user could leverage the temporary credentials to wreak havoc-spin up or remove instances, create new users, elevate privileges, and other malicious activities-throughout the environment.\
This Analytic Story includes searches that will help you monitor your GCP Audit logs logs for evidence of suspicious cross-account activity.  For example, while accessing multiple GCP accounts and roles may be perfectly valid behavior, it may be suspicious when an account requests privileges of an account it has not accessed in the past. After identifying suspicious activities, you can use the provided investigative searches to help you probe more deeply.

#### Detections
* GCP Detect accounts with high risk roles by project
* GCP Detect gcploit framework
* GCP Detect high risk permissions by resource and account
* gcp detect oauth token abuse

#### Data Models

#### Mappings

##### ATT&CK
* T1078

##### Kill Chain Phases
* Lateral Movement

###### CIS

##### NIST

##### References
* https://cloud.google.com/iam/docs/understanding-service-accounts

### Kubernetes Scanning Activity
* id = a9ef59cf-e981-4e66-9eef-bb049f695c09
* date = 2020-04-15
* version = 1

#### Description
This story addresses detection against Kubernetes cluster fingerprint scan and attack by providing information on items such as source ip, user agent, cluster names.

#### Narrative
Kubernetes is the most used container orchestration platform, this orchestration platform contains sensitve information and management priviledges of production workloads, microservices and applications. These searches allow operator to detect suspicious unauthenticated requests from the internet to kubernetes cluster.

#### Detections
* Amazon EKS Kubernetes Pod scan detection
* Amazon EKS Kubernetes cluster scan detection
* GCP Kubernetes cluster pod scan detection
* GCP Kubernetes cluster scan detection
* Kubernetes Azure pod scan fingerprint
* Kubernetes Azure scan fingerprint

#### Data Models

#### Mappings

##### ATT&CK
* T1526

##### Kill Chain Phases
* Reconnaissance

###### CIS

##### NIST

##### References
* https://github.com/splunk/cloud-datamodel-security-research

### Kubernetes Sensitive Object Access Activity
* id = 2574e6d9-7254-4751-8925-0447deeec8ea
* date = 2020-05-20
* version = 1

#### Description
This story addresses detection and response of accounts acccesing Kubernetes cluster sensitive objects such as configmaps or secrets providing information on items such as user user, group. object, namespace and authorization reason.

#### Narrative
Kubernetes is the most used container orchestration platform, this orchestration platform contains sensitive objects within its architecture, specifically configmaps and secrets, if accessed by an attacker can lead to further compromise. These searches allow operator to detect suspicious requests against Kubernetes sensitive objects.

#### Detections
* AWS EKS Kubernetes cluster sensitive object access
* Kubernetes AWS detect service accounts forbidden failure access
* Kubernetes AWS detect suspicious kubectl calls
* Kubernetes Azure detect sensitive object access
* Kubernetes Azure detect service accounts forbidden failure access
* Kubernetes Azure detect suspicious kubectl calls
* Kubernetes GCP detect sensitive object access
* Kubernetes GCP detect service accounts forbidden failure access
* Kubernetes GCP detect suspicious kubectl calls

#### Data Models

#### Mappings

##### ATT&CK

##### Kill Chain Phases
* Lateral Movement

###### CIS

##### NIST

##### References
* https://www.splunk.com/en_us/blog/security/approaching-kubernetes-security-detecting-kubernetes-scan-with-splunk.html

### Kubernetes Sensitive Role Activity
* id = 2574e6d9-7254-4751-8925-0447deeec8ew
* date = 2020-05-20
* version = 1

#### Description
This story addresses detection and response around Sensitive Role usage within a Kubernetes clusters against cluster resources and namespaces.

#### Narrative
Kubernetes is the most used container orchestration platform, this orchestration platform contains sensitive roles within its architecture, specifically configmaps and secrets, if accessed by an attacker can lead to further compromise. These searches allow operator to detect suspicious requests against Kubernetes role activities

#### Detections
* Kubernetes AWS detect RBAC authorization by account
* Kubernetes AWS detect most active service accounts by pod
* Kubernetes AWS detect sensitive role access
* Kubernetes Azure detect RBAC authorization by account
* Kubernetes Azure detect most active service accounts by pod namespace
* Kubernetes Azure detect sensitive role access
* Kubernetes GCP detect RBAC authorizations by account
* Kubernetes GCP detect most active service accounts by pod
* Kubernetes GCP detect sensitive role access

#### Data Models

#### Mappings

##### ATT&CK

##### Kill Chain Phases
* Lateral Movement

###### CIS

##### NIST

##### References
* https://www.splunk.com/en_us/blog/security/approaching-kubernetes-security-detecting-kubernetes-scan-with-splunk.html

### Office 365 Detections
* id = 1a51dd71-effc-48b2-abc4-3e9cdb61e5b9
* date = 2020-12-16
* version = 1

#### Description
This story is focused around detecting Office 365 Attacks.

#### Narrative
More and more companies are using Microsofts Office 365 cloud offering. Therefore, we see more and more attacks against Office 365. This story provides various detections for Office 365 attacks.

#### Detections
* High Number of Login Failures from a single source
* O365 Bypass MFA via Trusted IP
* O365 Disable MFA
* O365 Excessive Authentication Failures Alert
* O365 PST export alert
* O365 Suspicious Admin Email Forwarding
* O365 Suspicious Rights Delegation
* O365 Suspicious User Email Forwarding

#### Data Models

#### Mappings

##### ATT&CK
* T1110
* T1110.001
* T1114
* T1114.002
* T1114.003
* T1556
* T1562.007

##### Kill Chain Phases
* Actions on Objective
* Actions on Objectives
* Not Applicable

###### CIS
* CIS 16

##### NIST
* DE.AE
* DE.DP

##### References
* https://i.blackhat.com/USA-20/Thursday/us-20-Bienstock-My-Cloud-Is-APTs-Cloud-Investigating-And-Defending-Office-365.pdf

### Suspicious AWS EC2 Activities
* id = 2e8948a5-5239-406b-b56b-6c50f1268af3
* date = 2018-02-09
* version = 1

#### Description
Use the searches in this Analytic Story to monitor your AWS EC2 instances for evidence of anomalous activity and suspicious behaviors, such as EC2 instances that originate from unusual locations or those launched by previously unseen users (among others). Included investigative searches will help you probe more deeply, when the information warrants it.

#### Narrative
AWS CloudTrail is an AWS service that helps you enable governance, compliance, and risk auditing within your AWS account. Actions taken by a user, role, or an AWS service are recorded as events in CloudTrail. It is crucial for a company to monitor events and actions taken in the AWS Console, AWS command-line interface, and AWS SDKs and APIs to ensure that your EC2 instances are not vulnerable to attacks. This Analytic Story identifies suspicious activities in your AWS EC2 instances and helps you respond and investigate those activities.

#### Detections
* Abnormally High AWS Instances Launched by User
* Abnormally High AWS Instances Launched by User - MLTK
* Abnormally High AWS Instances Terminated by User
* Abnormally High AWS Instances Terminated by User - MLTK
* EC2 Instance Started In Previously Unseen Region
* EC2 Instance Started With Previously Unseen User

#### Data Models

#### Mappings

##### ATT&CK
* T1078.004
* T1535

##### Kill Chain Phases
* Actions on Objectives

###### CIS
* CIS 1
* CIS 12
* CIS 13

##### NIST
* DE.AE
* DE.DP
* ID.AM

##### References
* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf

### Suspicious AWS Login Activities
* id = 2e8948a5-5239-406b-b56b-6c59f1268af3
* date = 2019-05-01
* version = 1

#### Description
Monitor your AWS authentication events using your CloudTrail logs. Searches within this Analytic Story will help you stay aware of and investigate suspicious logins. 

#### Narrative
It is important to monitor and control who has access to your AWS infrastructure. Detecting suspicious logins to your AWS infrastructure will provide good starting points for investigations. Abusive behaviors caused by compromised credentials can lead to direct monetary costs, as you will be billed for any EC2 instances created by the attacker.

#### Detections
* Detect AWS Console Login by User from New City
* Detect AWS Console Login by User from New Country
* Detect AWS Console Login by User from New Region
* Detect new user AWS Console Login

#### Data Models
* Authentication

#### Mappings

##### ATT&CK
* T1078.004
* T1535

##### Kill Chain Phases
* Actions on Objectives

###### CIS
* CIS 16

##### NIST
* DE.AE
* DE.DP

##### References
* https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html

### Suspicious AWS S3 Activities
* id = 2e8948a5-5239-406b-b56b-6c50w3168af3
* date = 2018-07-24
* version = 2

#### Description
Use the searches in this Analytic Story to monitor your AWS S3 buckets for evidence of anomalous activity and suspicious behaviors, such as detecting open S3 buckets and buckets being accessed from a new IP. The contextual and investigative searches will give you more information, when required.

#### Narrative
As cloud computing has exploded, so has the number of creative attacks on virtual environments. And as the number-two cloud-service provider, Amazon Web Services (AWS) has certainly had its share.\
Amazon's "shared responsibility" model dictates that the company has responsibility for the environment outside of the VM and the customer is responsible for the security inside of the S3 container. As such, it's important to stay vigilant for activities that may belie suspicious behavior inside of your environment.\
Among things to look out for are S3 access from unfamiliar locations and by unfamiliar users. Some of the searches in this Analytic Story help you detect suspicious behavior and others help you investigate more deeply, when the situation warrants.   

#### Detections
* Detect New Open S3 Buckets over AWS CLI
* Detect New Open S3 buckets
* Detect S3 access from a new IP
* Detect Spike in S3 Bucket deletion

#### Data Models

#### Mappings

##### ATT&CK
* T1530

##### Kill Chain Phases
* Actions on Objectives

###### CIS
* CIS 13
* CIS 14

##### NIST
* DE.CM
* DE.DP
* PR.AC
* PR.DS

##### References
* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf
* https://www.tripwire.com/state-of-security/security-data-protection/cloud/public-aws-s3-buckets-writable/

### Suspicious AWS Traffic
* id = 2e8948a5-5239-406b-b56b-6c50f2168af3
* date = 2018-05-07
* version = 1

#### Description
Leverage these searches to monitor your AWS network traffic for evidence of anomalous activity and suspicious behaviors, such as a spike in blocked outbound traffic in your virtual private cloud (VPC).

#### Narrative
A virtual private cloud (VPC) is an on-demand managed cloud-computing service that isolates computing resources for each client. Inside the VPC container, the environment resembles a physical network. \
Amazon's VPC service enables you to launch EC2 instances and leverage other Amazon resources. The traffic that flows in and out of this VPC can be controlled via network access-control rules and security groups. Amazon also has a feature called VPC Flow Logs that enables you to log IP traffic going to and from the network interfaces in your VPC. This data is stored using Amazon CloudWatch Logs.\
 Attackers may abuse the AWS infrastructure with insecure VPCs so they can co-opt AWS resources for command-and-control nodes, data exfiltration, and more. Once an EC2 instance is compromised, an attacker may initiate outbound network connections for malicious reasons. Monitoring these network traffic behaviors is crucial for understanding the type of traffic flowing in and out of your network and to alert you to suspicious activities.\
The searches in this Analytic Story will monitor your AWS network traffic for evidence of anomalous activity and suspicious behaviors.

#### Detections
* Detect Spike in blocked Outbound Traffic from your AWS

#### Data Models

#### Mappings

##### ATT&CK

##### Kill Chain Phases
* Actions on Objectives
* Command and Control

###### CIS
* CIS 11

##### NIST
* DE.AE
* DE.CM
* PR.AC

##### References
* https://rhinosecuritylabs.com/aws/hiding-cloudcobalt-strike-beacon-c2-using-amazon-apis/

### Suspicious Cloud Authentication Activities
* id = 6380ebbb-55c5-4fce-b754-01fd565fb73c
* date = 2020-06-04
* version = 1

#### Description
Monitor your cloud authentication events. Searches within this Analytic Story leverage the recent cloud updates to the Authentication data model to help you stay aware of and investigate suspicious login activity. 

#### Narrative
It is important to monitor and control who has access to your cloud infrastructure. Detecting suspicious logins will provide good starting points for investigations. Abusive behaviors caused by compromised credentials can lead to direct monetary costs, as you will be billed for any compute activity whether legitimate or otherwise.\
This Analytic Story has data model versions of cloud searches leveraging Authentication data, including those looking for suspicious login activity, and cross-account activity for AWS.

#### Detections
* AWS Cross Account Activity From Previously Unseen Account
* Detect AWS Console Login by New User
* Detect AWS Console Login by User from New City
* Detect AWS Console Login by User from New Country
* Detect AWS Console Login by User from New Region

#### Data Models
* Authentication

#### Mappings

##### ATT&CK
* T1535

##### Kill Chain Phases
* Actions on Objectives

###### CIS
* CIS 16

##### NIST
* DE.AE
* DE.DP
* PR.AC
* PR.DS

##### References
* https://aws.amazon.com/blogs/security/aws-cloudtrail-now-tracks-cross-account-activity-to-its-origin/
* https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html

### Suspicious Cloud Instance Activities
* id = 8168ca88-392e-42f4-85a2-767579c660ce
* date = 2020-08-25
* version = 1

#### Description
Monitor your cloud infrastructure provisioning activities for behaviors originating from unfamiliar or unusual locations. These behaviors may indicate that malicious activities are occurring somewhere within your cloud environment.

#### Narrative
Monitoring your cloud infrastructure logs allows you enable governance, compliance, and risk auditing. It is crucial for a company to monitor events and actions taken in the their cloud environments to ensure that your instances are not vulnerable to attacks. This Analytic Story identifies suspicious activities in your cloud compute instances and helps you respond and investigate those activities.

#### Detections
* Abnormally High Number Of Cloud Instances Destroyed
* Abnormally High Number Of Cloud Instances Launched
* Cloud Instance Modified By Previously Unseen User

#### Data Models
* Change

#### Mappings

##### ATT&CK
* T1078.004

##### Kill Chain Phases
* Actions on Objectives

###### CIS
* CIS 1
* CIS 13

##### NIST
* DE.AE
* DE.DP
* ID.AM

##### References
* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf

### Suspicious Cloud Provisioning Activities
* id = 51045ded-1575-4ba6-aef7-af6c73cffd86
* date = 2018-08-20
* version = 1

#### Description
Monitor your cloud infrastructure provisioning activities for behaviors originating from unfamiliar or unusual locations. These behaviors may indicate that malicious activities are occurring somewhere within your cloud environment.

#### Narrative
Because most enterprise cloud infrastructure activities originate from familiar geographic locations, monitoring for activity from unknown or unusual regions is an important security measure. This indicator can be especially useful in environments where it is impossible to add specific IPs to an allow list because they vary.\
This Analytic Story was designed to provide you with flexibility in the precision you employ in specifying legitimate geographic regions. It can be as specific as an IP address or a city, or as broad as a region (think state) or an entire country. By determining how precise you want your geographical locations to be and monitoring for new locations that haven't previously accessed your environment, you can detect adversaries as they begin to probe your environment. Since there are legitimate reasons for activities from unfamiliar locations, this is not a standalone indicator. Nevertheless, location can be a relevant piece of information that you may wish to investigate further.

#### Detections
* Cloud Provisioning Activity From Previously Unseen City
* Cloud Provisioning Activity From Previously Unseen Country
* Cloud Provisioning Activity From Previously Unseen IP Address
* Cloud Provisioning Activity From Previously Unseen Region

#### Data Models
* Change

#### Mappings

##### ATT&CK
* T1078

##### Kill Chain Phases

###### CIS
* CIS 1

##### NIST
* ID.AM

##### References
* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf

### Suspicious Cloud User Activities
* id = 1ed5ce7d-5469-4232-92af-89d1a3595b39
* date = 2020-09-04
* version = 1

#### Description
Detect and investigate suspicious activities by users and roles in your cloud environments.

#### Narrative
It seems obvious that it is critical to monitor and control the users who have access to your cloud infrastructure. Nevertheless, it's all too common for enterprises to lose track of ad-hoc accounts, leaving their servers vulnerable to attack. In fact, this was the very oversight that led to Tesla's cryptojacking attack in February, 2018.\
In addition to compromising the security of your data, when bad actors leverage your compute resources, it can incur monumental costs, since you will be billed for any new instances and increased bandwidth usage.

#### Detections
* Abnormally High Number Of Cloud Infrastructure API Calls
* Abnormally High Number Of Cloud Security Group API Calls
* Cloud API Calls From Previously Unseen User Roles

#### Data Models
* Change

#### Mappings

##### ATT&CK
* T1078
* T1078.004

##### Kill Chain Phases
* Actions on Objectives

###### CIS
* CIS 1
* CIS 16

##### NIST
* DE.CM
* DE.DP
* ID.AM
* PR.AC

##### References
* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf
* https://redlock.io/blog/cryptojacking-tesla

### Suspicious GCP Storage Activities
* id = 4d656b2e-d6be-11ea-87d0-0242ac130003
* date = 2020-08-05
* version = 1

#### Description
Use the searches in this Analytic Story to monitor your GCP Storage buckets for evidence of anomalous activity and suspicious behaviors, such as detecting open storage buckets and buckets being accessed from a new IP. The contextual and investigative searches will give you more information, when required.

#### Narrative
Similar to other cloud providers, GCP operates on a shared responsibility model. This means the end user, you, are responsible for setting appropriate access control lists and permissions on your GCP resources.\ This Analytics Story concentrates on detecting things like open storage buckets (both read and write) along with storage bucket access from unfamiliar users and IP addresses.

#### Detections
* Detect GCP Storage access from a new IP
* Detect New Open GCP Storage Buckets

#### Data Models

#### Mappings

##### ATT&CK
* T1530

##### Kill Chain Phases
* Actions on Objectives

###### CIS
* CIS 13
* CIS 14

##### NIST
* DE.CM
* PR.AC
* PR.DS

##### References
* https://cloud.google.com/blog/products/gcp/4-steps-for-hardening-your-cloud-storage-buckets-taking-charge-of-your-security
* https://rhinosecuritylabs.com/gcp/google-cloud-platform-gcp-bucket-enumeration/

### Unusual AWS EC2 Modifications
* id = 73de57ef-0dfc-411f-b1e7-fa24428aeae0
* date = 2018-04-09
* version = 1

#### Description
Identify unusual changes to your AWS EC2 instances that may indicate malicious activity. Modifications to your EC2 instances by previously unseen users is an example of an activity that may warrant further investigation.

#### Narrative
A common attack technique is to infiltrate a cloud instance and make modifications. The adversary can then secure access to your infrastructure or hide their activities. So it's important to stay alert to changes that may indicate that your environment has been compromised. \
 Searches within this Analytic Story can help you detect the presence of a threat by monitoring for EC2 instances that have been created or changed--either by users that have never previously performed these activities or by known users who modify or create instances in a way that have not been done before. This story also provides investigative searches that help you go deeper once you detect suspicious behavior.

#### Detections
* EC2 Instance Modified With Previously Unseen User

#### Data Models

#### Mappings

##### ATT&CK
* T1078.004

##### Kill Chain Phases

###### CIS
* CIS 1

##### NIST
* ID.AM

##### References
* https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf


## Malware

* [ColdRoot MacOS RAT](#ColdRoot-MacOS-RAT)

* [DHS Report TA18-074A](#DHS-Report-TA18-074A)

* [Dynamic DNS](#Dynamic-DNS)

* [Emotet Malware  DHS Report TA18-201A ](#Emotet-Malware--DHS-Report-TA18-201A-)

* [Hidden Cobra Malware](#Hidden-Cobra-Malware)

* [Orangeworm Attack Group](#Orangeworm-Attack-Group)

* [Ransomware](#Ransomware)

* [Ransomware Cloud](#Ransomware-Cloud)

* [Ryuk Ransomware](#Ryuk-Ransomware)

* [SamSam Ransomware](#SamSam-Ransomware)

* [Unusual Processes](#Unusual-Processes)

* [Windows File Extension and Association Abuse](#Windows-File-Extension-and-Association-Abuse)

* [Windows Service Abuse](#Windows-Service-Abuse)

### ColdRoot MacOS RAT
* id = bd91a2bc-d20b-4f44-a982-1bea98e86390
* date = 2019-01-09
* version = 1

#### Description
Leverage searches that allow you to detect and investigate unusual activities that relate to the ColdRoot Remote Access Trojan that affects MacOS. An example of some of these activities are changing sensative binaries in the MacOS sub-system, detecting process names and executables associated with the RAT, detecting when a keyboard tab is installed on a MacOS machine and more.

#### Narrative
Conventional wisdom holds that Apple's MacOS operating system is significantly less vulnerable to attack than Windows machines. While that point is debatable, it is true that attacks against MacOS systems are much less common. However, this fact does not mean that Macs are impervious to breaches. To the contrary, research has shown that that Mac malware is increasing at an alarming rate. According to AV-test, in 2018, there were 86,865 new MacOS malware variants, up from 27,338 the year before&#151;a 31% increase. In contrast, the independent research firm found that new Windows malware had increased from 65.17M to 76.86M during that same period, less than half the rate of growth. The bottom line is that while the numbers look a lot smaller than Windows, it's definitely time to take Mac security more seriously.\
This Analytic Story addresses the ColdRoot remote access trojan (RAT), which was uploaded to Github in 2016, but was still escaping detection by the first quarter of 2018, when a new, more feature-rich variant was discovered masquerading as an Apple audio driver. Among other capabilities, the Pascal-based ColdRoot can heist passwords from users' keychains and remotely control infected machines without detection. In the initial report of his findings, Patrick Wardle, Chief Research Officer for Digita Security, explained that the new ColdRoot RAT could start and kill processes on the breached system, spawn new remote-desktop sessions, take screen captures and assemble them into a live stream of the victim's desktop, and more.\
Searches in this Analytic Story leverage the capabilities of OSquery to address ColdRoot detection from several different angles, such as looking for the existence of associated files and processes, and monitoring for signs of an installed keylogger.

#### Detections
* Osquery pack - ColdRoot detection
* Processes Tapping Keyboard Events

#### Data Models

#### Mappings

##### ATT&CK

##### Kill Chain Phases
* Command and Control
* Installation

###### CIS
* CIS 4
* CIS 8

##### NIST
* DE.CM
* DE.DP
* PR.PT

##### References
* https://www.intego.com/mac-security-blog/osxcoldroot-and-the-rat-invasion/
* https://objective-see.com/blog/blog_0x2A.html
* https://www.bleepingcomputer.com/news/security/coldroot-rat-still-undetectable-despite-being-uploaded-on-github-two-years-ago/

### DHS Report TA18-074A
* id = 0c016e5c-88be-4e2c-8c6c-c2b55b4fb4ef
* date = 2020-01-22
* version = 2

#### Description
Monitor for suspicious activities associated with DHS Technical Alert US-CERT TA18-074A. Some of the activities that adversaries used in these compromises included spearfishing attacks, malware, watering-hole domains, many and more.

#### Narrative
The frequency of nation-state cyber attacks has increased significantly over the last decade. Employing numerous tactics and techniques, these attacks continue to escalate in complexity. \
There is a wide range of motivations for these state-sponsored hacks, including stealing valuable corporate, military, or diplomatic data&#1151;all of which could confer advantages in various arenas. They may also target critical infrastructure. \
One joint Technical Alert (TA) issued by the Department of Homeland and the FBI in mid-March of 2018 attributed some cyber activity targeting utility infrastructure to operatives sponsored by the Russian government. The hackers executed spearfishing attacks, installed malware, employed watering-hole domains, and more. While they caused no physical damage, the attacks provoked fears that a nation-state could turn off water, redirect power, or compromise a nuclear power plant.\
Suspicious activities--spikes in SMB traffic, processes that launch netsh (to modify the network configuration), suspicious registry modifications, and many more--may all be events you may wish to investigate further. While the use of these technique may be an indication that a nation-state actor is attempting to compromise your environment, it is important to note that these techniques are often employed by other groups, as well.

#### Detections
* Create local admin accounts using net exe
* Detect New Local Admin account
* Detect Outbound SMB Traffic
* Detect PsExec With accepteula Flag
* First time seen command line argument
* Malicious PowerShell Process - Execution Policy Bypass
* Processes launching netsh
* Registry Keys Used For Persistence
* SMB Traffic Spike
* SMB Traffic Spike - MLTK
* Sc exe Manipulating Windows Services
* Scheduled Task Deleted Or Created via CMD
* Single Letter Process On Endpoint
* Suspicious Reg exe Process

#### Data Models
* Endpoint
* Network_Traffic

#### Mappings

##### ATT&CK
* T1021.002
* T1053.005
* T1059.001
* T1059.003
* T1071.002
* T1112
* T1136.001
* T1204.002
* T1543.003
* T1547.001
* T1562.004

##### Kill Chain Phases
* Actions on Objectives
* Command and Control
* Installation

###### CIS
* CIS 12
* CIS 16
* CIS 2
* CIS 3
* CIS 5
* CIS 7
* CIS 8

##### NIST
* DE.AE
* DE.CM
* ID.AM
* PR.AC
* PR.AT
* PR.DS
* PR.IP
* PR.PT

##### References
* https://www.us-cert.gov/ncas/alerts/TA18-074A

### Dynamic DNS
* id = 8169f17b-ef68-4b59-aae8-586907301221
* date = 2018-09-06
* version = 2

#### Description
Detect and investigate hosts in your environment that may be communicating with dynamic domain providers. Attackers may leverage these services to help them avoid firewall blocks and deny lists.

#### Narrative
Dynamic DNS services (DDNS) are legitimate low-cost or free services that allow users to rapidly update domain resolutions to IP infrastructure. While their usage can be benign, malicious actors can abuse DDNS to host harmful payloads or interactive-command-and-control infrastructure. These attackers will manually update or automate domain resolution changes by routing dynamic domains to IP addresses that circumvent firewall blocks and deny lists and frustrate a network defender's analytic and investigative processes. These searches will look for DNS queries made from within your infrastructure to suspicious dynamic domains and then investigate more deeply, when appropriate. While this list of top-level dynamic domains is not exhaustive, it can be dynamically updated as new suspicious dynamic domains are identified.

#### Detections
* Detect hosts connecting to dynamic domain providers
* Detect web traffic to dynamic domain providers

#### Data Models
* Network_Resolution
* Web

#### Mappings

##### ATT&CK
* T1071.001
* T1189

##### Kill Chain Phases
* Actions on Objectives
* Command and Control

###### CIS
* CIS 12
* CIS 13
* CIS 7
* CIS 8

##### NIST
* DE.AE
* DE.CM
* DE.DP
* PR.DS
* PR.IP
* PR.PT

##### References
* https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html
* https://umbrella.cisco.com/blog/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/
* http://www.noip.com/blog/2014/07/11/dynamic-dns-can-use-2/
* https://www.splunk.com/blog/2015/08/04/detecting-dynamic-dns-domains-in-splunk.html

### Emotet Malware  DHS Report TA18-201A 
* id = bb9f5ed2-916e-4364-bb6d-91c310efcf52
* date = 2020-01-27
* version = 1

#### Description
Detect rarely used executables, specific registry paths that may confer malware survivability and persistence, instances where cmd.exe is used to launch script interpreters, and other indicators that the Emotet financial malware has compromised your environment.

#### Narrative
The trojan downloader known as Emotet first surfaced in 2014, when it was discovered targeting the banking industry to steal credentials. However, according to a joint technical alert (TA) issued by three government agencies (https://www.us-cert.gov/ncas/alerts/TA18-201A), Emotet has evolved far beyond those beginnings to become what a ThreatPost article called a threat-delivery service(see https://threatpost.com/emotet-malware-evolves-beyond-banking-to-threat-delivery-service/134342/).  For example, in early 2018, Emotet was found to be using its loader function to spread the Quakbot and Ransomware variants. \
According to the TA, the the malware continues to be among the most costly and destructive malware affecting the private and public sectors. Researchers have linked it to the threat group Mealybug, which has also been on the security communitys radar since 2014.\
The searches in this Analytic Story will help you find executables that are rarely used in your environment, specific registry paths that malware often uses to ensure survivability and persistence, instances where cmd.exe is used to launch script interpreters, and other indicators that Emotet or other malware has compromised your environment. 

#### Detections
* Detect Rare Executables
* Detect Use of cmd exe to Launch Script Interpreters
* Detection of tools built by NirSoft
* Email Attachments With Lots Of Spaces
* Prohibited Software On Endpoint
* Registry Keys Used For Persistence
* SMB Traffic Spike
* SMB Traffic Spike - MLTK
* Suspicious Email Attachment Extensions

#### Data Models
* Email
* Endpoint
* Network_Traffic

#### Mappings

##### ATT&CK
* T1021.002
* T1059.003
* T1072
* T1547.001
* T1566.001

##### Kill Chain Phases
* Actions on Objectives
* Command and Control
* Delivery
* Exploitation
* Installation

###### CIS
* CIS 12
* CIS 2
* CIS 3
* CIS 7
* CIS 8

##### NIST
* DE.AE
* DE.CM
* ID.AM
* PR.DS
* PR.IP
* PR.PT

##### References
* https://www.us-cert.gov/ncas/alerts/TA18-201A
* https://www.first.org/resources/papers/conf2017/Advanced-Incident-Detection-and-Threat-Hunting-using-Sysmon-and-Splunk.pdf
* https://www.vkremez.com/2017/05/emotet-banking-trojan-malware-analysis.html

### Hidden Cobra Malware
* id = baf7580b-d4b4-4774-8173-7d198e9da335
* date = 2020-01-22
* version = 2

#### Description
Monitor for and investigate activities, including the creation or deletion of hidden shares and file writes, that may be evidence of infiltration by North Korean government-sponsored cybercriminals. Details of this activity were reported in DHS Report TA-18-149A.

#### Narrative
North Korea's government-sponsored "cyber army" has been slowly building momentum and gaining sophistication over the last 15 years or so. As a result, the group's activity, which the US government refers to as "Hidden Cobra," has surreptitiously crept onto the collective radar as a preeminent global threat.\
These state-sponsored actors are thought to be responsible for everything from a hack on a South Korean nuclear plant to an attack on Sony in anticipation of its release of the movie "The Interview" at the end of 2014. They're also notorious for cyberespionage. In recent years, the group seems to be focused on financial crimes, such as cryptojacking.\
In June of 2018, The Department of Homeland Security, together with the FBI and other U.S. government partners, issued Technical Alert (TA-18-149A) to advise the public about two variants of North Korean malware. One variant, dubbed "Joanap," is a multi-stage peer-to-peer botnet that allows North Korean state actors to exfiltrate data, download and execute secondary payloads, and initialize proxy communications. The other variant, "Brambul," is a Windows32 SMB worm that is dropped into a victim network. When executed, the malware attempts to spread laterally within a victim's local subnet, connecting via the SMB protocol and initiating brute-force password attacks. It reports details to the Hidden Cobra actors via email, so they can use the information for secondary remote operations.\
Among other searches in this Analytic Story is a detection search that looks for the creation or deletion of hidden shares, such as, "adnim$," which the Hidden Cobra malware creates on the target system. Another looks for the creation of three malicious files associated with the malware. You can also use a search in this story to investigate activity that indicates that malware is sending email back to the attackers.

#### Detections
* Create or delete windows shares using net exe
* DNS Query Length Outliers - MLTK
* DNS Query Length With High Standard Deviation
* Detect Outbound SMB Traffic
* First time seen command line argument
* Remote Desktop Network Traffic
* Remote Desktop Process Running On System
* SMB Traffic Spike
* SMB Traffic Spike - MLTK
* Suspicious File Write

#### Data Models
* Endpoint
* Network_Resolution
* Network_Traffic

#### Mappings

##### ATT&CK
* T1021.001
* T1021.002
* T1048.003
* T1059.001
* T1059.003
* T1070.005
* T1071.002
* T1071.004

##### Kill Chain Phases
* Actions on Objectives
* Command and Control

###### CIS
* CIS 12
* CIS 16
* CIS 3
* CIS 8
* CIS 9

##### NIST
* DE.AE
* DE.CM
* PR.AC
* PR.IP
* PR.PT

##### References
* https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity
* https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Destructive-Malware-Report.pdf

### Orangeworm Attack Group
* id = bb9f5ed2-916e-4364-bb6d-97c370efcf52
* date = 2020-01-22
* version = 2

#### Description
Detect activities and various techniques associated with the Orangeworm Attack Group, a group that frequently targets the healthcare industry.

#### Narrative
In May of 2018, the attack group Orangeworm was implicated for installing a custom backdoor called Trojan.Kwampirs within large international healthcare corporations in the United States, Europe, and Asia. This malware provides the attackers with remote access to the target system, decrypting and extracting a copy of its main DLL payload from its resource section. Before writing the payload to disk, it inserts a randomly generated string into the middle of the decrypted payload in an attempt to evade hash-based detections.\
Awareness of the Orangeworm group first surfaced in January, 2015. It has conducted targeted attacks against related industries, as well, such as pharmaceuticals and healthcare IT solution providers.\
Healthcare may be a promising target, because it is notoriously behind in technology, often using older operating systems and neglecting to patch computers. Even so, the group was able to evade detection for a full three years. Sources say that the malware spread quickly within the target networks, infecting computers used to control medical devices, such as MRI and X-ray machines.\
This Analytic Story is designed to help you detect and investigate suspicious activities that may be indicative of an Orangeworm attack. One detection search looks for command-line arguments. Another monitors for uses of sc.exe, a non-essential Windows file that can manipulate Windows services. One of the investigative searches helps you get more information on web hosts that you suspect have been compromised.

#### Detections
* First Time Seen Running Windows Service
* First time seen command line argument
* Sc exe Manipulating Windows Services

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK
* T1059.001
* T1059.003
* T1543.003
* T1569.002

##### Kill Chain Phases
* Actions on Objectives
* Command and Control
* Installation

###### CIS
* CIS 2
* CIS 3
* CIS 5
* CIS 8
* CIS 9

##### NIST
* DE.AE
* DE.CM
* ID.AM
* PR.AC
* PR.AT
* PR.DS
* PR.IP
* PR.PT

##### References
* https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia
* https://www.infosecurity-magazine.com/news/healthcare-targeted-by-hacker/

### Ransomware
* id = cf309d0d-d4aa-4fbb-963d-1e79febd3756
* date = 2020-02-04
* version = 1

#### Description
Leverage searches that allow you to detect and investigate unusual activities that might relate to ransomware--spikes in SMB traffic, suspicious wevtutil usage, the presence of common ransomware extensions, and system processes run from unexpected locations, and many others.

#### Narrative
Ransomware is an ever-present risk to the enterprise, wherein an infected host encrypts business-critical data, holding it hostage until the victim pays the attacker a ransom. There are many types and varieties of ransomware that can affect an enterprise. Attackers can deploy ransomware to enterprises through spearphishing campaigns and driveby downloads, as well as through traditional remote service-based exploitation. In the case of the WannaCry campaign, there was self-propagating wormable functionality that was used to maximize infection. Fortunately, organizations can apply several techniques--such as those in this Analytic Story--to detect and or mitigate the effects of ransomware.

#### Detections
* BCDEdit Failure Recovery Modification
* Common Ransomware Extensions
* Common Ransomware Notes
* Deleting Shadow Copies
* Prohibited Network Traffic Allowed
* Registry Keys Used For Persistence
* Remote Process Instantiation via WMI
* SMB Traffic Spike
* SMB Traffic Spike - MLTK
* Scheduled tasks used in BadRabbit ransomware
* Schtasks used for forcing a reboot
* Spike in File Writes
* Suspicious wevtutil Usage
* System Processes Run From Unexpected Locations
* TOR Traffic
* USN Journal Deletion
* Unusually Long Command Line
* Unusually Long Command Line - MLTK
* WBAdmin Delete System Backups
* Windows Event Log Cleared

#### Data Models
* Endpoint
* Network_Traffic

#### Mappings

##### ATT&CK
* T1021.002
* T1036.003
* T1047
* T1048
* T1053.005
* T1070
* T1070.001
* T1071.001
* T1485
* T1490
* T1547.001

##### Kill Chain Phases
* Actions on Objectives
* Command and Control
* Delivery

###### CIS
* CIS 10
* CIS 12
* CIS 3
* CIS 5
* CIS 6
* CIS 8
* CIS 9

##### NIST
* DE.AE
* DE.CM
* DE.DP
* PR.AC
* PR.AT
* PR.IP
* PR.PT

##### References
* https://www.carbonblack.com/2017/06/28/carbon-black-threat-research-technical-analysis-petya-notpetya-ransomware/
* https://www.splunk.com/blog/2017/06/27/closing-the-detection-to-mitigation-gap-or-to-petya-or-notpetya-whocares-.html

### Ransomware Cloud
* id = f52f6c43-05f8-4b19-a9d3-5b8c56da91c2
* date = 2020-10-27
* version = 1

#### Description
Leverage searches that allow you to detect and investigate unusual activities that might relate to ransomware. These searches include cloud related objects that may be targeted by malicious actors via cloud providers own encryption features.

#### Narrative
Ransomware is an ever-present risk to the enterprise, wherein an infected host encrypts business-critical data, holding it hostage until the victim pays the attacker a ransom. There are many types and varieties of ransomware that can affect an enterprise.Cloud ransomware can be deployed by obtaining high privilege credentials from targeted users or resources.

#### Detections
* AWS Detect Users creating keys with encrypt policy without MFA
* AWS Detect Users with KMS keys performing encryption S3

#### Data Models

#### Mappings

##### ATT&CK
* T1486

##### Kill Chain Phases

###### CIS

##### NIST

##### References
* https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/
* https://github.com/d1vious/git-wild-hunt
* https://www.youtube.com/watch?v=PgzNib37g0M

### Ryuk Ransomware
* id = 507edc74-13d5-4339-878e-b9744ded1f35
* date = 2020-11-06
* version = 1

#### Description
Leverage searches that allow you to detect and investigate unusual activities that might relate to the Ryuk ransomware, including looking for file writes associated with Ryuk, Stopping Security Access Manager, DisableAntiSpyware registry key modification, suspicious psexec use, and more.

#### Narrative
Cybersecurity Infrastructure Security Agency (CISA) released Alert (AA20-302A) on October 28th called “Ransomware Activity Targeting the Healthcare and Public Health Sector.” This alert details TTPs associated with ongoing and possible imminent attacks against the Healthcare sector, and is a joint advisory in coordination with other U.S. Government agencies. The objective of these malicious campaigns is to infiltrate targets in named sectors and to drop ransomware payloads, which will likely cause disruption of service and increase risk of actual harm to the health and safety of patients at hospitals, even with the aggravant of an ongoing COVID-19 pandemic. This document specifically refers to several crimeware exploitation frameworks, emphasizing the use of Ryuk ransomware as payload. The Ryuk ransomware payload is not new. It has been well documented and identified in multiple variants. Payloads need a carrier, and for Ryuk it has often been exploitation frameworks such as Cobalt Strike, or popular crimeware frameworks such as Emotet or Trickbot.

#### Detections
* BCDEdit Failure Recovery Modification
* Common Ransomware Notes
* NLTest Domain Trust Discovery
* Remote Desktop Network Bruteforce
* Remote Desktop Network Traffic
* Ryuk Test Files Detected
* Spike in File Writes
* WBAdmin Delete System Backups
* Windows DisableAntiSpyware Registry
* Windows Security Account Manager Stopped
* Windows connhost exe started forcefully

#### Data Models
* Endpoint
* Network_Traffic

#### Mappings

##### ATT&CK
* T1021.001
* T1059.003
* T1482
* T1485
* T1486
* T1489
* T1490
* T1562.001

##### Kill Chain Phases
* Actions on Objectives
* Delivery
* Exploitation
* Reconnaissance

###### CIS
* CIS 12
* CIS 16
* CIS 3
* CIS 8
* CIS 9

##### NIST
* DE.AE
* DE.CM
* PR.AC
* PR.IP
* PR.PT

##### References
* https://www.splunk.com/en_us/blog/security/detecting-ryuk-using-splunk-attack-range.html
* https://www.crowdstrike.com/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/
* https://us-cert.cisa.gov/ncas/alerts/aa20-302a

### SamSam Ransomware
* id = c4b89506-fbcf-4cb7-bfd6-527e54789604
* date = 2018-12-13
* version = 1

#### Description
Leverage searches that allow you to detect and investigate unusual activities that might relate to the SamSam ransomware, including looking for file writes associated with SamSam, RDP brute force attacks, the presence of files with SamSam ransomware extensions, suspicious psexec use, and more.

#### Narrative
The first version of the SamSam ransomware (a.k.a. Samas or SamsamCrypt) was launched in 2015 by a group of Iranian threat actors. The malicious software has affected and continues to affect thousands of victims and has raised almost $6M in ransom.\
Although categorized under the heading of ransomware, SamSam campaigns have some importance distinguishing characteristics. Most notable is the fact that conventional ransomware is a numbers game. Perpetrators use a "spray-and-pray" approach with phishing campaigns or other mechanisms, charging a small ransom (typically under $1,000). The goal is to find a large number of victims willing to pay these mini-ransoms, adding up to a lucrative payday. They use relatively simple methods for infecting systems.\
SamSam attacks are different beasts. They have become progressively more targeted and skillful than typical ransomware attacks. First, malicious actors break into a victim's network, surveil it, then run the malware manually. The attacks are tailored to cause maximum damage and the threat actors usually demand amounts in the tens of thousands of dollars.\
In a typical attack on one large healthcare organization in 2018, the company ended up paying a ransom of four Bitcoins, then worth $56,707. Reports showed that access to the company's files was restored within two hours of paying the sum.\
According to Sophos, SamSam previously leveraged  RDP to gain access to targeted networks via brute force. SamSam is not spread automatically, like other malware. It requires skill because it forces the attacker to adapt their tactics to the individual environment. Next, the actors escalate their privileges to admin level. They scan the networks for worthy targets, using conventional tools, such as PsExec or PaExec, to deploy/execute, quickly encrypting files.\
This Analytic Story includes searches designed to help detect and investigate signs of the SamSam ransomware, such as the creation of fileswrites to system32, writes with tell-tale extensions, batch files written to system32, and evidence of brute-force attacks via RDP.

#### Detections
* Batch File Write to System32
* Common Ransomware Extensions
* Common Ransomware Notes
* Deleting Shadow Copies
* Detect PsExec With accepteula Flag
* Detect attackers scanning for vulnerable JBoss servers
* Detect malicious requests to exploit JBoss servers
* File with Samsam Extension
* Prohibited Software On Endpoint
* Remote Desktop Network Bruteforce
* Remote Desktop Network Traffic
* Samsam Test File Write
* Spike in File Writes

#### Data Models
* Endpoint
* Network_Traffic
* Web

#### Mappings

##### ATT&CK
* T1021.001
* T1021.002
* T1082
* T1204.002
* T1485
* T1486
* T1490

##### Kill Chain Phases
* Actions on Objectives
* Command and Control
* Delivery
* Installation
* Reconnaissance

###### CIS
* CIS 10
* CIS 12
* CIS 16
* CIS 18
* CIS 2
* CIS 3
* CIS 4
* CIS 8
* CIS 9

##### NIST
* DE.AE
* DE.CM
* ID.AM
* ID.RA
* PR.AC
* PR.DS
* PR.IP
* PR.MA
* PR.PT

##### References
* https://www.crowdstrike.com/blog/an-in-depth-analysis-of-samsam-ransomware-and-boss-spider/
* https://nakedsecurity.sophos.com/2018/07/31/samsam-the-almost-6-million-ransomware/
* https://thehackernews.com/2018/07/samsam-ransomware-attacks.html

### Unusual Processes
* id = f4368e3f-d59f-4192-84f6-748ac5a3ddb6
* date = 2020-02-04
* version = 2

#### Description
Quickly identify systems running new or unusual processes in your environment that could be indicators of suspicious activity. Processes run from unusual locations, those with conspicuously long command lines, and rare executables are all examples of activities that may warrant deeper investigation.

#### Narrative
Being able to profile a host's processes within your environment can help you more quickly identify processes that seem out of place when compared to the rest of the population of hosts or asset types.\
This Analytic Story lets you identify processes that are either a) not typically seen running or b) have some sort of suspicious command-line arguments associated with them. This Analytic Story will also help you identify the user running these processes and the associated process activity on the host.\
In the event an unusual process is identified, it is imperative to better understand how that process was able to execute on the host, when it first executed, and whether other hosts are affected. This extra information may provide clues that can help the analyst further investigate any suspicious activity.

#### Detections
* Detect Rare Executables
* Detect processes used for System Network Configuration Discovery
* RunDLL Loading DLL By Ordinal
* System Processes Run From Unexpected Locations
* Uncommon Processes On Endpoint
* Unusually Long Command Line
* Unusually Long Command Line - MLTK

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK
* T1016
* T1036.003
* T1204.002
* T1218.011

##### Kill Chain Phases
* Actions on Objectives
* Command and Control
* Installation

###### CIS
* CIS 2
* CIS 8

##### NIST
* DE.CM
* ID.AM
* PR.DS
* PR.PT

##### References
* https://www.fireeye.com/blog/threat-research/2017/08/monitoring-windows-console-activity-part-two.html
* https://www.splunk.com/pdfs/technical-briefs/advanced-threat-detection-and-response-tech-brief.pdf
* https://www.sans.org/reading-room/whitepapers/logging/detecting-security-incidents-windows-workstation-event-logs-34262

### Windows File Extension and Association Abuse
* id = 30552a76-ac78-48e4-b3c0-de4e34e9563d
* date = 2018-01-26
* version = 1

#### Description
Detect and investigate suspected abuse of file extensions and Windows file associations. Some of the malicious behaviors involved may include inserting spaces before file extensions or prepending the file extension with a different one, among other techniques.

#### Narrative
Attackers use a variety of techniques to entice users to run malicious code or to persist on an endpoint. One way to accomplish these goals is to leverage file extensions and the mechanism Windows uses to associate files with specific applications. \
 Since its earliest days, Windows has used extensions to identify file types. Users have become familiar with these extensions and their application associations. For example, if users see that a file ends in `.doc` or `.docx`, they will assume that it is a Microsoft Word document and expect that double-clicking will open it using `winword.exe`. The user will typically also presume that the `.docx` file is safe. \
 Attackers take advantage of this expectation by obfuscating the true file extension. They can accomplish this in a couple of ways. One technique involves inserting multiple spaces in the file name before the extension to hide the extension from the GUI, obscuring the true nature of the file. Another approach involves prepending the real extension with a different one. This is especially effective when Windows is configured to "hide extensions for known file types." In this case, the real extension is not displayed, but the prepended one is, leading end users to believe the file is a different type than it actually is.\
Changing the association between a file extension and an application can allow an attacker to execute arbitrary code. The technique typically involves changing the association for an often-launched file type to associate instead with a malicious program the attacker has dropped on the endpoint. When the end user launches a file that has been manipulated in this way, it will execute the attacker's malware. It will also execute the application the end user expected to run, cleverly obscuring the fact that something suspicious has occurred.\
Run the searches in this story to detect and investigate suspicious behavior that may indicate abuse or manipulation of Windows file extensions and/or associations.

#### Detections
* Execution of File With Spaces Before Extension
* Execution of File with Multiple Extensions
* Suspicious Changes to File Associations

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK
* T1036.003
* T1546.001

##### Kill Chain Phases
* Actions on Objectives

###### CIS
* CIS 3
* CIS 8

##### NIST
* DE.CM
* PR.IP
* PR.PT

##### References
* https://blog.malwarebytes.com/cybercrime/2013/12/file-extensions-2/
* https://attack.mitre.org/wiki/Technique/T1042

### Windows Service Abuse
* id = 6dbd810e-f66d-414b-8dfc-e46de55cbfe2
* date = 2017-11-02
* version = 3

#### Description
Windows services are often used by attackers for persistence and the ability to load drivers or otherwise interact with the Windows kernel. This Analytic Story helps you monitor your environment for indications that Windows services are being modified or created in a suspicious manner.

#### Narrative
The Windows operating system uses a services architecture to allow for running code in the background, similar to a UNIX daemon. Attackers will often leverage Windows services for persistence, hiding in plain sight, seeking the ability to run privileged code that can interact with the kernel. In many cases, attackers will create a new service to host their malicious code. Attackers have also been observed modifying unnecessary or unused services to point to their own code, as opposed to what was intended. In these cases, attackers often use tools to create or modify services in ways that are not typical for most environments, providing opportunities for detection.

#### Detections
* First Time Seen Running Windows Service
* Reg exe Manipulating Windows Services Registry Keys
* Sc exe Manipulating Windows Services

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK
* T1543.003
* T1569.002
* T1574.011

##### Kill Chain Phases
* Actions on Objectives
* Installation

###### CIS
* CIS 2
* CIS 3
* CIS 5
* CIS 8
* CIS 9

##### NIST
* DE.AE
* DE.CM
* ID.AM
* PR.AC
* PR.AT
* PR.DS
* PR.IP
* PR.PT

##### References
* https://attack.mitre.org/wiki/Technique/T1050
* https://attack.mitre.org/wiki/Technique/T1031


## Vulnerability

* [Apache Struts Vulnerability](#Apache-Struts-Vulnerability)

* [JBoss Vulnerability](#JBoss-Vulnerability)

* [Spectre And Meltdown Vulnerabilities](#Spectre-And-Meltdown-Vulnerabilities)

* [Splunk Enterprise Vulnerability](#Splunk-Enterprise-Vulnerability)

* [Splunk Enterprise Vulnerability CVE-2018-11409](#Splunk-Enterprise-Vulnerability-CVE-2018-11409)

### Apache Struts Vulnerability
* id = 2dcfd6a2-e7d2-4873-b6ba-adaf819d2a1e
* date = 2018-12-06
* version = 1

#### Description
Detect and investigate activities--such as unusually long `Content-Type` length, suspicious java classes and web servers executing suspicious processes--consistent with attempts to exploit Apache Struts vulnerabilities.

#### Narrative
In March of 2017, a remote code-execution vulnerability in the Jakarta Multipart parser in Apache Struts, a widely used open-source framework for creating Java web applications, was disclosed and assigned to CVE-2017-5638. About two months later, hackers exploited the flaw to carry out the world's <a href=https://www.usatoday.com/story/tech/2017/09/07/nations-biggest-hacks-and-data-breaches-millions/644311001/> 5th largest data breach</a>. The target, credit giant Equifax, <a href=https://money.cnn.com/2017/09/16/technology/equifax-breach-security-hole/index.html>told investigators</a> that it had become aware of the vulnerability two months before the attack. \
The exploit involved manipulating the `Content-Type HTTP` header to execute commands embedded in the header.\
This Analytic Story contains two different searches that help to identify activity that may be related to this issue. The first search looks for characteristics of the `Content-Type` header consistent with attempts to exploit the vulnerability. This should be a relatively pertinent indicator, as the `Content-Type` header is generally consistent and does not have a large degree of variation.\
The second search looks for the execution of various commands typically entered on the command shell when an attacker first lands on a system. These commands are not generally executed on web servers during the course of day-to-day operation, but they may be used when the system is undergoing maintenance or troubleshooting.\
First, it is helpful is to understand how often the notable event is generated, as well as the commonalities in some of these events. This may help determine whether this is a common occurrence that is of a lesser concern or a rare event that may require more extensive investigation. It can also help to understand whether the issue is restricted to a single user or system or is broader in scope.\
When looking at the target of the behavior illustrated by the event, you should note the sensitivity of the user and or/system to help determine the potential impact. It is also helpful to see what other events involving the target have occurred in the recent past. This can help tie different events together and give further situational awareness regarding the target.\
Various types of information for external systems should be reviewed and (potentially) collected if the incident is, indeed, judged to be malicious. Information like this can be useful in generating your own threat intelligence to create alerts in the future.\
Looking at the country, responsible party, and fully qualified domain names associated with the external IP address--as well as the registration information associated with those domain names, if they are frequently visited by others--can help you answer the question of "who," in regard to the external system. Answering that can help qualify the event and may serve useful for tracking. In addition, there are various sources that can provide some reputation information on the IP address or domain name, which can assist in determining if the event is malicious in nature. Finally, determining whether or not there are other events associated with the IP address may help connect some dots or show other events that should be brought into scope.\
Gathering various data elements on the system of interest can sometimes help quickly determine that something suspicious may be happening. Some of these items include determining who else may have recently logged into the system, whether any unusual scheduled tasks exist, whether the system is communicating on suspicious ports, whether there are modifications to sensitive registry keys, and whether there are any known vulnerabilities on the system. This information can often highlight other activity commonly seen in attack scenarios or give more information about how the system may have been targeted.\
hen a specific service or application is targeted, it is often helpful to know the associated version to help determine whether or not it is vulnerable to a specific exploit.\
hen it is suspected there is an attack targeting a web server, it is helpful to look at some of the behavior of the web service to see if there is evidence that the service has been compromised. Some indications of this might be network connections to external resources, the web service spawning child processes that are not associated with typical behavior, and whether the service wrote any files that might be malicious in nature.\
In the event that a suspicious file is found, we can review more information about it to help determine if it is, in fact, malicious. Identifying the file type, any processes that have the file open, what processes created and/or modified the file, and the number of systems that may have this file can help to determine if the file is malicious. Also, determining the file hash and checking it against reputation sources, such as VirusTotal, can sometimes quickly help determine whether it is malicious in nature.\
Often, a simple inspection of a suspect process name and path can tell you if the system has been compromised. For example, if `svchost.exe` is found running from a location other than `C:\Windows\System32`, it is likely something malicious designed to hide in plain sight when simply reviewing process names. Similarly, if the process itself seems legitimate, but the parent process is running from the temporary browser cache, there may be activity initiated via a compromised website the user visited.\
It can also be very helpful to examine various behaviors of the process of interest or the parent of the process that is of interest. For example, if it turns out that the process of interest is malicious, it would be good to see if the parent to that process spawned other processes that might also be worth further scrutiny. If a process is suspect, reviewing the network connections made around the time of the event and/or if the process spawned any child processes could be helpful in determining whether it is malicious or executing a malicious script.

#### Detections
* Suspicious Java Classes
* Unusually Long Content-Type Length
* Web Servers Executing Suspicious Processes

#### Data Models
* Endpoint

#### Mappings

##### ATT&CK
* T1082

##### Kill Chain Phases
* Actions on Objectives
* Delivery
* Exploitation

###### CIS
* CIS 12
* CIS 18
* CIS 3
* CIS 4
* CIS 7

##### NIST
* DE.AE
* DE.CM
* ID.RA
* PR.IP
* PR.MA
* PR.PT
* RS.MI

##### References
* https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.2/dev/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf

### JBoss Vulnerability
* id = 1f5294cb-b85f-4c2d-9c58-ffcf248f52bd
* date = 2017-09-14
* version = 1

#### Description
In March of 2016, adversaries were seen using JexBoss--an open-source utility used for testing and exploiting JBoss application servers. These searches help detect evidence of these attacks, such as network connections to external resources or web services spawning atypical child processes, among others.

#### Narrative
This Analytic Story looks for probing and exploitation attempts targeting JBoss application servers. While the vulnerabilities associated with this story are rather dated, they were leveraged in a spring 2016 campaign in connection with the Samsam ransomware variant. Incidents involving this ransomware are unique, in that they begin with attacks against vulnerable services, rather than the phishing or drive-by attacks more common with ransomware. In this case, vulnerable JBoss applications appear to be the target of choice.\
It is helpful to understand how often a notable event generated by this story occurs, as well as the commonalities between some of these events, both of which may provide clues about whether this is a common occurrence of minimal concern or a rare event that may require more extensive investigation. It may also help to understand whether the issue is restricted to a single user/system or whether it is broader in scope.\
When looking at the target of the behavior uncovered by the event, you should note the sensitivity of the user and or/system to help determine the potential impact. It is also helpful to identify other recent events involving the target. This can help tie different events together and give further situational awareness regarding the target host.\
Various types of information for external systems should be reviewed and, potentially, collected if the incident is, indeed, judged to be malicious. This data may be useful for generating your own threat intelligence, so you can create future alerts.\
The following factors may assist you in determining whether the event is malicious: \
1. Country of origin\
1. Responsible party\
1. Fully qualified domain names associated with the external IP address\
1. Registration of fully qualified domain names associated with external IP address Determining whether it is a dynamic domain frequently visited by others and/or how third parties categorize it can also help you qualify and understand the event and possible motivation for the attack. In addition, there are various sources that may provide reputation information on the IP address or domain name, which can assist you in determining whether the event is malicious in nature. Finally, determining whether there are other events associated with the IP address may help connect data points or expose other historic events that might be brought back into scope.\
Gathering various data on the system of interest can sometimes help quickly determine whether something suspicious is happening. Some of these items include determining who else may have logged into the system recently, whether any unusual scheduled tasks exist, whether the system is communicating on suspicious ports, whether there are modifications to sensitive registry keys, and/or whether there are any known vulnerabilities on the system. This information can often highlight other activity commonly seen in attack scenarios or give more information about how the system may have been targeted.\
hen a specific service or application is targeted, it is often helpful to know the associated version, to help determine whether it is vulnerable to a specific exploit.\
If you suspect an attack targeting a web server, it is helpful to look at some of the behavior of the web service to see if there is evidence that the service has been compromised. Some indications of this might be network connections to external resources, the web service spawning child processes that are not associated with typical behavior, and whether the service wrote any files that might be malicious in nature.\
If a suspicious file is found, we can review more information about it to help determine if it is, in fact, malicious. Identifying the file type, any processes that opened the file, the processes that may have created and/or modified the file, and how many other systems potentially have this file can you determine whether the file is malicious. Also, determining the file hash and checking it against reputation sources, such as VirusTotal, can sometimes help you quickly determine if it is malicious in nature.\
Often, a simple inspection of a suspect process name and path can tell you if the system has been compromised. For example, if svchost.exe is found running from a location other than `C:\Windows\System32`, it is likely something malicious designed to hide in plain sight when simply reviewing process names. \
It can also be helpful to examine various behaviors of and the parent of the process of interest. For example, if it turns out the process of interest is malicious, it would be good to see whether the parent process spawned other processes that might also warrant further scrutiny. If a process is suspect, a review of the network connections made around the time of the event and noting whether the process has spawned any child processes could be helpful in determining whether it is malicious or executing a malicious script.

#### Detections
* Detect attackers scanning for vulnerable JBoss servers
* Detect malicious requests to exploit JBoss servers

#### Data Models
* Web

#### Mappings

##### ATT&CK
* T1082

##### Kill Chain Phases
* Delivery
* Reconnaissance

###### CIS
* CIS 12
* CIS 18
* CIS 4

##### NIST
* DE.AE
* DE.CM
* ID.RA
* PR.IP
* PR.MA
* PR.PT

##### References
* http://www.deependresearch.org/2016/04/jboss-exploits-view-from-victim.html

### Spectre And Meltdown Vulnerabilities
* id = 6d3306f6-bb2b-4219-8609-8efad64032f2
* date = 2018-01-08
* version = 1

#### Description
Assess and mitigate your systems' vulnerability to Spectre and Meltdown exploitation with the searches in this Analytic Story.

#### Narrative
Meltdown and Spectre exploit critical vulnerabilities in modern CPUs that allow unintended access to data in memory. This Analytic Story will help you identify the systems can be patched for these vulnerabilities, as well as those that still need to be patched.

#### Detections
* Spectre and Meltdown Vulnerable Systems

#### Data Models
* Vulnerabilities

#### Mappings

##### ATT&CK

##### Kill Chain Phases

###### CIS
* CIS 4

##### NIST
* DE.CM
* ID.RA
* PR.IP
* RS.MI

##### References
* https://meltdownattack.com/

### Splunk Enterprise Vulnerability
* id = 4e692b96-de2d-4bd1-9105-37e2368a8db1
* date = 2017-09-19
* version = 1

#### Description
Keeping your Splunk deployment up to date is critical and may help you reduce the risk of CVE-2016-4859, an open-redirection vulnerability within some older versions of Splunk Enterprise. The detection search will help ensure that users are being properly authenticated and not being redirected to malicious domains.

#### Narrative
This Analytic Story is associated with CVE-2016-4859, an open-redirect vulnerability in the following versions of Splunk Enterprise:\
\
1. Splunk Enterprise 6.4.x, prior to 6.4.3\
1. Splunk Enterprise 6.3.x, prior to 6.3.6\
1. Splunk Enterprise 6.2.x, prior to 6.2.10\
1. Splunk Enterprise 6.1.x, prior to 6.1.11\
1. Splunk Enterprise 6.0.x, prior to 6.0.12\
1. Splunk Enterprise 5.0.x, prior to 5.0.16\
1. Splunk Light, prior to 6.4.3CVE-2016-4859 allows attackers to redirect users to arbitrary web sites and conduct phishing attacks via unspecified vectors. (Credit: Noriaki Iwasaki, Cyber Defense Institute, Inc.).\
It is important to ensure that your Splunk deployment is being kept up to date and is properly configured. This detection search allows analysts to monitor internal logs to ensure users are properly authenticated and cannot be redirected to any malicious third-party websites.

#### Detections
* Open Redirect in Splunk Web

#### Data Models

#### Mappings

##### ATT&CK

##### Kill Chain Phases
* Delivery

###### CIS
* CIS 18
* CIS 3
* CIS 4

##### NIST
* DE.CM
* ID.RA
* PR.AC
* PR.IP
* PR.PT
* RS.MI

##### References
* http://www.splunk.com/view/SP-CAAAPQ6#announce
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4859

### Splunk Enterprise Vulnerability CVE-2018-11409
* id = 1fc34cbc-34e9-43ba-87ab-6811c9e95400
* date = 2018-06-14
* version = 1

#### Description
Reduce the risk of CVE-2018-11409, an information disclosure vulnerability within some older versions of Splunk Enterprise, with searches designed to help ensure that your Splunk system does not leak information to authenticated users.

#### Narrative
Although there have been no reports of it being exploited, Splunk Enterprise versions through 7.0.1 reportedly have a vulnerability that may expose information through a REST endpoint (read more here: https://www.splunk.com/view/SP-CAAAP5E#VulnerabilityDescriptionsandRatings). NIST has included it in its vulnerability database (read more here: https://nvd.nist.gov/vuln/detail/CVE-2018-11409). The REST endpoint that exposes system information is also necessary for the proper operation of Splunk clustering and instrumentation. Customers should upgrade to the latest version to reduce the risk of this vulnerability.\
Splunk Enterprise exposes partial information about the host operating system, hardware, and Splunk license. Splunk Enterprise before 6.6.0 exposes this information without authentication. Splunk Enterprise 6.6.0 and later exposes this information only to authenticated Splunk users. Based on the information exposure, Splunk characterizes this issue as a low severity impact.\
Read more in Splunk's official response: https://www.splunk.com/view/SP-CAAAP5E#VulnerabilityDescriptionsandRatings.\
A detection search within this Analytic Story looks for vulnerabilities described in CVE-2018-11409: Information Exposure (https://nvd.nist.gov/vuln/detail/CVE-2018-11409). If it turns up activities that may be specific, you can use the included investigative searches to return information regarding web activity and network traffic by src_ip.

#### Detections
* Splunk Enterprise Information Disclosure

#### Data Models

#### Mappings

##### ATT&CK

##### Kill Chain Phases
* Delivery

###### CIS
* CIS 18
* CIS 3
* CIS 4

##### NIST
* DE.CM
* ID.RA
* PR.AC
* PR.IP
* PR.PT
* RS.MI

##### References
* https://nvd.nist.gov/vuln/detail/CVE-2018-11409
* https://www.splunk.com/view/SP-CAAAP5E#VulnerabilityDescriptionsandRatings
* https://www.exploit-db.com/exploits/44865/


