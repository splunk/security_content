---
title: "SamSam Ransomware"
last_modified_at: 2018-12-13
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
  - Web
  - Actions on Objectives
  - Command & Control
  - Delivery
  - Exploitation
  - Installation
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the SamSam ransomware, including looking for file writes associated with SamSam, RDP brute force attacks, the presence of files with SamSam ransomware extensions, suspicious psexec use, and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic), [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2018-12-13
- **Author**: Rico Valdez, Splunk
- **ID**: c4b89506-fbcf-4cb7-bfd6-527e54789604

#### Narrative

The first version of the SamSam ransomware (a.k.a. Samas or SamsamCrypt) was launched in 2015 by a group of Iranian threat actors. The malicious software has affected and continues to affect thousands of victims and has raised almost $6M in ransom.\
Although categorized under the heading of ransomware, SamSam campaigns have some importance distinguishing characteristics. Most notable is the fact that conventional ransomware is a numbers game. Perpetrators use a "spray-and-pray" approach with phishing campaigns or other mechanisms, charging a small ransom (typically under $1,000). The goal is to find a large number of victims willing to pay these mini-ransoms, adding up to a lucrative payday. They use relatively simple methods for infecting systems.\
SamSam attacks are different beasts. They have become progressively more targeted and skillful than typical ransomware attacks. First, malicious actors break into a victim's network, surveil it, then run the malware manually. The attacks are tailored to cause maximum damage and the threat actors usually demand amounts in the tens of thousands of dollars.\
In a typical attack on one large healthcare organization in 2018, the company ended up paying a ransom of four Bitcoins, then worth $56,707. Reports showed that access to the company's files was restored within two hours of paying the sum.\
According to Sophos, SamSam previously leveraged  RDP to gain access to targeted networks via brute force. SamSam is not spread automatically, like other malware. It requires skill because it forces the attacker to adapt their tactics to the individual environment. Next, the actors escalate their privileges to admin level. They scan the networks for worthy targets, using conventional tools, such as PsExec or PaExec, to deploy/execute, quickly encrypting files.\
This Analytic Story includes searches designed to help detect and investigate signs of the SamSam ransomware, such as the creation of fileswrites to system32, writes with tell-tale extensions, batch files written to system32, and evidence of brute-force attacks via RDP.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Prohibited Software On Endpoint](/deprecated/prohibited_software_on_endpoint/) | None| Hunting |
| [Attacker Tools On Endpoint](/endpoint/attacker_tools_on_endpoint/) | [Match Legitimate Name or Location](/tags/#match-legitimate-name-or-location), [Masquerading](/tags/#masquerading), [OS Credential Dumping](/tags/#os-credential-dumping), [Active Scanning](/tags/#active-scanning)| TTP |
| [Batch File Write to System32](/endpoint/batch_file_write_to_system32/) | [User Execution](/tags/#user-execution), [Malicious File](/tags/#malicious-file)| TTP |
| [Common Ransomware Extensions](/endpoint/common_ransomware_extensions/) | [Data Destruction](/tags/#data-destruction)| Hunting |
| [Common Ransomware Notes](/endpoint/common_ransomware_notes/) | [Data Destruction](/tags/#data-destruction)| Hunting |
| [Deleting Shadow Copies](/endpoint/deleting_shadow_copies/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery)| TTP |
| [Detect PsExec With accepteula Flag](/endpoint/detect_psexec_with_accepteula_flag/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares)| TTP |
| [Detect Renamed PSExec](/endpoint/detect_renamed_psexec/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution)| Hunting |
| [File with Samsam Extension](/endpoint/file_with_samsam_extension/) | None| TTP |
| [Samsam Test File Write](/endpoint/samsam_test_file_write/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact)| TTP |
| [Spike in File Writes](/endpoint/spike_in_file_writes/) | None| Anomaly |
| [Remote Desktop Network Bruteforce](/network/remote_desktop_network_bruteforce/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services)| TTP |
| [Remote Desktop Network Traffic](/network/remote_desktop_network_traffic/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services)| Anomaly |
| [Detect attackers scanning for vulnerable JBoss servers](/web/detect_attackers_scanning_for_vulnerable_jboss_servers/) | [System Information Discovery](/tags/#system-information-discovery)| TTP |
| [Detect malicious requests to exploit JBoss servers](/web/detect_malicious_requests_to_exploit_jboss_servers/) | None| TTP |

#### Reference

* [https://www.crowdstrike.com/blog/an-in-depth-analysis-of-samsam-ransomware-and-boss-spider/](https://www.crowdstrike.com/blog/an-in-depth-analysis-of-samsam-ransomware-and-boss-spider/)
* [https://nakedsecurity.sophos.com/2018/07/31/samsam-the-almost-6-million-ransomware/](https://nakedsecurity.sophos.com/2018/07/31/samsam-the-almost-6-million-ransomware/)
* [https://thehackernews.com/2018/07/samsam-ransomware-attacks.html](https://thehackernews.com/2018/07/samsam-ransomware-attacks.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/samsam_ransomware.yml) \| *version*: **1**