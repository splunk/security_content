---
title: "Lateral Movement"
last_modified_at: 2020-02-04
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect and investigate tactics, techniques, and procedures around how attackers move laterally within the enterprise. Because lateral movement can expose the adversary to detection, it should be an important focus for security analysts.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-02-04
- **Author**: David Dorsey, Splunk
- **ID**: 399d65dc-1f08-499b-a259-aad9051f38ad

#### Narrative

Once attackers gain a foothold within an enterprise, they will seek to expand their accesses and leverage techniques that facilitate lateral movement. Attackers will often spend quite a bit of time and effort moving laterally. Because lateral movement renders an attacker the most vulnerable to detection, it's an excellent focus for detection and investigation.\
Indications of lateral movement can include the abuse of system utilities (such as `psexec.exe`), unauthorized use of remote desktop services, `file/admin$` shares, WMI, PowerShell, pass-the-hash, or the abuse of scheduled tasks. Organizations must be extra vigilant in detecting lateral movement techniques and look for suspicious activity in and around high-value strategic network assets, such as Active Directory, which are often considered the primary target or "crown jewels" to a persistent threat actor.\
An adversary can use lateral movement for multiple purposes, including remote execution of tools, pivoting to additional systems, obtaining access to specific information or files, access to additional credentials, exfiltrating data, or delivering a secondary effect. Adversaries may use legitimate credentials alongside inherent network and operating-system functionality to remotely connect to other systems and remain under the radar of network defenders.\
If there is evidence of lateral movement, it is imperative for analysts to collect evidence of the associated offending hosts. For example, an attacker might leverage host A to gain access to host B. From there, the attacker may try to move laterally to host C. In this example, the analyst should gather as much information as possible from all three hosts. \
 It is also important to collect authentication logs for each host, to ensure that the offending accounts are well-documented. Analysts should account for all processes to ensure that the attackers did not install unauthorized software.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Activity Related to Pass the Hash Attacks](/endpoint/detect_activity_related_to_pass_the_hash_attacks/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material), [Pass the Hash](/tags/#pass-the-hash) | TTP |
| [Detect Pass the Hash](/endpoint/detect_pass_the_hash/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material), [Pass the Hash](/tags/#pass-the-hash) | TTP |
| [Detect PsExec With accepteula Flag](/endpoint/detect_psexec_with_accepteula_flag/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | TTP |
| [Detect Renamed PSExec](/endpoint/detect_renamed_psexec/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | Hunting |
| [Kerberoasting spn request with RC4 encryption](/endpoint/kerberoasting_spn_request_with_rc4_encryption/) | [Kerberoasting](/tags/#kerberoasting), [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets) | TTP |
| [Potential Pass the Token or Hash Observed at the Destination Device](/endpoint/potential_pass_the_token_or_hash_observed_at_the_destination_device/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material), [Pass the Hash](/tags/#pass-the-hash) | TTP |
| [Potential Pass the Token or Hash Observed by an Event Collecting Device](/endpoint/potential_pass_the_token_or_hash_observed_by_an_event_collecting_device/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material), [Pass the Hash](/tags/#pass-the-hash) | TTP |
| [Remote Desktop Network Traffic](/network/remote_desktop_network_traffic/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services) | Anomaly |
| [Remote Desktop Process Running On System](/endpoint/remote_desktop_process_running_on_system/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services) | Hunting |
| [Schtasks scheduling job on remote system](/endpoint/schtasks_scheduling_job_on_remote_system/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | TTP |
| [ServicePrincipalNames Discovery with PowerShell](/endpoint/serviceprincipalnames_discovery_with_powershell/) | [Kerberoasting](/tags/#kerberoasting) | TTP |
| [ServicePrincipalNames Discovery with SetSPN](/endpoint/serviceprincipalnames_discovery_with_setspn/) | [Kerberoasting](/tags/#kerberoasting) | TTP |

#### Reference

* [https://www.fireeye.com/blog/executive-perspective/2015/08/malware_lateral_move.html](https://www.fireeye.com/blog/executive-perspective/2015/08/malware_lateral_move.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/lateral_movement.yml) \| *version*: **2**