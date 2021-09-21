---
title: "SamSam Ransomware"
last_modified_at: 2018-12-13
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
  - Web
---

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the SamSam ransomware, including looking for file writes associated with SamSam, RDP brute force attacks, the presence of files with SamSam ransomware extensions, suspicious psexec use, and more.

- **ID**: c4b89506-fbcf-4cb7-bfd6-527e54789604
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic), [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2018-12-13
- **Author**: Rico Valdez, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Attacker Tools On Endpoint](/endpoint/attacker_tools_on_endpoint/) | None | TTP |
| [Batch File Write to System32](/endpoint/batch_file_write_to_system32/) | None | TTP |
| [Common Ransomware Extensions](/endpoint/common_ransomware_extensions/) | None | Hunting |
| [Common Ransomware Notes](/endpoint/common_ransomware_notes/) | None | Hunting |
| [Deleting Shadow Copies](/endpoint/deleting_shadow_copies/) | None | TTP |
| [Detect PsExec With accepteula Flag](/endpoint/detect_psexec_with_accepteula_flag/) | None | TTP |
| [Detect Renamed PSExec](/endpoint/detect_renamed_psexec/) | None | TTP |
| [Detect attackers scanning for vulnerable JBoss servers](/web/detect_attackers_scanning_for_vulnerable_jboss_servers/) | None | TTP |
| [Detect malicious requests to exploit JBoss servers](/web/detect_malicious_requests_to_exploit_jboss_servers/) | None | TTP |
| [File with Samsam Extension](/endpoint/file_with_samsam_extension/) | None | TTP |
| [Remote Desktop Network Bruteforce](/network/remote_desktop_network_bruteforce/) | None | TTP |
| [Remote Desktop Network Traffic](/network/remote_desktop_network_traffic/) | None | Anomaly |
| [Samsam Test File Write](/endpoint/samsam_test_file_write/) | None | TTP |
| [Spike in File Writes](/endpoint/spike_in_file_writes/) | None | Anomaly |

#### Reference

* [https://www.crowdstrike.com/blog/an-in-depth-analysis-of-samsam-ransomware-and-boss-spider/](https://www.crowdstrike.com/blog/an-in-depth-analysis-of-samsam-ransomware-and-boss-spider/)
* [https://nakedsecurity.sophos.com/2018/07/31/samsam-the-almost-6-million-ransomware/](https://nakedsecurity.sophos.com/2018/07/31/samsam-the-almost-6-million-ransomware/)
* [https://thehackernews.com/2018/07/samsam-ransomware-attacks.html](https://thehackernews.com/2018/07/samsam-ransomware-attacks.html)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/samsam_ransomware.yml) | _version_: **1**