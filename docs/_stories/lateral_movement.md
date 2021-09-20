---
title: "Lateral Movement"
last_modified_at: 2020-02-04
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
---

#### Description

Detect and investigate tactics, techniques, and procedures around how attackers move laterally within the enterprise. Because lateral movement can expose the adversary to detection, it should be an important focus for security analysts.

- **ID**: 399d65dc-1f08-499b-a259-aad9051f38ad
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-02-04
- **Author**: David Dorsey, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Activity Related to Pass the Hash Attacks](/endpoint/detect_activity_related_to_pass_the_hash_attacks/) | None | TTP |
| [Detect Pass the Hash](/endpoint/detect_pass_the_hash/) | None | TTP |
| [Detect PsExec With accepteula Flag](/endpoint/detect_psexec_with_accepteula_flag/) | None | TTP |
| [Detect Renamed PSExec](/endpoint/detect_renamed_psexec/) | None | TTP |
| [Kerberoasting spn request with RC4 encryption](/endpoint/kerberoasting_spn_request_with_rc4_encryption/) | None | TTP |
| [Remote Desktop Network Traffic](/network/remote_desktop_network_traffic/) | None | Anomaly |
| [Remote Desktop Process Running On System](/endpoint/remote_desktop_process_running_on_system/) | None | Hunting |
| [Schtasks scheduling job on remote system](/endpoint/schtasks_scheduling_job_on_remote_system/) | None | TTP |

#### Kill Chain Phase



#### Reference

* [https://www.fireeye.com/blog/executive-perspective/2015/08/malware_lateral_move.html](https://www.fireeye.com/blog/executive-perspective/2015/08/malware_lateral_move.html)



_version_: 2