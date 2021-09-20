---
title: "Collection and Staging"
last_modified_at: 2020-02-03
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
---

#### Description

Monitor for and investigate activities--such as suspicious writes to the Windows Recycling Bin or email servers sending high amounts of traffic to specific hosts, for example--that may indicate that an adversary is harvesting and exfiltrating sensitive data. 

- **ID**: 8e03c61e-13c4-4dcd-bfbe-5ce5a8dc031a
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-02-03
- **Author**: Rico Valdez, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Renamed 7-Zip](/endpoint/detect_renamed_7-zip/) | None | TTP |
| [Detect Renamed WinRAR](/endpoint/detect_renamed_winrar/) | None | TTP |
| [Email files written outside of the Outlook directory](/application/email_files_written_outside_of_the_outlook_directory/) | None | TTP |
| [Email servers sending high volume traffic to hosts](/application/email_servers_sending_high_volume_traffic_to_hosts/) | None | Anomaly |
| [Hosts receiving high volume of network traffic from email server](/network/hosts_receiving_high_volume_of_network_traffic_from_email_server/) | None | Anomaly |
| [Suspicious writes to windows Recycle Bin](/endpoint/suspicious_writes_to_windows_recycle_bin/) | None | TTP |

#### Kill Chain Phase



#### Reference

* [https://attack.mitre.org/wiki/Collection](https://attack.mitre.org/wiki/Collection)
* [https://attack.mitre.org/wiki/Technique/T1074](https://attack.mitre.org/wiki/Technique/T1074)



_version_: 1