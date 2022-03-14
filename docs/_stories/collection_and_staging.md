---
title: "Collection and Staging"
last_modified_at: 2020-02-03
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
  - Actions on Objectives
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for and investigate activities--such as suspicious writes to the Windows Recycling Bin or email servers sending high amounts of traffic to specific hosts, for example--that may indicate that an adversary is harvesting and exfiltrating sensitive data. 

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-02-03
- **Author**: Rico Valdez, Splunk
- **ID**: 8e03c61e-13c4-4dcd-bfbe-5ce5a8dc031a

#### Narrative

A common adversary goal is to identify and exfiltrate data of value from a target organization. This data may include email conversations and addresses, confidential company information, links to network design/infrastructure, important dates, and so on.\
 Attacks are composed of three activities: identification, collection, and staging data for exfiltration. Identification typically involves scanning systems and observing user activity. Collection can involve the transfer of large amounts of data from various repositories. Staging/preparation includes moving data to a central location and compressing (and optionally encoding and/or encrypting) it. All of these activities provide opportunities for defenders to identify their presence. \
Use the searches to detect and monitor suspicious behavior related to these activities.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Suspicious writes to System Volume Information](/deprecated/suspicious_writes_to_system_volume_information/) | [Masquerading](/tags/#masquerading)| Hunting |
| [Detect Renamed 7-Zip](/endpoint/detect_renamed_7-zip/) | [Archive via Utility](/tags/#archive-via-utility), [Archive Collected Data](/tags/#archive-collected-data)| Hunting |
| [Detect Renamed WinRAR](/endpoint/detect_renamed_winrar/) | [Archive via Utility](/tags/#archive-via-utility), [Archive Collected Data](/tags/#archive-collected-data)| Hunting |
| [Suspicious writes to windows Recycle Bin](/endpoint/suspicious_writes_to_windows_recycle_bin/) | [Masquerading](/tags/#masquerading)| TTP |
| [Email files written outside of the Outlook directory](/application/email_files_written_outside_of_the_outlook_directory/) | [Email Collection](/tags/#email-collection), [Local Email Collection](/tags/#local-email-collection)| TTP |
| [Email servers sending high volume traffic to hosts](/application/email_servers_sending_high_volume_traffic_to_hosts/) | [Email Collection](/tags/#email-collection), [Remote Email Collection](/tags/#remote-email-collection)| Anomaly |
| [Hosts receiving high volume of network traffic from email server](/network/hosts_receiving_high_volume_of_network_traffic_from_email_server/) | [Remote Email Collection](/tags/#remote-email-collection), [Email Collection](/tags/#email-collection)| Anomaly |

#### Reference

* [https://attack.mitre.org/wiki/Collection](https://attack.mitre.org/wiki/Collection)
* [https://attack.mitre.org/wiki/Technique/T1074](https://attack.mitre.org/wiki/Technique/T1074)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/collection_and_staging.yml) \| *version*: **1**