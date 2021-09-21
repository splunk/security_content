---
title: "Data Exfiltration"
last_modified_at: 2020-10-21
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
---

#### Description

The stealing of data by an adversary.

- **ID**: 66b0fe0c-1351-11eb-adc1-0242ac120002
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-10-21
- **Author**: Shannon Davis, Splunk

#### Narrative

Exfiltration comes in many flavors.  Adversaries can collect data over encrypted or non-encrypted channels.  They can utilise Command and Control channels that are already in place to exfiltrate data.  They can use both standard data transfer protocols such as FTP, SCP, etc to exfiltrate data.  Or they can use non-standard protocols such as DNS, ICMP, etc with specially crafted fields to try and circumvent security technologies in place.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [DNS Exfiltration Using Nslookup App](/endpoint/dns_exfiltration_using_nslookup_app/) | None | TTP |
| [Detect SNICat SNI Exfiltration](/network/detect_snicat_sni_exfiltration/) | None | TTP |
| [Detect shared ec2 snapshot](/cloud/detect_shared_ec2_snapshot/) | None | TTP |
| [Excessive Usage of NSLOOKUP App](/endpoint/excessive_usage_of_nslookup_app/) | None | Anomaly |
| [Mailsniper Invoke functions](/endpoint/mailsniper_invoke_functions/) | None | TTP |
| [Multiple Archive Files Http Post Traffic](/network/multiple_archive_files_http_post_traffic/) | None | TTP |
| [O365 PST export alert](/cloud/o365_pst_export_alert/) | None | TTP |
| [O365 Suspicious Admin Email Forwarding](/cloud/o365_suspicious_admin_email_forwarding/) | None | Anomaly |
| [O365 Suspicious User Email Forwarding](/cloud/o365_suspicious_user_email_forwarding/) | None | Anomaly |
| [Plain HTTP POST Exfiltrated Data](/network/plain_http_post_exfiltrated_data/) | None | TTP |

#### Reference

* [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/data_exfiltration.yml) \| *version*: **1**