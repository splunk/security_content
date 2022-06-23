---
title: "Insider Threat"
last_modified_at: 2022-05-19
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Splunk Behavioral Analytics
  - Authentication
  - Endpoint
  - Exploitation
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for activities and techniques associated with insider threats and specifically focusing on malicious insiders operating with in a corporate environment.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud, Splunk Behavioral Analytics
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication), [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-05-19
- **Author**: Jose Hernandez, Splunk
- **ID**: c633df29-a950-4c4c-a0f8-02be6730797c

#### Narrative

Insider Threats are best defined by CISA: "Insider threat incidents are possible in any sector or organization. An insider threat is typically a current or former employee, third-party contractor, or business partner. In their present or former role, the person has or had access to an organization's network systems, data, or premises, and uses their access (sometimes unwittingly). To combat the insider threat, organizations can implement a proactive, prevention-focused mitigation program to detect and identify threats, assess risk, and manage that risk - before an incident occurs." An insider is any person who has or had authorized access to or knowledge of an organization's resources, including personnel, facilities, information, equipment, networks, and systems. These are the common insiders that create insider threats: Departing Employees, Security Evaders, Malicious Insiders, and Negligent Employees. This story aims at detecting the malicious insider.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Gsuite Drive Share In External Email](/cloud/gsuite_drive_share_in_external_email/) | [Exfiltration to Cloud Storage](/tags/#exfiltration-to-cloud-storage), [Exfiltration Over Web Service](/tags/#exfiltration-over-web-service)| Anomaly |
| [Gsuite Outbound Email With Attachment To External Domain](/cloud/gsuite_outbound_email_with_attachment_to_external_domain/) | [Exfiltration Over Unencrypted Non-C2 Protocol](/tags/#exfiltration-over-unencrypted-non-c2-protocol), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol)| Anomaly |
| [High Frequency Copy Of Files In Network Share](/endpoint/high_frequency_copy_of_files_in_network_share/) | [Transfer Data to Cloud Account](/tags/#transfer-data-to-cloud-account)| Anomaly |
| [Multiple Users Failing To Authenticate From Process](/endpoint/multiple_users_failing_to_authenticate_from_process/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force)| Anomaly |
| [Potential password in username](/endpoint/potential_password_in_username/) | [Local Accounts](/tags/#local-accounts), [Credentials In Files](/tags/#credentials-in-files)| Hunting |
| [Windows Users Authenticate Using Explicit Credentials](/endpoint/windows_users_authenticate_using_explicit_credentials/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force)| Anomaly |

#### Reference

* [https://www.imperva.com/learn/application-security/insider-threats/](https://www.imperva.com/learn/application-security/insider-threats/)
* [https://www.cisa.gov/defining-insider-threats](https://www.cisa.gov/defining-insider-threats)
* [https://www.code42.com/glossary/types-of-insider-threats/](https://www.code42.com/glossary/types-of-insider-threats/)
* [https://github.com/Insider-Threat/Insider-Threat](https://github.com/Insider-Threat/Insider-Threat)
* [https://ctid.mitre-engenuity.org/our-work/insider-ttp-kb/](https://ctid.mitre-engenuity.org/our-work/insider-ttp-kb/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/insider_threat.yml) \| *version*: **1**