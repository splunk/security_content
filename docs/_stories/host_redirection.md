---
title: "Host Redirection"
last_modified_at: 2017-09-14
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Resolution
  - Command & Control
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect evidence of tactics used to redirect traffic from a host to a destination other than the one intended--potentially one that is part of an adversary's attack infrastructure. An example is redirecting communications regarding patches and updates or misleading users into visiting a malicious website.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2017-09-14
- **Author**: Rico Valdez, Splunk
- **ID**: 2e8948a5-5239-406b-b56b-6c50fe268af4

#### Narrative

Attackers will often attempt to manipulate client communications for nefarious purposes. In some cases, an attacker may endeavor to modify a local host file to redirect communications with resources (such as antivirus or system-update services) to prevent clients from receiving patches or updates. In other cases, an attacker might use this tactic to have the client connect to a site that looks like the intended site, but instead installs malware or collects information from the victim. Additionally, an attacker may redirect a victim in order to execute a MITM attack and observe communications.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Clients Connecting to Multiple DNS Servers](/deprecated/clients_connecting_to_multiple_dns_servers/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol)| TTP |
| [DNS Query Requests Resolved by Unauthorized DNS Servers](/deprecated/dns_query_requests_resolved_by_unauthorized_dns_servers/) | [DNS](/tags/#dns)| TTP |
| [Windows hosts file modification](/deprecated/windows_hosts_file_modification/) | None| TTP |

#### Reference

* [https://blog.malwarebytes.com/cybercrime/2016/09/hosts-file-hijacks/](https://blog.malwarebytes.com/cybercrime/2016/09/hosts-file-hijacks/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/host_redirection.yml) \| *version*: **1**