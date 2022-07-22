---
title: "VMware Server Side Injection and Privilege Escalation"
last_modified_at: 2022-05-19
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Web
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Recently disclosed CVE-2022-22954 and CVE-2022-22960 have been identified in the wild abusing VMware products to compromise internet faced devices and escalate privileges.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2022-05-19
- **Author**: Michael Haag, Splunk
- **ID**: d6d51cc2-a092-43b7-9f61-1159943afe39

#### Narrative

On April 6, 2022, VMware published VMSA-2022-0011, which discloses multiple vulnerabilities discovered by Steven Seeley (mr_me) of Qihoo 360 Vulnerability Research Institute. The most critical of the CVEs published in VMSA-2022-0011 is CVE-2022-22954, which is a server-side template injection issue with a CVSSv3 base score of 9.8. The vulnerability allows an unauthenticated user with network access to the web interface to execute an arbitrary shell command as the VMware user. To further exacerbate this issue, VMware also disclosed a local privilege escalation issue, CVE-2022-22960, which permits the attacker to gain root after exploiting CVE-2022-22954. Products affected include - VMware Workspace ONE Access (Access) 20.10.0.0 - 20.10.0.1, 21.08.0.0 - 21.08.0.1 and VMware Identity Manager (vIDM) 3.3.3 - 3.3.6.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [VMware Server Side Template Injection Hunt](/web/vmware_server_side_template_injection_hunt/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application)| Hunting |
| [VMware Workspace ONE Freemarker Server-side Template Injection](/web/vmware_workspace_one_freemarker_server-side_template_injection/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application)| Anomaly |

#### Reference

* [https://attackerkb.com/topics/BDXyTqY1ld/cve-2022-22954/rapid7-analysis](https://attackerkb.com/topics/BDXyTqY1ld/cve-2022-22954/rapid7-analysis)
* [https://www.cisa.gov/uscert/ncas/alerts/aa22-138b](https://www.cisa.gov/uscert/ncas/alerts/aa22-138b)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/vmware_server_side_injection_and_privilege_escalation.yml) \| *version*: **1**