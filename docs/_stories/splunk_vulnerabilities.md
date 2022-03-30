---
title: "Splunk Vulnerabilities"
last_modified_at: 2022-03-28
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Delivery
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Keeping your Splunk Enterprise deployment up to date is critical and will help you reduce the risk associated with vulnerabilities in the product.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2022-03-28
- **Author**: Lou Stella, Splunk
- **ID**: 5354df00-dce2-48ac-9a64-8adb48006828

#### Narrative

This analytic story includes detections that focus on attacker behavior targeted at your Splunk environment directly.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Splunk DoS via Malformed S2S Request](/application/splunk_dos_via_malformed_s2s_request/) | [Network Denial of Service](/tags/#network-denial-of-service)| TTP |
| [Open Redirect in Splunk Web](/deprecated/open_redirect_in_splunk_web/) | None| TTP |
| [Splunk Enterprise Information Disclosure](/deprecated/splunk_enterprise_information_disclosure/) | None| TTP |

#### Reference

* [https://www.splunk.com/en_us/product-security/announcements/svd-2022-0301.html](https://www.splunk.com/en_us/product-security/announcements/svd-2022-0301.html)
* [https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3422](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3422)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/splunk_vulnerabilities.yml) \| *version*: **1**