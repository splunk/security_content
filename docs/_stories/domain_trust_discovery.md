---
title: "Domain Trust Discovery"
last_modified_at: 2021-03-25
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities in Windows multi-domain/forest environments.

- **ID**: e6f30f14-8daf-11eb-a017-acde48001122
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-25
- **Author**: Michael Haag, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [DSQuery Domain Discovery](/endpoint/dsquery_domain_discovery/) | None | TTP |
| [NLTest Domain Trust Discovery](/endpoint/nltest_domain_trust_discovery/) | None | TTP |
| [Windows AdFind Exe](/endpoint/windows_adfind_exe/) | None | TTP |

#### Kill Chain Phase



#### Reference

* [https://attack.mitre.org/techniques/T1482/](https://attack.mitre.org/techniques/T1482/)



_version_: 1