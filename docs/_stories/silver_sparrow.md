---
title: "Silver Sparrow"
last_modified_at: 2021-02-24
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Silver Sparrow, identified by Red Canary Intelligence, is a new forward looking MacOS (Intel and M1) malicious software downloader utilizing JavaScript for execution and a launchAgent to establish persistence.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-02-24
- **Author**: Michael Haag, Splunk
- **ID**: cb4f48fe-7699-11eb-af77-acde48001122

#### Narrative

Silver Sparrow works is a dropper and uses typical persistence mechanisms on a Mac. It is cross platform, covering both Intel and Apple M1 architecture. To this date, no implant has been downloaded for malicious purposes. During installation of the update.pkg or updater.pkg file, the malicious software utilizes JavaScript to generate files and scripts on disk for persistence.These files later download a implant from an S3 bucket every hour. This analytic assists with identifying different types of macOS malware families establishing LaunchAgent persistence. Per SentinelOne source, it is predicted that Silver Sparrow is likely selling itself as a mechanism to 3rd party Caffiliates or pay-per-install (PPI) partners, typically seen as commodity adware/malware. Additional indicators and behaviors may be found within the references.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Suspicious Curl Network Connection](/endpoint/suspicious_curl_network_connection/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| TTP |
| [Suspicious PlistBuddy Usage](/endpoint/suspicious_plistbuddy_usage/) | [Launch Agent](/tags/#launch-agent), [Create or Modify System Process](/tags/#create-or-modify-system-process)| TTP |
| [Suspicious PlistBuddy Usage via OSquery](/endpoint/suspicious_plistbuddy_usage_via_osquery/) | [Launch Agent](/tags/#launch-agent), [Create or Modify System Process](/tags/#create-or-modify-system-process)| TTP |
| [Suspicious SQLite3 LSQuarantine Behavior](/endpoint/suspicious_sqlite3_lsquarantine_behavior/) | [Data Staged](/tags/#data-staged)| TTP |

#### Reference

* [https://redcanary.com/blog/clipping-silver-sparrows-wings/](https://redcanary.com/blog/clipping-silver-sparrows-wings/)
* [https://www.sentinelone.com/blog/5-things-you-need-to-know-about-silver-sparrow/](https://www.sentinelone.com/blog/5-things-you-need-to-know-about-silver-sparrow/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/silver_sparrow.yml) \| *version*: **1**