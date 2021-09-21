---
title: "Silver Sparrow"
last_modified_at: 2021-02-24
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Silver Sparrow, identified by Red Canary Intelligence, is a new forward looking MacOS (Intel and M1) malicious software downloader utilizing JavaScript for execution and a launchAgent to establish persistence.

- **ID**: cb4f48fe-7699-11eb-af77-acde48001122
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-02-24
- **Author**: Michael Haag, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Suspicious Curl Network Connection](/endpoint/suspicious_curl_network_connection/) | None | TTP |
| [Suspicious PlistBuddy Usage](/endpoint/suspicious_plistbuddy_usage/) | None | TTP |
| [Suspicious PlistBuddy Usage via OSquery](/endpoint/suspicious_plistbuddy_usage_via_osquery/) | None | TTP |
| [Suspicious SQLite3 LSQuarantine Behavior](/endpoint/suspicious_sqlite3_lsquarantine_behavior/) | None | TTP |

#### Reference

* [https://redcanary.com/blog/clipping-silver-sparrows-wings/](https://redcanary.com/blog/clipping-silver-sparrows-wings/)
* [https://www.sentinelone.com/blog/5-things-you-need-to-know-about-silver-sparrow/](https://www.sentinelone.com/blog/5-things-you-need-to-know-about-silver-sparrow/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/silver_sparrow.yml) \| *version*: **1**