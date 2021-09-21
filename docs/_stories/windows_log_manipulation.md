---
title: "Windows Log Manipulation"
last_modified_at: 2017-09-12
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Adversaries often try to cover their tracks by manipulating Windows logs. Use these searches to help you monitor for suspicious activity surrounding log files--an essential component of an effective defense.

- **ID**: b6db2c60-a281-48b4-95f1-2cd99ed56835
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2017-09-12
- **Author**: Rico Valdez, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Deleting Shadow Copies](/endpoint/deleting_shadow_copies/) | None | TTP |
| [Illegal Deletion of Logs via Mimikatz modules](/endpoint/illegal_deletion_of_logs_via_mimikatz_modules/) | None | TTP |
| [Suspicious Event Log Service Behavior](/endpoint/suspicious_event_log_service_behavior/) | None | TTP |
| [Suspicious wevtutil Usage](/endpoint/suspicious_wevtutil_usage/) | None | TTP |
| [USN Journal Deletion](/endpoint/usn_journal_deletion/) | None | TTP |
| [WevtUtil Usage To Clear Logs](/endpoint/wevtutil_usage_to_clear_logs/) | None | TTP |
| [Wevtutil Usage To Disable Logs](/endpoint/wevtutil_usage_to_disable_logs/) | None | TTP |
| [Windows Event Log Cleared](/endpoint/windows_event_log_cleared/) | None | TTP |

#### Reference

* [https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/)
* [https://zeltser.com/security-incident-log-review-checklist/](https://zeltser.com/security-incident-log-review-checklist/)
* [http://journeyintoir.blogspot.com/2013/01/re-introducing-usnjrnl.html](http://journeyintoir.blogspot.com/2013/01/re-introducing-usnjrnl.html)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/windows_log_manipulation.yml) | _version_: **2**