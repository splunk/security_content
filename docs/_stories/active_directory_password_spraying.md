---
title: "Active Directory Password Spraying"
last_modified_at: 2021-04-07
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Monitor for activities and techniques associated with Password Spraying attacks within Active Directory environments.

- **ID**: 3de109da-97d2-11eb-8b6a-acde48001122
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-07
- **Author**: Mauricio Velazco, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Multiple Disabled Users Failing To Authenticate From Host Using Kerberos](/endpoint/multiple_disabled_users_failing_to_authenticate_from_host_using_kerberos/) | None | Anomaly |
| [Multiple Invalid Users Failing To Authenticate From Host Using Kerberos](/endpoint/multiple_invalid_users_failing_to_authenticate_from_host_using_kerberos/) | None | Anomaly |
| [Multiple Invalid Users Failing To Authenticate From Host Using NTLM](/endpoint/multiple_invalid_users_failing_to_authenticate_from_host_using_ntlm/) | None | Anomaly |
| [Multiple Users Attempting To Authenticate Using Explicit Credentials](/endpoint/multiple_users_attempting_to_authenticate_using_explicit_credentials/) | None | Anomaly |
| [Multiple Users Failing To Authenticate From Host Using Kerberos](/endpoint/multiple_users_failing_to_authenticate_from_host_using_kerberos/) | None | Anomaly |
| [Multiple Users Failing To Authenticate From Host Using NTLM](/endpoint/multiple_users_failing_to_authenticate_from_host_using_ntlm/) | None | Anomaly |
| [Multiple Users Failing To Authenticate From Process](/endpoint/multiple_users_failing_to_authenticate_from_process/) | None | Anomaly |
| [Multiple Users Remotely Failing To Authenticate From Host](/endpoint/multiple_users_remotely_failing_to_authenticate_from_host/) | None | Anomaly |

#### Reference

* [https://attack.mitre.org/techniques/T1110/003/](https://attack.mitre.org/techniques/T1110/003/)
* [https://www.microsoft.com/security/blog/2020/04/23/protecting-organization-password-spray-attacks/](https://www.microsoft.com/security/blog/2020/04/23/protecting-organization-password-spray-attacks/)
* [https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn452415(v=ws.11)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn452415(v=ws.11))



[_source_](https://github.com/splunk/security_content/tree/develop/stories/active_directory_password_spraying.yml) | _version_: **1**