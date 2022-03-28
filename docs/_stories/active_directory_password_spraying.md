---
title: "Active Directory Password Spraying"
last_modified_at: 2021-04-07
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for activities and techniques associated with Password Spraying attacks within Active Directory environments.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-04-07
- **Author**: Mauricio Velazco, Splunk
- **ID**: 3de109da-97d2-11eb-8b6a-acde48001122

#### Narrative

In a password spraying attack, adversaries leverage one or a small list of commonly used / popular passwords against a large volume of usernames to acquire valid account credentials. Unlike a Brute Force attack that targets a specific user or small group of users with a large number of passwords, password spraying follows the opposite aproach and increases the chances of obtaining valid credentials while avoiding account lockouts. This allows adversaries to remain undetected if the target organization does not have the proper monitoring and detection controls in place.\
Password Spraying can be leveraged by adversaries across different stages in an attack. It can be used to obtain an iniial access to an environment but can also be used to escalate privileges when access has been already achieved. In some scenarios, this technique capitalizes on a security policy most organizations implement, password rotation. As enterprise users change their passwords, it is possible some pick predictable, seasonal passwords such as `$CompanyNameWinter`, `Summer2021`, etc.\
Specifically, this Analytic Story is focused on detecting possible Password Spraying attacks against Active Directory environments leveraging Windows Event Logs in the `Account Logon` and `Logon/Logoff` Advanced Audit Policy categories. It presents 9 detection analytics which can aid defenders in identifyng instances where one source user, source host or source process attempts to authenticate against a target or targets using a high, unsual, number of unique users. A user, host or process attempting to authenticate with multiple users is not common behavior for legitimate systems and should be monitored by security teams. Possible false positive scenarios include but are not limited to vulnerability scanners, remote administration tools, multi-user systems and missconfigured systems. These should be easily spotted when first implementing the detection and addded to an allow list or lookup table. The presented detections can also be used in Threat Hunting exercises.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Multiple Invalid Users Failing To Authenticate From Host Using NTLM](/endpoint/multiple_invalid_users_failing_to_authenticate_from_host_using_ntlm/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force)| Anomaly |
| [Multiple Users Failing To Authenticate From Host Using Kerberos](/endpoint/multiple_users_failing_to_authenticate_from_host_using_kerberos/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force)| Anomaly |
| [Multiple Users Failing To Authenticate From Host Using NTLM](/endpoint/multiple_users_failing_to_authenticate_from_host_using_ntlm/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force)| Anomaly |
| [Multiple Users Failing To Authenticate From Process](/endpoint/multiple_users_failing_to_authenticate_from_process/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force)| Anomaly |
| [Multiple Users Remotely Failing To Authenticate From Host](/endpoint/multiple_users_remotely_failing_to_authenticate_from_host/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force)| Anomaly |
| [Windows Disabled Users Failing To Authenticate Kerberos](/endpoint/windows_disabled_users_failing_to_authenticate_kerberos/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force)| Anomaly |
| [Windows Invalid Users Failed Authentication via Kerberos](/endpoint/windows_invalid_users_failed_authentication_via_kerberos/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force)| Anomaly |
| [Windows Users Authenticate Using Explicit Credentials](/endpoint/windows_users_authenticate_using_explicit_credentials/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force)| Anomaly |

#### Reference

* [https://attack.mitre.org/techniques/T1110/003/](https://attack.mitre.org/techniques/T1110/003/)
* [https://www.microsoft.com/security/blog/2020/04/23/protecting-organization-password-spray-attacks/](https://www.microsoft.com/security/blog/2020/04/23/protecting-organization-password-spray-attacks/)
* [https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn452415(v=ws.11)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn452415(v=ws.11))



[*source*](https://github.com/splunk/security_content/tree/develop/stories/active_directory_password_spraying.yml) \| *version*: **1**