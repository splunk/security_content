---
title: "Suspicious Okta Activity"
last_modified_at: 2020-04-02
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

#### Description

Monitor your Okta environment for suspicious activities. Due to the Covid outbreak, many users are migrating over to leverage cloud services more and more. Okta is a popular tool to manage multiple users and the web-based applications they need to stay productive. The searches in this story will help monitor your Okta environment for suspicious activities and associated user behaviors.

- **ID**: 9cbd34af-8f39-4476-a423-bacd126c750b
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-04-02
- **Author**: Rico Valdez, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Multiple Okta Users With Invalid Credentials From The Same IP](/application/multiple_okta_users_with_invalid_credentials_from_the_same_ip/) | None | TTP |
| [Okta Account Lockout Events](/application/okta_account_lockout_events/) | None | Anomaly |
| [Okta Failed SSO Attempts](/application/okta_failed_sso_attempts/) | None | Anomaly |
| [Okta User Logins From Multiple Cities](/application/okta_user_logins_from_multiple_cities/) | None | Anomaly |

#### Reference

* [https://attack.mitre.org/wiki/Technique/T1078](https://attack.mitre.org/wiki/Technique/T1078)
* [https://owasp.org/www-community/attacks/Credential_stuffing](https://owasp.org/www-community/attacks/Credential_stuffing)
* [https://searchsecurity.techtarget.com/answer/What-is-a-password-spraying-attack-and-how-does-it-work](https://searchsecurity.techtarget.com/answer/What-is-a-password-spraying-attack-and-how-does-it-work)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/suspicious_okta_activity.yml) | _version_: **1**