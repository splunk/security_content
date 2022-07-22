---
title: "Office 365 Detections"
last_modified_at: 2020-12-16
toc: true
toc_label: ""
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This story is focused around detecting Office 365 Attacks.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-12-16
- **Author**: Patrick Bareiss, Splunk
- **ID**: 1a51dd71-effc-48b2-abc4-3e9cdb61e5b9

#### Narrative

More and more companies are using Microsofts Office 365 cloud offering. Therefore, we see more and more attacks against Office 365. This story provides various detections for Office 365 attacks.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [O365 Add App Role Assignment Grant User](/cloud/o365_add_app_role_assignment_grant_user/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account)| TTP |
| [O365 Added Service Principal](/cloud/o365_added_service_principal/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account)| TTP |
| [O365 Bypass MFA via Trusted IP](/cloud/o365_bypass_mfa_via_trusted_ip/) | [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [O365 Disable MFA](/cloud/o365_disable_mfa/) | [Modify Authentication Process](/tags/#modify-authentication-process)| TTP |
| [O365 Excessive Authentication Failures Alert](/cloud/o365_excessive_authentication_failures_alert/) | [Brute Force](/tags/#brute-force)| Anomaly |
| [O365 Excessive SSO logon errors](/cloud/o365_excessive_sso_logon_errors/) | [Modify Authentication Process](/tags/#modify-authentication-process)| Anomaly |
| [O365 New Federated Domain Added](/cloud/o365_new_federated_domain_added/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account)| TTP |
| [O365 PST export alert](/cloud/o365_pst_export_alert/) | [Email Collection](/tags/#email-collection)| TTP |
| [O365 Suspicious Admin Email Forwarding](/cloud/o365_suspicious_admin_email_forwarding/) | [Email Forwarding Rule](/tags/#email-forwarding-rule), [Email Collection](/tags/#email-collection)| Anomaly |
| [O365 Suspicious Rights Delegation](/cloud/o365_suspicious_rights_delegation/) | [Remote Email Collection](/tags/#remote-email-collection), [Email Collection](/tags/#email-collection)| TTP |
| [O365 Suspicious User Email Forwarding](/cloud/o365_suspicious_user_email_forwarding/) | [Email Forwarding Rule](/tags/#email-forwarding-rule), [Email Collection](/tags/#email-collection)| Anomaly |
| [High Number of Login Failures from a single source](/cloud/high_number_of_login_failures_from_a_single_source/) | [Password Guessing](/tags/#password-guessing), [Brute Force](/tags/#brute-force)| Anomaly |

#### Reference

* [https://i.blackhat.com/USA-20/Thursday/us-20-Bienstock-My-Cloud-Is-APTs-Cloud-Investigating-And-Defending-Office-365.pdf](https://i.blackhat.com/USA-20/Thursday/us-20-Bienstock-My-Cloud-Is-APTs-Cloud-Investigating-And-Defending-Office-365.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/office_365_detections.yml) \| *version*: **1**