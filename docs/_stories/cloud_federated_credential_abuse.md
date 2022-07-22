---
title: "Cloud Federated Credential Abuse"
last_modified_at: 2021-01-26
toc: true
toc_label: ""
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
  - Command & Control
  - Exploitation
  - Installation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytical story addresses events that indicate abuse of cloud federated credentials. These credentials are usually extracted from endpoint desktop or servers specially those servers that provide federation services such as Windows Active Directory Federation Services. Identity Federation relies on objects such as Oauth2 tokens, cookies or SAML assertions in order to provide seamless access between cloud and perimeter environments. If these objects are either hijacked or forged then attackers will be able to pivot into victim's cloud environements.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-01-26
- **Author**: Rod Soto, Splunk
- **ID**: cecdc1e7-0af2-4a55-8967-b9ea62c0317d

#### Narrative

This story is composed of detection searches based on endpoint that addresses the use of Mimikatz, Escalation of Privileges and Abnormal processes that may indicate the extraction of Federated directory objects such as passwords, Oauth2 tokens, certificates and keys. Cloud environment (AWS, Azure) related events are also addressed in specific cloud environment detection searches.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS SAML Access by Provider User and Principal](/cloud/aws_saml_access_by_provider_user_and_principal/) | [Valid Accounts](/tags/#valid-accounts)| Anomaly |
| [AWS SAML Update identity provider](/cloud/aws_saml_update_identity_provider/) | [Valid Accounts](/tags/#valid-accounts)| TTP |
| [O365 Add App Role Assignment Grant User](/cloud/o365_add_app_role_assignment_grant_user/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account)| TTP |
| [O365 Added Service Principal](/cloud/o365_added_service_principal/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account)| TTP |
| [O365 Excessive SSO logon errors](/cloud/o365_excessive_sso_logon_errors/) | [Modify Authentication Process](/tags/#modify-authentication-process)| Anomaly |
| [O365 New Federated Domain Added](/cloud/o365_new_federated_domain_added/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account)| TTP |
| [Detect Mimikatz Via PowerShell And EventCode 4703](/deprecated/detect_mimikatz_via_powershell_and_eventcode_4703/) | [LSASS Memory](/tags/#lsass-memory)| TTP |
| [Certutil exe certificate extraction](/endpoint/certutil_exe_certificate_extraction/) | None| TTP |
| [Detect Mimikatz Using Loaded Images](/endpoint/detect_mimikatz_using_loaded_images/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping)| TTP |
| [Registry Keys Used For Privilege Escalation](/endpoint/registry_keys_used_for_privilege_escalation/) | [Image File Execution Options Injection](/tags/#image-file-execution-options-injection), [Event Triggered Execution](/tags/#event-triggered-execution)| TTP |
| [Detect Rare Executables](/endpoint/detect_rare_executables/) | None| Anomaly |

#### Reference

* [https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps](https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps)
* [https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf)
* [https://us-cert.cisa.gov/ncas/alerts/aa21-008a](https://us-cert.cisa.gov/ncas/alerts/aa21-008a)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/cloud_federated_credential_abuse.yml) \| *version*: **1**