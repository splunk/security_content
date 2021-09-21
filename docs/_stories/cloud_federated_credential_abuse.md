---
title: "Cloud Federated Credential Abuse"
last_modified_at: 2021-01-26
toc: true
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

This analytical story addresses events that indicate abuse of cloud federated credentials. These credentials are usually extracted from endpoint desktop or servers specially those servers that provide federation services such as Windows Active Directory Federation Services. Identity Federation relies on objects such as Oauth2 tokens, cookies or SAML assertions in order to provide seamless access between cloud and perimeter environments. If these objects are either hijacked or forged then attackers will be able to pivot into victim's cloud environements.

- **ID**: cecdc1e7-0af2-4a55-8967-b9ea62c0317d
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-01-26
- **Author**: Rod Soto, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS SAML Access by Provider User and Principal](/cloud/aws_saml_access_by_provider_user_and_principal/) | None | Anomaly |
| [AWS SAML Update identity provider](/cloud/aws_saml_update_identity_provider/) | None | TTP |
| [Certutil exe certificate extraction](/endpoint/certutil_exe_certificate_extraction/) | None | TTP |
| [Detect Mimikatz Using Loaded Images](/endpoint/detect_mimikatz_using_loaded_images/) | None | TTP |
| [Detect Rare Executables](/endpoint/detect_rare_executables/) | None | Anomaly |
| [O365 Add App Role Assignment Grant User](/cloud/o365_add_app_role_assignment_grant_user/) | None | TTP |
| [O365 Added Service Principal](/cloud/o365_added_service_principal/) | None | TTP |
| [O365 Excessive SSO logon errors](/cloud/o365_excessive_sso_logon_errors/) | None | Anomaly |
| [O365 New Federated Domain Added](/cloud/o365_new_federated_domain_added/) | None | TTP |
| [Registry Keys Used For Privilege Escalation](/endpoint/registry_keys_used_for_privilege_escalation/) | None | TTP |

#### Reference

* [https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps](https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps)
* [https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf)
* [https://us-cert.cisa.gov/ncas/alerts/aa21-008a](https://us-cert.cisa.gov/ncas/alerts/aa21-008a)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/cloud_federated_credential_abuse.yml) \| *version*: **1**