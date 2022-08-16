---
title: "Splunk Vulnerabilities"
last_modified_at: 2022-03-28
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Splunk_Audit
  - Actions on Objectives
  - Delivery
  - Exploitation
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Keeping your Splunk Enterprise deployment up to date is critical and will help you reduce the risk associated with vulnerabilities in the product.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Splunk_Audit](https://docs.splunk.com/Documentation/CIM/latest/User/SplunkAudit)
- **Last Updated**: 2022-03-28
- **Author**: Lou Stella, Splunk
- **ID**: 5354df00-dce2-48ac-9a64-8adb48006828

#### Narrative

This analytic story includes detections that focus on attacker behavior targeted at your Splunk environment directly.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Risky SPL using Pretrained ML Model](/application/detect_risky_spl_using_pretrained_ml_model/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| Anomaly |
| [Path traversal SPL injection](/application/path_traversal_spl_injection/) | [File and Directory Discovery](/tags/#file-and-directory-discovery)| TTP |
| [Splunk Command and Scripting Interpreter Delete Usage](/application/splunk_command_and_scripting_interpreter_delete_usage/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| Anomaly |
| [Splunk Command and Scripting Interpreter Risky Commands](/application/splunk_command_and_scripting_interpreter_risky_commands/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| Hunting |
| [Splunk Command and Scripting Interpreter Risky SPL MLTK](/application/splunk_command_and_scripting_interpreter_risky_spl_mltk/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| Anomaly |
| [Splunk Digital Certificates Infrastructure Version](/application/splunk_digital_certificates_infrastructure_version/) | [Digital Certificates](/tags/#digital-certificates)| Hunting |
| [Splunk Digital Certificates Lack of Encryption](/application/splunk_digital_certificates_lack_of_encryption/) | [Digital Certificates](/tags/#digital-certificates)| Anomaly |
| [Splunk DoS via Malformed S2S Request](/application/splunk_dos_via_malformed_s2s_request/) | [Network Denial of Service](/tags/#network-denial-of-service)| TTP |
| [Splunk Endpoint Denial of Service DoS Zip Bomb](/application/splunk_endpoint_denial_of_service_dos_zip_bomb/) | [Endpoint Denial of Service](/tags/#endpoint-denial-of-service)| TTP |
| [Splunk Process Injection Forwarder Bundle Downloads](/application/splunk_process_injection_forwarder_bundle_downloads/) | [Process Injection](/tags/#process-injection)| Hunting |
| [Splunk Protocol Impersonation Weak Encryption Configuration](/application/splunk_protocol_impersonation_weak_encryption_configuration/) | [Protocol Impersonation](/tags/#protocol-impersonation)| Hunting |
| [Splunk protocol impersonation weak encryption selfsigned](/application/splunk_protocol_impersonation_weak_encryption_selfsigned/) | [Digital Certificates](/tags/#digital-certificates)| Hunting |
| [Splunk protocol impersonation weak encryption simplerequest](/application/splunk_protocol_impersonation_weak_encryption_simplerequest/) | [Digital Certificates](/tags/#digital-certificates)| Hunting |
| [Splunk User Enumeration Attempt](/application/splunk_user_enumeration_attempt/) | [Valid Accounts](/tags/#valid-accounts)| TTP |
| [Splunk XSS in Monitoring Console](/application/splunk_xss_in_monitoring_console/) | [Drive-by Compromise](/tags/#drive-by-compromise)| TTP |
| [Open Redirect in Splunk Web](/deprecated/open_redirect_in_splunk_web/) | None| TTP |
| [Splunk Enterprise Information Disclosure](/deprecated/splunk_enterprise_information_disclosure/) | None| TTP |
| [Splunk Account Discovery Drilldown Dashboard Disclosure](/application/splunk_account_discovery_drilldown_dashboard_disclosure/) | [Account Discovery](/tags/#account-discovery)| TTP |
| [Splunk Identified SSL TLS Certificates](/network/splunk_identified_ssl_tls_certificates/) | [Network Sniffing](/tags/#network-sniffing)| Hunting |

#### Reference

* [https://www.splunk.com/en_us/product-security/announcements.html](https://www.splunk.com/en_us/product-security/announcements.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/splunk_vulnerabilities.yml) \| *version*: **1**