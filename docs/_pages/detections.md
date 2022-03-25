---
title: "Detections"
layout: categories
author_profile: false
permalink: /detections/
classes: wide
sidebar:
  nav: "detections"
---

| Name           | Technique       | Type            |
| -------------- | --------------- | --------------- |
| [7zip CommandLine To SMB Share Path](/endpoint/7zip_commandline_to_smb_share_path/) | [Archive via Utility](/tags/#archive-via-utility), [Archive Collected Data](/tags/#archive-collected-data) | Hunting |
| [AWS Cloud Provisioning From Previously Unseen City](/deprecated/aws_cloud_provisioning_from_previously_unseen_city/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | Anomaly |
| [AWS Cloud Provisioning From Previously Unseen Country](/deprecated/aws_cloud_provisioning_from_previously_unseen_country/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | Anomaly |
| [AWS Cloud Provisioning From Previously Unseen IP Address]() | None | Anomaly |
| [AWS Cloud Provisioning From Previously Unseen Region](/deprecated/aws_cloud_provisioning_from_previously_unseen_region/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | Anomaly |
| [AWS Create Policy Version to allow all resources](/cloud/aws_create_policy_version_to_allow_all_resources/) | [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts) | TTP |
| [AWS CreateAccessKey](/cloud/aws_createaccesskey/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account) | Hunting |
| [AWS CreateLoginProfile](/cloud/aws_createloginprofile/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account) | TTP |
| [AWS Cross Account Activity From Previously Unseen Account]() | None | Anomaly |
| [AWS Detect Users creating keys with encrypt policy without MFA](/cloud/aws_detect_users_creating_keys_with_encrypt_policy_without_mfa/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | TTP |
| [AWS Detect Users with KMS keys performing encryption S3](/cloud/aws_detect_users_with_kms_keys_performing_encryption_s3/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | Anomaly |
| [AWS ECR Container Scanning Findings High](/cloud/aws_ecr_container_scanning_findings_high/) | [Malicious Image](/tags/#malicious-image), [User Execution](/tags/#user-execution) | TTP |
| [AWS ECR Container Scanning Findings Low Informational Unknown](/cloud/aws_ecr_container_scanning_findings_low_informational_unknown/) | [Malicious Image](/tags/#malicious-image), [User Execution](/tags/#user-execution) | Hunting |
| [AWS ECR Container Scanning Findings Medium](/cloud/aws_ecr_container_scanning_findings_medium/) | [Malicious Image](/tags/#malicious-image), [User Execution](/tags/#user-execution) | Anomaly |
| [AWS ECR Container Upload Outside Business Hours](/cloud/aws_ecr_container_upload_outside_business_hours/) | [Malicious Image](/tags/#malicious-image), [User Execution](/tags/#user-execution) | Anomaly |
| [AWS ECR Container Upload Unknown User](/cloud/aws_ecr_container_upload_unknown_user/) | [Malicious Image](/tags/#malicious-image), [User Execution](/tags/#user-execution) | Anomaly |
| [AWS EKS Kubernetes cluster sensitive object access]() | None | Hunting |
| [AWS Excessive Security Scanning](/cloud/aws_excessive_security_scanning/) | [Cloud Service Discovery](/tags/#cloud-service-discovery) | TTP |
| [AWS IAM AccessDenied Discovery Events](/cloud/aws_iam_accessdenied_discovery_events/) | [Cloud Infrastructure Discovery](/tags/#cloud-infrastructure-discovery) | Anomaly |
| [AWS IAM Assume Role Policy Brute Force](/cloud/aws_iam_assume_role_policy_brute_force/) | [Cloud Infrastructure Discovery](/tags/#cloud-infrastructure-discovery), [Brute Force](/tags/#brute-force) | TTP |
| [AWS IAM Delete Policy](/cloud/aws_iam_delete_policy/) | [Account Manipulation](/tags/#account-manipulation) | Hunting |
| [AWS IAM Failure Group Deletion](/cloud/aws_iam_failure_group_deletion/) | [Account Manipulation](/tags/#account-manipulation) | Anomaly |
| [AWS IAM Successful Group Deletion](/cloud/aws_iam_successful_group_deletion/) | [Cloud Groups](/tags/#cloud-groups), [Account Manipulation](/tags/#account-manipulation), [Permission Groups Discovery](/tags/#permission-groups-discovery) | Hunting |
| [AWS Lambda UpdateFunctionCode](/cloud/aws_lambda_updatefunctioncode/) | [User Execution](/tags/#user-execution) | Hunting |
| [AWS Network Access Control List Created with All Open Ports](/cloud/aws_network_access_control_list_created_with_all_open_ports/) | [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [AWS Network Access Control List Deleted](/cloud/aws_network_access_control_list_deleted/) | [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall), [Impair Defenses](/tags/#impair-defenses) | Anomaly |
| [AWS SAML Access by Provider User and Principal](/cloud/aws_saml_access_by_provider_user_and_principal/) | [Valid Accounts](/tags/#valid-accounts) | Anomaly |
| [AWS SAML Update identity provider](/cloud/aws_saml_update_identity_provider/) | [Valid Accounts](/tags/#valid-accounts) | TTP |
| [AWS SetDefaultPolicyVersion](/cloud/aws_setdefaultpolicyversion/) | [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts) | TTP |
| [AWS UpdateLoginProfile](/cloud/aws_updateloginprofile/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account) | TTP |
| [Abnormally High AWS Instances Launched by User](/deprecated/abnormally_high_aws_instances_launched_by_user/) | [Cloud Accounts](/tags/#cloud-accounts) | Anomaly |
| [Abnormally High AWS Instances Launched by User - MLTK](/deprecated/abnormally_high_aws_instances_launched_by_user_-_mltk/) | [Cloud Accounts](/tags/#cloud-accounts) | Anomaly |
| [Abnormally High AWS Instances Terminated by User](/deprecated/abnormally_high_aws_instances_terminated_by_user/) | [Cloud Accounts](/tags/#cloud-accounts) | Anomaly |
| [Abnormally High AWS Instances Terminated by User - MLTK](/deprecated/abnormally_high_aws_instances_terminated_by_user_-_mltk/) | [Cloud Accounts](/tags/#cloud-accounts) | Anomaly |
| [Abnormally High Number Of Cloud Infrastructure API Calls](/cloud/abnormally_high_number_of_cloud_infrastructure_api_calls/) | [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts) | Anomaly |
| [Abnormally High Number Of Cloud Instances Destroyed](/cloud/abnormally_high_number_of_cloud_instances_destroyed/) | [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts) | Anomaly |
| [Abnormally High Number Of Cloud Instances Launched](/cloud/abnormally_high_number_of_cloud_instances_launched/) | [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts) | Anomaly |
| [Abnormally High Number Of Cloud Security Group API Calls](/cloud/abnormally_high_number_of_cloud_security_group_api_calls/) | [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts) | Anomaly |
| [Access LSASS Memory for Dump Creation](/endpoint/access_lsass_memory_for_dump_creation/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Account Discovery With Net App](/endpoint/account_discovery_with_net_app/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | TTP |
| [Active Setup Registry Autostart](/endpoint/active_setup_registry_autostart/) | [Active Setup](/tags/#active-setup), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | TTP |
| [Add DefaultUser And Password In Registry](/endpoint/add_defaultuser_and_password_in_registry/) | [Credentials in Registry](/tags/#credentials-in-registry), [Unsecured Credentials](/tags/#unsecured-credentials) | Anomaly |
| [Add or Set Windows Defender Exclusion](/endpoint/add_or_set_windows_defender_exclusion/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [AdsiSearcher Account Discovery](/endpoint/adsisearcher_account_discovery/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | TTP |
| [Allow File And Printing Sharing In Firewall](/endpoint/allow_file_and_printing_sharing_in_firewall/) | [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Allow Inbound Traffic By Firewall Rule Registry](/endpoint/allow_inbound_traffic_by_firewall_rule_registry/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services) | TTP |
| [Allow Inbound Traffic In Firewall Rule](/endpoint/allow_inbound_traffic_in_firewall_rule/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services) | TTP |
| [Allow Network Discovery In Firewall](/endpoint/allow_network_discovery_in_firewall/) | [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Allow Operation with Consent Admin](/endpoint/allow_operation_with_consent_admin/) | [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Amazon EKS Kubernetes Pod scan detection](/cloud/amazon_eks_kubernetes_pod_scan_detection/) | [Cloud Service Discovery](/tags/#cloud-service-discovery) | Hunting |
| [Amazon EKS Kubernetes cluster scan detection](/cloud/amazon_eks_kubernetes_cluster_scan_detection/) | [Cloud Service Discovery](/tags/#cloud-service-discovery) | Hunting |
| [Anomalous usage of 7zip](/endpoint/anomalous_usage_of_7zip/) | [Archive via Utility](/tags/#archive-via-utility), [Archive Collected Data](/tags/#archive-collected-data) | Anomaly |
| [Any Powershell DownloadFile](/endpoint/any_powershell_downloadfile/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | TTP |
| [Any Powershell DownloadString](/endpoint/any_powershell_downloadstring/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | TTP |
| [Attacker Tools On Endpoint](/endpoint/attacker_tools_on_endpoint/) | [Match Legitimate Name or Location](/tags/#match-legitimate-name-or-location), [Masquerading](/tags/#masquerading), [OS Credential Dumping](/tags/#os-credential-dumping), [Active Scanning](/tags/#active-scanning) | TTP |
| [Attempt To Add Certificate To Untrusted Store](/endpoint/attempt_to_add_certificate_to_untrusted_store/) | [Install Root Certificate](/tags/#install-root-certificate), [Subvert Trust Controls](/tags/#subvert-trust-controls) | TTP |
| [Attempt To Stop Security Service](/endpoint/attempt_to_stop_security_service/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Attempted Credential Dump From Registry via Reg exe](/endpoint/attempted_credential_dump_from_registry_via_reg_exe/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Auto Admin Logon Registry Entry](/endpoint/auto_admin_logon_registry_entry/) | [Credentials in Registry](/tags/#credentials-in-registry), [Unsecured Credentials](/tags/#unsecured-credentials) | TTP |
| [BCDEdit Failure Recovery Modification](/endpoint/bcdedit_failure_recovery_modification/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | TTP |
| [BITS Job Persistence](/endpoint/bits_job_persistence/) | [BITS Jobs](/tags/#bits-jobs) | TTP |
| [BITSAdmin Download File](/endpoint/bitsadmin_download_file/) | [BITS Jobs](/tags/#bits-jobs), [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | TTP |
| [Batch File Write to System32](/endpoint/batch_file_write_to_system32/) | [User Execution](/tags/#user-execution), [Malicious File](/tags/#malicious-file) | TTP |
| [Bcdedit Command Back To Normal Mode Boot](/endpoint/bcdedit_command_back_to_normal_mode_boot/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | TTP |
| [CHCP Command Execution](/endpoint/chcp_command_execution/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | TTP |
| [CMD Carry Out String Command Parameter](/endpoint/cmd_carry_out_string_command_parameter/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | Hunting |
| [CMD Echo Pipe - Escalation](/endpoint/cmd_echo_pipe_-_escalation/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Windows Command Shell](/tags/#windows-command-shell), [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process) | TTP |
| [CMLUA Or CMSTPLUA UAC Bypass](/endpoint/cmlua_or_cmstplua_uac_bypass/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [CMSTP](/tags/#cmstp) | TTP |
| [CSC Net On The Fly Compilation](/endpoint/csc_net_on_the_fly_compilation/) | [Compile After Delivery](/tags/#compile-after-delivery), [Obfuscated Files or Information](/tags/#obfuscated-files-or-information) | Hunting |
| [CertUtil Download With URLCache and Split Arguments](/endpoint/certutil_download_with_urlcache_and_split_arguments/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | TTP |
| [CertUtil Download With VerifyCtl and Split Arguments](/endpoint/certutil_download_with_verifyctl_and_split_arguments/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | TTP |
| [CertUtil With Decode Argument](/endpoint/certutil_with_decode_argument/) | [Deobfuscate/Decode Files or Information](/tags/#deobfuscate/decode-files-or-information) | TTP |
| [Certutil exe certificate extraction]() | None | TTP |
| [Change Default File Association](/endpoint/change_default_file_association/) | [Change Default File Association](/tags/#change-default-file-association), [Event Triggered Execution](/tags/#event-triggered-execution) | TTP |
| [Change To Safe Mode With Network Config](/endpoint/change_to_safe_mode_with_network_config/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | TTP |
| [Check Elevated CMD using whoami](/endpoint/check_elevated_cmd_using_whoami/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | TTP |
| [Child Processes of Spoolsv exe](/endpoint/child_processes_of_spoolsv_exe/) | [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation) | TTP |
| [Circle CI Disable Security Job](/cloud/circle_ci_disable_security_job/) | [Compromise Client Software Binary](/tags/#compromise-client-software-binary) | Anomaly |
| [Circle CI Disable Security Step](/cloud/circle_ci_disable_security_step/) | [Compromise Client Software Binary](/tags/#compromise-client-software-binary) | Anomaly |
| [Clear Unallocated Sector Using Cipher App](/endpoint/clear_unallocated_sector_using_cipher_app/) | [File Deletion](/tags/#file-deletion), [Indicator Removal on Host](/tags/#indicator-removal-on-host) | TTP |
| [Clients Connecting to Multiple DNS Servers](/deprecated/clients_connecting_to_multiple_dns_servers/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol) | TTP |
| [Clop Common Exec Parameter](/endpoint/clop_common_exec_parameter/) | [User Execution](/tags/#user-execution) | TTP |
| [Clop Ransomware Known Service Name](/endpoint/clop_ransomware_known_service_name/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | TTP |
| [Cloud API Calls From Previously Unseen User Roles](/cloud/cloud_api_calls_from_previously_unseen_user_roles/) | [Valid Accounts](/tags/#valid-accounts) | Anomaly |
| [Cloud Compute Instance Created By Previously Unseen User](/cloud/cloud_compute_instance_created_by_previously_unseen_user/) | [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts) | Anomaly |
| [Cloud Compute Instance Created In Previously Unused Region](/cloud/cloud_compute_instance_created_in_previously_unused_region/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | Anomaly |
| [Cloud Compute Instance Created With Previously Unseen Image]() | None | Anomaly |
| [Cloud Compute Instance Created With Previously Unseen Instance Type]() | None | Anomaly |
| [Cloud Instance Modified By Previously Unseen User](/cloud/cloud_instance_modified_by_previously_unseen_user/) | [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts) | Anomaly |
| [Cloud Network Access Control List Deleted]() | None | Anomaly |
| [Cloud Provisioning Activity From Previously Unseen City](/cloud/cloud_provisioning_activity_from_previously_unseen_city/) | [Valid Accounts](/tags/#valid-accounts) | Anomaly |
| [Cloud Provisioning Activity From Previously Unseen Country](/cloud/cloud_provisioning_activity_from_previously_unseen_country/) | [Valid Accounts](/tags/#valid-accounts) | Anomaly |
| [Cloud Provisioning Activity From Previously Unseen IP Address](/cloud/cloud_provisioning_activity_from_previously_unseen_ip_address/) | [Valid Accounts](/tags/#valid-accounts) | Anomaly |
| [Cloud Provisioning Activity From Previously Unseen Region](/cloud/cloud_provisioning_activity_from_previously_unseen_region/) | [Valid Accounts](/tags/#valid-accounts) | Anomaly |
| [Cmdline Tool Not Executed In CMD Shell](/endpoint/cmdline_tool_not_executed_in_cmd_shell/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [JavaScript](/tags/#javascript) | TTP |
| [Cobalt Strike Named Pipes](/endpoint/cobalt_strike_named_pipes/) | [Process Injection](/tags/#process-injection) | TTP |
| [Common Ransomware Extensions](/endpoint/common_ransomware_extensions/) | [Data Destruction](/tags/#data-destruction) | Hunting |
| [Common Ransomware Notes](/endpoint/common_ransomware_notes/) | [Data Destruction](/tags/#data-destruction) | Hunting |
| [Conti Common Exec parameter](/endpoint/conti_common_exec_parameter/) | [User Execution](/tags/#user-execution) | TTP |
| [Control Loading from World Writable Directory](/endpoint/control_loading_from_world_writable_directory/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Control Panel](/tags/#control-panel) | TTP |
| [Correlation by Repository and Risk](/cloud/correlation_by_repository_and_risk/) | [Malicious Image](/tags/#malicious-image), [User Execution](/tags/#user-execution) | Correlation |
| [Correlation by User and Risk](/cloud/correlation_by_user_and_risk/) | [Malicious Image](/tags/#malicious-image), [User Execution](/tags/#user-execution) | Correlation |
| [Create Remote Thread In Shell Application](/endpoint/create_remote_thread_in_shell_application/) | [Process Injection](/tags/#process-injection) | TTP |
| [Create Remote Thread into LSASS](/endpoint/create_remote_thread_into_lsass/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Create local admin accounts using net exe](/endpoint/create_local_admin_accounts_using_net_exe/) | [Local Account](/tags/#local-account), [Create Account](/tags/#create-account) | TTP |
| [Create or delete windows shares using net exe](/endpoint/create_or_delete_windows_shares_using_net_exe/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host), [Network Share Connection Removal](/tags/#network-share-connection-removal) | TTP |
| [Creation of Shadow Copy](/endpoint/creation_of_shadow_copy/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Creation of Shadow Copy with wmic and powershell](/endpoint/creation_of_shadow_copy_with_wmic_and_powershell/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Creation of lsass Dump with Taskmgr](/endpoint/creation_of_lsass_dump_with_taskmgr/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Credential Dumping via Copy Command from Shadow Copy](/endpoint/credential_dumping_via_copy_command_from_shadow_copy/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Credential Dumping via Symlink to Shadow Copy](/endpoint/credential_dumping_via_symlink_to_shadow_copy/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Curl Download and Bash Execution](/endpoint/curl_download_and_bash_execution/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | TTP |
| [DLLHost with no Command Line Arguments with Network](/endpoint/dllhost_with_no_command_line_arguments_with_network/) | [Process Injection](/tags/#process-injection) | TTP |
| [DNS Exfiltration Using Nslookup App](/endpoint/dns_exfiltration_using_nslookup_app/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | TTP |
| [DNS Query Length Outliers - MLTK](/network/dns_query_length_outliers_-_mltk/) | [DNS](/tags/#dns), [Application Layer Protocol](/tags/#application-layer-protocol) | Anomaly |
| [DNS Query Length With High Standard Deviation](/network/dns_query_length_with_high_standard_deviation/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | Anomaly |
| [DNS Query Requests Resolved by Unauthorized DNS Servers](/deprecated/dns_query_requests_resolved_by_unauthorized_dns_servers/) | [DNS](/tags/#dns) | TTP |
| [DNS record changed](/deprecated/dns_record_changed/) | [DNS](/tags/#dns) | TTP |
| [DSQuery Domain Discovery](/endpoint/dsquery_domain_discovery/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | TTP |
| [Delete ShadowCopy With PowerShell](/endpoint/delete_shadowcopy_with_powershell/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | TTP |
| [Deleting Of Net Users](/endpoint/deleting_of_net_users/) | [Account Access Removal](/tags/#account-access-removal) | TTP |
| [Deleting Shadow Copies](/endpoint/deleting_shadow_copies/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | TTP |
| [Detect API activity from users without MFA]() | None | Hunting |
| [Detect ARP Poisoning](/network/detect_arp_poisoning/) | [Hardware Additions](/tags/#hardware-additions), [Network Denial of Service](/tags/#network-denial-of-service), [Adversary-in-the-Middle](/tags/#adversary-in-the-middle), [ARP Cache Poisoning](/tags/#arp-cache-poisoning) | TTP |
| [Detect AWS API Activities From Unapproved Accounts](/deprecated/detect_aws_api_activities_from_unapproved_accounts/) | [Cloud Accounts](/tags/#cloud-accounts) | Hunting |
| [Detect AWS Console Login by New User]() | None | Hunting |
| [Detect AWS Console Login by User from New City](/cloud/detect_aws_console_login_by_user_from_new_city/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | Hunting |
| [Detect AWS Console Login by User from New Country](/cloud/detect_aws_console_login_by_user_from_new_country/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | Hunting |
| [Detect AWS Console Login by User from New Region](/cloud/detect_aws_console_login_by_user_from_new_region/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | Hunting |
| [Detect Activity Related to Pass the Hash Attacks](/endpoint/detect_activity_related_to_pass_the_hash_attacks/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material), [Pass the Hash](/tags/#pass-the-hash) | TTP |
| [Detect AzureHound Command-Line Arguments](/endpoint/detect_azurehound_command-line_arguments/) | [Domain Account](/tags/#domain-account), [Local Groups](/tags/#local-groups), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Local Account](/tags/#local-account), [Account Discovery](/tags/#account-discovery), [Domain Groups](/tags/#domain-groups), [Permission Groups Discovery](/tags/#permission-groups-discovery) | TTP |
| [Detect AzureHound File Modifications](/endpoint/detect_azurehound_file_modifications/) | [Domain Account](/tags/#domain-account), [Local Groups](/tags/#local-groups), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Local Account](/tags/#local-account), [Account Discovery](/tags/#account-discovery), [Domain Groups](/tags/#domain-groups), [Permission Groups Discovery](/tags/#permission-groups-discovery) | TTP |
| [Detect Baron Samedit CVE-2021-3156](/endpoint/detect_baron_samedit_cve-2021-3156/) | [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation) | TTP |
| [Detect Baron Samedit CVE-2021-3156 Segfault](/endpoint/detect_baron_samedit_cve-2021-3156_segfault/) | [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation) | TTP |
| [Detect Baron Samedit CVE-2021-3156 via OSQuery](/endpoint/detect_baron_samedit_cve-2021-3156_via_osquery/) | [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation) | TTP |
| [Detect Computer Changed with Anonymous Account](/endpoint/detect_computer_changed_with_anonymous_account/) | [Exploitation of Remote Services](/tags/#exploitation-of-remote-services) | Hunting |
| [Detect Copy of ShadowCopy with Script Block Logging](/endpoint/detect_copy_of_shadowcopy_with_script_block_logging/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Detect Credential Dumping through LSASS access](/endpoint/detect_credential_dumping_through_lsass_access/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Detect DNS requests to Phishing Sites leveraging EvilGinx2](/deprecated/detect_dns_requests_to_phishing_sites_leveraging_evilginx2/) | [Spearphishing via Service](/tags/#spearphishing-via-service) | TTP |
| [Detect Empire with PowerShell Script Block Logging](/endpoint/detect_empire_with_powershell_script_block_logging/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | TTP |
| [Detect Excessive Account Lockouts From Endpoint](/endpoint/detect_excessive_account_lockouts_from_endpoint/) | [Valid Accounts](/tags/#valid-accounts), [Domain Accounts](/tags/#domain-accounts) | Anomaly |
| [Detect Excessive User Account Lockouts](/endpoint/detect_excessive_user_account_lockouts/) | [Valid Accounts](/tags/#valid-accounts), [Local Accounts](/tags/#local-accounts) | Anomaly |
| [Detect Exchange Web Shell](/endpoint/detect_exchange_web_shell/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell), [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | TTP |
| [Detect F5 TMUI RCE CVE-2020-5902](/web/detect_f5_tmui_rce_cve-2020-5902/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | TTP |
| [Detect GCP Storage access from a new IP](/cloud/detect_gcp_storage_access_from_a_new_ip/) | [Data from Cloud Storage Object](/tags/#data-from-cloud-storage-object) | Anomaly |
| [Detect HTML Help Renamed](/endpoint/detect_html_help_renamed/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Compiled HTML File](/tags/#compiled-html-file) | Hunting |
| [Detect HTML Help Spawn Child Process](/endpoint/detect_html_help_spawn_child_process/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Compiled HTML File](/tags/#compiled-html-file) | TTP |
| [Detect HTML Help URL in Command Line](/endpoint/detect_html_help_url_in_command_line/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Compiled HTML File](/tags/#compiled-html-file) | TTP |
| [Detect HTML Help Using InfoTech Storage Handlers](/endpoint/detect_html_help_using_infotech_storage_handlers/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Compiled HTML File](/tags/#compiled-html-file) | TTP |
| [Detect IPv6 Network Infrastructure Threats](/network/detect_ipv6_network_infrastructure_threats/) | [Hardware Additions](/tags/#hardware-additions), [Network Denial of Service](/tags/#network-denial-of-service), [Adversary-in-the-Middle](/tags/#adversary-in-the-middle), [ARP Cache Poisoning](/tags/#arp-cache-poisoning) | TTP |
| [Detect Large Outbound ICMP Packets](/network/detect_large_outbound_icmp_packets/) | [Non-Application Layer Protocol](/tags/#non-application-layer-protocol) | TTP |
| [Detect Long DNS TXT Record Response](/deprecated/detect_long_dns_txt_record_response/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol) | TTP |
| [Detect MSHTA Url in Command Line](/endpoint/detect_mshta_url_in_command_line/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Mshta](/tags/#mshta) | TTP |
| [Detect Mimikatz Using Loaded Images](/endpoint/detect_mimikatz_using_loaded_images/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Detect Mimikatz Via PowerShell And EventCode 4703](/deprecated/detect_mimikatz_via_powershell_and_eventcode_4703/) | [LSASS Memory](/tags/#lsass-memory) | TTP |
| [Detect Mimikatz With PowerShell Script Block Logging](/endpoint/detect_mimikatz_with_powershell_script_block_logging/) | [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Detect New Local Admin account](/endpoint/detect_new_local_admin_account/) | [Local Account](/tags/#local-account), [Create Account](/tags/#create-account) | TTP |
| [Detect New Login Attempts to Routers]() | None | TTP |
| [Detect New Open GCP Storage Buckets](/cloud/detect_new_open_gcp_storage_buckets/) | [Data from Cloud Storage Object](/tags/#data-from-cloud-storage-object) | TTP |
| [Detect New Open S3 Buckets over AWS CLI](/cloud/detect_new_open_s3_buckets_over_aws_cli/) | [Data from Cloud Storage Object](/tags/#data-from-cloud-storage-object) | TTP |
| [Detect New Open S3 buckets](/cloud/detect_new_open_s3_buckets/) | [Data from Cloud Storage Object](/tags/#data-from-cloud-storage-object) | TTP |
| [Detect Outbound LDAP Traffic](/network/detect_outbound_ldap_traffic/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | Hunting |
| [Detect Outbound SMB Traffic](/network/detect_outbound_smb_traffic/) | [File Transfer Protocols](/tags/#file-transfer-protocols), [Application Layer Protocol](/tags/#application-layer-protocol) | TTP |
| [Detect Outlook exe writing a zip file](/endpoint/detect_outlook_exe_writing_a_zip_file/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Detect Path Interception By Creation Of program exe](/endpoint/detect_path_interception_by_creation_of_program_exe/) | [Path Interception by Unquoted Path](/tags/#path-interception-by-unquoted-path), [Hijack Execution Flow](/tags/#hijack-execution-flow) | TTP |
| [Detect Port Security Violation](/network/detect_port_security_violation/) | [Hardware Additions](/tags/#hardware-additions), [Network Denial of Service](/tags/#network-denial-of-service), [Adversary-in-the-Middle](/tags/#adversary-in-the-middle), [ARP Cache Poisoning](/tags/#arp-cache-poisoning) | TTP |
| [Detect Prohibited Applications Spawning cmd exe](/endpoint/detect_prohibited_applications_spawning_cmd_exe/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Windows Command Shell](/tags/#windows-command-shell) | Hunting |
| [Detect PsExec With accepteula Flag](/endpoint/detect_psexec_with_accepteula_flag/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | TTP |
| [Detect RClone Command-Line Usage](/endpoint/detect_rclone_command-line_usage/) | [Automated Exfiltration](/tags/#automated-exfiltration) | TTP |
| [Detect Rare Executables]() | None | Anomaly |
| [Detect Regasm Spawning a Process](/endpoint/detect_regasm_spawning_a_process/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm) | TTP |
| [Detect Regasm with Network Connection](/endpoint/detect_regasm_with_network_connection/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm) | TTP |
| [Detect Regasm with no Command Line Arguments](/endpoint/detect_regasm_with_no_command_line_arguments/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm) | TTP |
| [Detect Regsvcs Spawning a Process](/endpoint/detect_regsvcs_spawning_a_process/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm) | TTP |
| [Detect Regsvcs with Network Connection](/endpoint/detect_regsvcs_with_network_connection/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm) | TTP |
| [Detect Regsvcs with No Command Line Arguments](/endpoint/detect_regsvcs_with_no_command_line_arguments/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm) | TTP |
| [Detect Regsvr32 Application Control Bypass](/endpoint/detect_regsvr32_application_control_bypass/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvr32](/tags/#regsvr32) | TTP |
| [Detect Renamed 7-Zip](/endpoint/detect_renamed_7-zip/) | [Archive via Utility](/tags/#archive-via-utility), [Archive Collected Data](/tags/#archive-collected-data) | Hunting |
| [Detect Renamed PSExec](/endpoint/detect_renamed_psexec/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | Hunting |
| [Detect Renamed RClone](/endpoint/detect_renamed_rclone/) | [Automated Exfiltration](/tags/#automated-exfiltration) | Hunting |
| [Detect Renamed WinRAR](/endpoint/detect_renamed_winrar/) | [Archive via Utility](/tags/#archive-via-utility), [Archive Collected Data](/tags/#archive-collected-data) | Hunting |
| [Detect Rogue DHCP Server](/network/detect_rogue_dhcp_server/) | [Hardware Additions](/tags/#hardware-additions), [Network Denial of Service](/tags/#network-denial-of-service), [Adversary-in-the-Middle](/tags/#adversary-in-the-middle) | TTP |
| [Detect Rundll32 Application Control Bypass - advpack](/endpoint/detect_rundll32_application_control_bypass_-_advpack/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32) | TTP |
| [Detect Rundll32 Application Control Bypass - setupapi](/endpoint/detect_rundll32_application_control_bypass_-_setupapi/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32) | TTP |
| [Detect Rundll32 Application Control Bypass - syssetup](/endpoint/detect_rundll32_application_control_bypass_-_syssetup/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32) | TTP |
| [Detect Rundll32 Inline HTA Execution](/endpoint/detect_rundll32_inline_hta_execution/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Mshta](/tags/#mshta) | TTP |
| [Detect S3 access from a new IP](/cloud/detect_s3_access_from_a_new_ip/) | [Data from Cloud Storage Object](/tags/#data-from-cloud-storage-object) | Anomaly |
| [Detect SNICat SNI Exfiltration](/network/detect_snicat_sni_exfiltration/) | [Exfiltration Over C2 Channel](/tags/#exfiltration-over-c2-channel) | TTP |
| [Detect SharpHound Command-Line Arguments](/endpoint/detect_sharphound_command-line_arguments/) | [Domain Account](/tags/#domain-account), [Local Groups](/tags/#local-groups), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Local Account](/tags/#local-account), [Account Discovery](/tags/#account-discovery), [Domain Groups](/tags/#domain-groups), [Permission Groups Discovery](/tags/#permission-groups-discovery) | TTP |
| [Detect SharpHound File Modifications](/endpoint/detect_sharphound_file_modifications/) | [Domain Account](/tags/#domain-account), [Local Groups](/tags/#local-groups), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Local Account](/tags/#local-account), [Account Discovery](/tags/#account-discovery), [Domain Groups](/tags/#domain-groups), [Permission Groups Discovery](/tags/#permission-groups-discovery) | TTP |
| [Detect SharpHound Usage](/endpoint/detect_sharphound_usage/) | [Domain Account](/tags/#domain-account), [Local Groups](/tags/#local-groups), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Local Account](/tags/#local-account), [Account Discovery](/tags/#account-discovery), [Domain Groups](/tags/#domain-groups), [Permission Groups Discovery](/tags/#permission-groups-discovery) | TTP |
| [Detect Software Download To Network Device](/network/detect_software_download_to_network_device/) | [TFTP Boot](/tags/#tftp-boot), [Pre-OS Boot](/tags/#pre-os-boot) | TTP |
| [Detect Spike in AWS API Activity](/deprecated/detect_spike_in_aws_api_activity/) | [Cloud Accounts](/tags/#cloud-accounts) | Anomaly |
| [Detect Spike in AWS Security Hub Alerts for EC2 Instance]() | None | Anomaly |
| [Detect Spike in AWS Security Hub Alerts for User]() | None | Anomaly |
| [Detect Spike in Network ACL Activity](/deprecated/detect_spike_in_network_acl_activity/) | [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall) | Anomaly |
| [Detect Spike in S3 Bucket deletion](/cloud/detect_spike_in_s3_bucket_deletion/) | [Data from Cloud Storage Object](/tags/#data-from-cloud-storage-object) | Anomaly |
| [Detect Spike in Security Group Activity](/deprecated/detect_spike_in_security_group_activity/) | [Cloud Accounts](/tags/#cloud-accounts) | Anomaly |
| [Detect Spike in blocked Outbound Traffic from your AWS]() | None | Anomaly |
| [Detect Traffic Mirroring](/network/detect_traffic_mirroring/) | [Hardware Additions](/tags/#hardware-additions), [Automated Exfiltration](/tags/#automated-exfiltration), [Network Denial of Service](/tags/#network-denial-of-service), [Traffic Duplication](/tags/#traffic-duplication) | TTP |
| [Detect USB device insertion]() | None | TTP |
| [Detect Unauthorized Assets by MAC address]() | None | TTP |
| [Detect Use of cmd exe to Launch Script Interpreters](/endpoint/detect_use_of_cmd_exe_to_launch_script_interpreters/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Windows Command Shell](/tags/#windows-command-shell) | TTP |
| [Detect WMI Event Subscription Persistence](/endpoint/detect_wmi_event_subscription_persistence/) | [Windows Management Instrumentation Event Subscription](/tags/#windows-management-instrumentation-event-subscription), [Event Triggered Execution](/tags/#event-triggered-execution) | TTP |
| [Detect Windows DNS SIGRed via Splunk Stream](/network/detect_windows_dns_sigred_via_splunk_stream/) | [Exploitation for Client Execution](/tags/#exploitation-for-client-execution) | TTP |
| [Detect Windows DNS SIGRed via Zeek](/network/detect_windows_dns_sigred_via_zeek/) | [Exploitation for Client Execution](/tags/#exploitation-for-client-execution) | TTP |
| [Detect Zerologon via Zeek](/network/detect_zerologon_via_zeek/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | TTP |
| [Detect attackers scanning for vulnerable JBoss servers](/web/detect_attackers_scanning_for_vulnerable_jboss_servers/) | [System Information Discovery](/tags/#system-information-discovery) | TTP |
| [Detect hosts connecting to dynamic domain providers](/network/detect_hosts_connecting_to_dynamic_domain_providers/) | [Drive-by Compromise](/tags/#drive-by-compromise) | TTP |
| [Detect malicious requests to exploit JBoss servers]() | None | TTP |
| [Detect mshta inline hta execution](/endpoint/detect_mshta_inline_hta_execution/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Mshta](/tags/#mshta) | TTP |
| [Detect mshta renamed](/endpoint/detect_mshta_renamed/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Mshta](/tags/#mshta) | Hunting |
| [Detect new API calls from user roles](/deprecated/detect_new_api_calls_from_user_roles/) | [Cloud Accounts](/tags/#cloud-accounts) | Anomaly |
| [Detect new user AWS Console Login](/deprecated/detect_new_user_aws_console_login/) | [Cloud Accounts](/tags/#cloud-accounts) | Hunting |
| [Detect processes used for System Network Configuration Discovery](/endpoint/detect_processes_used_for_system_network_configuration_discovery/) | [System Network Configuration Discovery](/tags/#system-network-configuration-discovery) | TTP |
| [Detect shared ec2 snapshot](/cloud/detect_shared_ec2_snapshot/) | [Transfer Data to Cloud Account](/tags/#transfer-data-to-cloud-account) | TTP |
| [Detect web traffic to dynamic domain providers](/deprecated/detect_web_traffic_to_dynamic_domain_providers/) | [Web Protocols](/tags/#web-protocols) | TTP |
| [Detection of DNS Tunnels](/deprecated/detection_of_dns_tunnels/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol) | TTP |
| [Detection of tools built by NirSoft](/endpoint/detection_of_tools_built_by_nirsoft/) | [Software Deployment Tools](/tags/#software-deployment-tools) | TTP |
| [Disable AMSI Through Registry](/endpoint/disable_amsi_through_registry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disable Defender AntiVirus Registry](/endpoint/disable_defender_antivirus_registry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disable Defender BlockAtFirstSeen Feature](/endpoint/disable_defender_blockatfirstseen_feature/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disable Defender Enhanced Notification](/endpoint/disable_defender_enhanced_notification/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disable Defender MpEngine Registry](/endpoint/disable_defender_mpengine_registry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disable Defender Spynet Reporting](/endpoint/disable_defender_spynet_reporting/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disable Defender Submit Samples Consent Feature](/endpoint/disable_defender_submit_samples_consent_feature/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disable ETW Through Registry](/endpoint/disable_etw_through_registry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disable Logs Using WevtUtil](/endpoint/disable_logs_using_wevtutil/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host), [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | TTP |
| [Disable Registry Tool](/endpoint/disable_registry_tool/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disable Schedule Task](/endpoint/disable_schedule_task/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disable Security Logs Using MiniNt Registry](/endpoint/disable_security_logs_using_minint_registry/) | [Modify Registry](/tags/#modify-registry) | TTP |
| [Disable Show Hidden Files](/endpoint/disable_show_hidden_files/) | [Hidden Files and Directories](/tags/#hidden-files-and-directories), [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Hide Artifacts](/tags/#hide-artifacts), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disable UAC Remote Restriction](/endpoint/disable_uac_remote_restriction/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Disable Windows App Hotkeys](/endpoint/disable_windows_app_hotkeys/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disable Windows Behavior Monitoring](/endpoint/disable_windows_behavior_monitoring/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disable Windows SmartScreen Protection](/endpoint/disable_windows_smartscreen_protection/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disabled Kerberos Pre-Authentication Discovery With Get-ADUser](/endpoint/disabled_kerberos_pre-authentication_discovery_with_get-aduser/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [AS-REP Roasting](/tags/#as-rep-roasting) | TTP |
| [Disabled Kerberos Pre-Authentication Discovery With PowerView](/endpoint/disabled_kerberos_pre-authentication_discovery_with_powerview/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [AS-REP Roasting](/tags/#as-rep-roasting) | TTP |
| [Disabling CMD Application](/endpoint/disabling_cmd_application/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disabling ControlPanel](/endpoint/disabling_controlpanel/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disabling Defender Services](/endpoint/disabling_defender_services/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disabling Firewall with Netsh](/endpoint/disabling_firewall_with_netsh/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disabling FolderOptions Windows Feature](/endpoint/disabling_folderoptions_windows_feature/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disabling Net User Account](/endpoint/disabling_net_user_account/) | [Account Access Removal](/tags/#account-access-removal) | TTP |
| [Disabling NoRun Windows App](/endpoint/disabling_norun_windows_app/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disabling Remote User Account Control](/endpoint/disabling_remote_user_account_control/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Disabling SystemRestore In Registry](/endpoint/disabling_systemrestore_in_registry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disabling Task Manager](/endpoint/disabling_task_manager/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Domain Account Discovery With Net App](/endpoint/domain_account_discovery_with_net_app/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | TTP |
| [Domain Account Discovery with Dsquery](/endpoint/domain_account_discovery_with_dsquery/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | Hunting |
| [Domain Account Discovery with Wmic](/endpoint/domain_account_discovery_with_wmic/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | TTP |
| [Domain Controller Discovery with Nltest](/endpoint/domain_controller_discovery_with_nltest/) | [Remote System Discovery](/tags/#remote-system-discovery) | TTP |
| [Domain Controller Discovery with Wmic](/endpoint/domain_controller_discovery_with_wmic/) | [Remote System Discovery](/tags/#remote-system-discovery) | Hunting |
| [Domain Group Discovery With Dsquery](/endpoint/domain_group_discovery_with_dsquery/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | Hunting |
| [Domain Group Discovery With Net](/endpoint/domain_group_discovery_with_net/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | Hunting |
| [Domain Group Discovery With Wmic](/endpoint/domain_group_discovery_with_wmic/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | Hunting |
| [Domain Group Discovery with Adsisearcher](/endpoint/domain_group_discovery_with_adsisearcher/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | TTP |
| [Download Files Using Telegram](/endpoint/download_files_using_telegram/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | TTP |
| [Drop IcedID License dat](/endpoint/drop_icedid_license_dat/) | [User Execution](/tags/#user-execution), [Malicious File](/tags/#malicious-file) | Hunting |
| [Dump LSASS via comsvcs DLL](/endpoint/dump_lsass_via_comsvcs_dll/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Dump LSASS via procdump](/endpoint/dump_lsass_via_procdump/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Dump LSASS via procdump Rename](/deprecated/dump_lsass_via_procdump_rename/) | [LSASS Memory](/tags/#lsass-memory) | Hunting |
| [EC2 Instance Modified With Previously Unseen User](/deprecated/ec2_instance_modified_with_previously_unseen_user/) | [Cloud Accounts](/tags/#cloud-accounts) | Anomaly |
| [EC2 Instance Started In Previously Unseen Region](/deprecated/ec2_instance_started_in_previously_unseen_region/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | Anomaly |
| [EC2 Instance Started With Previously Unseen AMI]() | None | Anomaly |
| [EC2 Instance Started With Previously Unseen Instance Type]() | None | Anomaly |
| [EC2 Instance Started With Previously Unseen User](/deprecated/ec2_instance_started_with_previously_unseen_user/) | [Cloud Accounts](/tags/#cloud-accounts) | Anomaly |
| [ETW Registry Disabled](/endpoint/etw_registry_disabled/) | [Indicator Blocking](/tags/#indicator-blocking), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Elevated Group Discovery With Net](/endpoint/elevated_group_discovery_with_net/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | TTP |
| [Elevated Group Discovery With Wmic](/endpoint/elevated_group_discovery_with_wmic/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | TTP |
| [Elevated Group Discovery with PowerView](/endpoint/elevated_group_discovery_with_powerview/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | Hunting |
| [Email Attachments With Lots Of Spaces]() | None | Anomaly |
| [Email files written outside of the Outlook directory](/application/email_files_written_outside_of_the_outlook_directory/) | [Email Collection](/tags/#email-collection), [Local Email Collection](/tags/#local-email-collection) | TTP |
| [Email servers sending high volume traffic to hosts](/application/email_servers_sending_high_volume_traffic_to_hosts/) | [Email Collection](/tags/#email-collection), [Remote Email Collection](/tags/#remote-email-collection) | Anomaly |
| [Enable RDP In Other Port Number](/endpoint/enable_rdp_in_other_port_number/) | [Remote Services](/tags/#remote-services) | TTP |
| [Enable WDigest UseLogonCredential Registry](/endpoint/enable_wdigest_uselogoncredential_registry/) | [Modify Registry](/tags/#modify-registry), [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Enumerate Users Local Group Using Telegram](/endpoint/enumerate_users_local_group_using_telegram/) | [Account Discovery](/tags/#account-discovery) | TTP |
| [Esentutl SAM Copy](/endpoint/esentutl_sam_copy/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | Hunting |
| [Eventvwr UAC Bypass](/endpoint/eventvwr_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Excel Spawning PowerShell](/endpoint/excel_spawning_powershell/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Excel Spawning Windows Script Host](/endpoint/excel_spawning_windows_script_host/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Excessive Attempt To Disable Services](/endpoint/excessive_attempt_to_disable_services/) | [Service Stop](/tags/#service-stop) | Anomaly |
| [Excessive DNS Failures](/network/excessive_dns_failures/) | [DNS](/tags/#dns), [Application Layer Protocol](/tags/#application-layer-protocol) | Anomaly |
| [Excessive File Deletion In WinDefender Folder](/endpoint/excessive_file_deletion_in_windefender_folder/) | [Data Destruction](/tags/#data-destruction) | TTP |
| [Excessive Service Stop Attempt](/endpoint/excessive_service_stop_attempt/) | [Service Stop](/tags/#service-stop) | Anomaly |
| [Excessive Usage Of Cacls App](/endpoint/excessive_usage_of_cacls_app/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | Anomaly |
| [Excessive Usage Of Net App](/endpoint/excessive_usage_of_net_app/) | [Account Access Removal](/tags/#account-access-removal) | Anomaly |
| [Excessive Usage Of SC Service Utility](/endpoint/excessive_usage_of_sc_service_utility/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | Anomaly |
| [Excessive Usage Of Taskkill](/endpoint/excessive_usage_of_taskkill/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | Anomaly |
| [Excessive Usage of NSLOOKUP App](/endpoint/excessive_usage_of_nslookup_app/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | Anomaly |
| [Excessive distinct processes from Windows Temp](/endpoint/excessive_distinct_processes_from_windows_temp/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | Anomaly |
| [Excessive number of service control start as disabled](/endpoint/excessive_number_of_service_control_start_as_disabled/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | Anomaly |
| [Excessive number of taskhost processes](/endpoint/excessive_number_of_taskhost_processes/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | Anomaly |
| [Exchange PowerShell Abuse via SSRF](/endpoint/exchange_powershell_abuse_via_ssrf/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | TTP |
| [Exchange PowerShell Module Usage](/endpoint/exchange_powershell_module_usage/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | TTP |
| [Executable File Written in Administrative SMB Share](/endpoint/executable_file_written_in_administrative_smb_share/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | TTP |
| [Executables Or Script Creation In Suspicious Path](/endpoint/executables_or_script_creation_in_suspicious_path/) | [Masquerading](/tags/#masquerading) | TTP |
| [Execute Javascript With Jscript COM CLSID](/endpoint/execute_javascript_with_jscript_com_clsid/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Visual Basic](/tags/#visual-basic) | TTP |
| [Execution of File With Spaces Before Extension](/deprecated/execution_of_file_with_spaces_before_extension/) | [Rename System Utilities](/tags/#rename-system-utilities) | TTP |
| [Execution of File with Multiple Extensions](/endpoint/execution_of_file_with_multiple_extensions/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities) | TTP |
| [Extended Period Without Successful Netbackup Backups]() | None | Hunting |
| [Extraction of Registry Hives](/endpoint/extraction_of_registry_hives/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [File with Samsam Extension]() | None | TTP |
| [Firewall Allowed Program Enable](/endpoint/firewall_allowed_program_enable/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses) | Anomaly |
| [First Time Seen Child Process of Zoom](/endpoint/first_time_seen_child_process_of_zoom/) | [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation) | Anomaly |
| [First Time Seen Running Windows Service](/endpoint/first_time_seen_running_windows_service/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | Anomaly |
| [First time seen command line argument](/deprecated/first_time_seen_command_line_argument/) | [PowerShell](/tags/#powershell), [Windows Command Shell](/tags/#windows-command-shell) | Hunting |
| [FodHelper UAC Bypass](/endpoint/fodhelper_uac_bypass/) | [Modify Registry](/tags/#modify-registry), [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Fsutil Zeroing File](/endpoint/fsutil_zeroing_file/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host) | TTP |
| [GCP Detect accounts with high risk roles by project](/deprecated/gcp_detect_accounts_with_high_risk_roles_by_project/) | [Valid Accounts](/tags/#valid-accounts) | Hunting |
| [GCP Detect gcploit framework](/cloud/gcp_detect_gcploit_framework/) | [Valid Accounts](/tags/#valid-accounts) | TTP |
| [GCP Detect high risk permissions by resource and account](/deprecated/gcp_detect_high_risk_permissions_by_resource_and_account/) | [Valid Accounts](/tags/#valid-accounts) | Hunting |
| [GCP GCR container uploaded](/deprecated/gcp_gcr_container_uploaded/) | [Implant Internal Image](/tags/#implant-internal-image) | Hunting |
| [GCP Kubernetes cluster pod scan detection](/cloud/gcp_kubernetes_cluster_pod_scan_detection/) | [Cloud Service Discovery](/tags/#cloud-service-discovery) | Hunting |
| [GCP Kubernetes cluster scan detection](/deprecated/gcp_kubernetes_cluster_scan_detection/) | [Cloud Service Discovery](/tags/#cloud-service-discovery) | TTP |
| [GPUpdate with no Command Line Arguments with Network](/endpoint/gpupdate_with_no_command_line_arguments_with_network/) | [Process Injection](/tags/#process-injection) | TTP |
| [GSuite Email Suspicious Attachment](/cloud/gsuite_email_suspicious_attachment/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing) | Anomaly |
| [Gdrive suspicious file sharing](/cloud/gdrive_suspicious_file_sharing/) | [Phishing](/tags/#phishing) | Hunting |
| [Get ADDefaultDomainPasswordPolicy with Powershell](/endpoint/get_addefaultdomainpasswordpolicy_with_powershell/) | [Password Policy Discovery](/tags/#password-policy-discovery) | Hunting |
| [Get ADDefaultDomainPasswordPolicy with Powershell Script Block](/endpoint/get_addefaultdomainpasswordpolicy_with_powershell_script_block/) | [Password Policy Discovery](/tags/#password-policy-discovery) | Hunting |
| [Get ADUser with PowerShell](/endpoint/get_aduser_with_powershell/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | Hunting |
| [Get ADUser with PowerShell Script Block](/endpoint/get_aduser_with_powershell_script_block/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | Hunting |
| [Get ADUserResultantPasswordPolicy with Powershell](/endpoint/get_aduserresultantpasswordpolicy_with_powershell/) | [Password Policy Discovery](/tags/#password-policy-discovery) | TTP |
| [Get ADUserResultantPasswordPolicy with Powershell Script Block](/endpoint/get_aduserresultantpasswordpolicy_with_powershell_script_block/) | [Password Policy Discovery](/tags/#password-policy-discovery) | TTP |
| [Get DomainPolicy with Powershell](/endpoint/get_domainpolicy_with_powershell/) | [Password Policy Discovery](/tags/#password-policy-discovery) | TTP |
| [Get DomainPolicy with Powershell Script Block](/endpoint/get_domainpolicy_with_powershell_script_block/) | [Password Policy Discovery](/tags/#password-policy-discovery) | TTP |
| [Get DomainUser with PowerShell](/endpoint/get_domainuser_with_powershell/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | TTP |
| [Get DomainUser with PowerShell Script Block](/endpoint/get_domainuser_with_powershell_script_block/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | TTP |
| [Get WMIObject Group Discovery](/endpoint/get_wmiobject_group_discovery/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | Hunting |
| [Get WMIObject Group Discovery with Script Block Logging](/endpoint/get_wmiobject_group_discovery_with_script_block_logging/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | Hunting |
| [Get-DomainTrust with PowerShell](/endpoint/get-domaintrust_with_powershell/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | TTP |
| [Get-DomainTrust with PowerShell Script Block](/endpoint/get-domaintrust_with_powershell_script_block/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | TTP |
| [Get-ForestTrust with PowerShell](/endpoint/get-foresttrust_with_powershell/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | TTP |
| [Get-ForestTrust with PowerShell Script Block](/endpoint/get-foresttrust_with_powershell_script_block/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | TTP |
| [GetAdComputer with PowerShell](/endpoint/getadcomputer_with_powershell/) | [Remote System Discovery](/tags/#remote-system-discovery) | Hunting |
| [GetAdComputer with PowerShell Script Block](/endpoint/getadcomputer_with_powershell_script_block/) | [Remote System Discovery](/tags/#remote-system-discovery) | Hunting |
| [GetAdGroup with PowerShell](/endpoint/getadgroup_with_powershell/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | Hunting |
| [GetAdGroup with PowerShell Script Block](/endpoint/getadgroup_with_powershell_script_block/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | Hunting |
| [GetCurrent User with PowerShell](/endpoint/getcurrent_user_with_powershell/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | Hunting |
| [GetCurrent User with PowerShell Script Block](/endpoint/getcurrent_user_with_powershell_script_block/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | Hunting |
| [GetDomainComputer with PowerShell](/endpoint/getdomaincomputer_with_powershell/) | [Remote System Discovery](/tags/#remote-system-discovery) | TTP |
| [GetDomainComputer with PowerShell Script Block](/endpoint/getdomaincomputer_with_powershell_script_block/) | [Remote System Discovery](/tags/#remote-system-discovery) | TTP |
| [GetDomainController with PowerShell](/endpoint/getdomaincontroller_with_powershell/) | [Remote System Discovery](/tags/#remote-system-discovery) | Hunting |
| [GetDomainController with PowerShell Script Block](/endpoint/getdomaincontroller_with_powershell_script_block/) | [Remote System Discovery](/tags/#remote-system-discovery) | TTP |
| [GetDomainGroup with PowerShell](/endpoint/getdomaingroup_with_powershell/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | TTP |
| [GetDomainGroup with PowerShell Script Block](/endpoint/getdomaingroup_with_powershell_script_block/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | TTP |
| [GetLocalUser with PowerShell](/endpoint/getlocaluser_with_powershell/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account) | Hunting |
| [GetLocalUser with PowerShell Script Block](/endpoint/getlocaluser_with_powershell_script_block/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account) | Hunting |
| [GetNetTcpconnection with PowerShell](/endpoint/getnettcpconnection_with_powershell/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | Hunting |
| [GetNetTcpconnection with PowerShell Script Block](/endpoint/getnettcpconnection_with_powershell_script_block/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | Hunting |
| [GetWmiObject DS User with PowerShell](/endpoint/getwmiobject_ds_user_with_powershell/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | TTP |
| [GetWmiObject DS User with PowerShell Script Block](/endpoint/getwmiobject_ds_user_with_powershell_script_block/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | TTP |
| [GetWmiObject Ds Computer with PowerShell](/endpoint/getwmiobject_ds_computer_with_powershell/) | [Remote System Discovery](/tags/#remote-system-discovery) | TTP |
| [GetWmiObject Ds Computer with PowerShell Script Block](/endpoint/getwmiobject_ds_computer_with_powershell_script_block/) | [Remote System Discovery](/tags/#remote-system-discovery) | TTP |
| [GetWmiObject Ds Group with PowerShell](/endpoint/getwmiobject_ds_group_with_powershell/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | TTP |
| [GetWmiObject Ds Group with PowerShell Script Block](/endpoint/getwmiobject_ds_group_with_powershell_script_block/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | TTP |
| [GetWmiObject User Account with PowerShell](/endpoint/getwmiobject_user_account_with_powershell/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account) | Hunting |
| [GetWmiObject User Account with PowerShell Script Block](/endpoint/getwmiobject_user_account_with_powershell_script_block/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account) | Hunting |
| [GitHub Dependabot Alert](/cloud/github_dependabot_alert/) | [Compromise Software Dependencies and Development Tools](/tags/#compromise-software-dependencies-and-development-tools), [Supply Chain Compromise](/tags/#supply-chain-compromise) | Anomaly |
| [GitHub Pull Request from Unknown User](/cloud/github_pull_request_from_unknown_user/) | [Compromise Software Dependencies and Development Tools](/tags/#compromise-software-dependencies-and-development-tools), [Supply Chain Compromise](/tags/#supply-chain-compromise) | Anomaly |
| [Github Commit Changes In Master](/cloud/github_commit_changes_in_master/) | [Trusted Relationship](/tags/#trusted-relationship) | Anomaly |
| [Github Commit In Develop](/cloud/github_commit_in_develop/) | [Trusted Relationship](/tags/#trusted-relationship) | Anomaly |
| [Gsuite Drive Share In External Email](/cloud/gsuite_drive_share_in_external_email/) | [Exfiltration to Cloud Storage](/tags/#exfiltration-to-cloud-storage), [Exfiltration Over Web Service](/tags/#exfiltration-over-web-service) | Anomaly |
| [Gsuite Email Suspicious Subject With Attachment](/cloud/gsuite_email_suspicious_subject_with_attachment/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing) | Anomaly |
| [Gsuite Email With Known Abuse Web Service Link](/cloud/gsuite_email_with_known_abuse_web_service_link/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing) | Anomaly |
| [Gsuite Outbound Email With Attachment To External Domain](/cloud/gsuite_outbound_email_with_attachment_to_external_domain/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | Anomaly |
| [Gsuite Suspicious Shared File Name](/cloud/gsuite_suspicious_shared_file_name/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing) | Anomaly |
| [Gsuite suspicious calendar invite](/cloud/gsuite_suspicious_calendar_invite/) | [Phishing](/tags/#phishing) | Hunting |
| [Hide User Account From Sign-In Screen](/endpoint/hide_user_account_from_sign-in_screen/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Hiding Files And Directories With Attrib exe](/endpoint/hiding_files_and_directories_with_attrib_exe/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification), [Windows File and Directory Permissions Modification](/tags/#windows-file-and-directory-permissions-modification) | TTP |
| [High Frequency Copy Of Files In Network Share](/endpoint/high_frequency_copy_of_files_in_network_share/) | [Transfer Data to Cloud Account](/tags/#transfer-data-to-cloud-account) | Anomaly |
| [High Number of Login Failures from a single source](/cloud/high_number_of_login_failures_from_a_single_source/) | [Password Guessing](/tags/#password-guessing), [Brute Force](/tags/#brute-force) | Anomaly |
| [High Process Termination Frequency](/endpoint/high_process_termination_frequency/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | Anomaly |
| [Hosts receiving high volume of network traffic from email server](/network/hosts_receiving_high_volume_of_network_traffic_from_email_server/) | [Remote Email Collection](/tags/#remote-email-collection), [Email Collection](/tags/#email-collection) | Anomaly |
| [Hunting for Log4Shell](/endpoint/hunting_for_log4shell/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | Hunting |
| [ICACLS Grant Command](/endpoint/icacls_grant_command/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | TTP |
| [Icacls Deny Command](/endpoint/icacls_deny_command/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | TTP |
| [IcedID Exfiltrated Archived File Creation](/endpoint/icedid_exfiltrated_archived_file_creation/) | [Archive via Utility](/tags/#archive-via-utility), [Archive Collected Data](/tags/#archive-collected-data) | Hunting |
| [Identify New User Accounts](/deprecated/identify_new_user_accounts/) | [Domain Accounts](/tags/#domain-accounts) | Hunting |
| [Impacket Lateral Movement Commandline Parameters](/endpoint/impacket_lateral_movement_commandline_parameters/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Windows Service](/tags/#windows-service) | TTP |
| [Interactive Session on Remote Endpoint with PowerShell](/endpoint/interactive_session_on_remote_endpoint_with_powershell/) | [Remote Services](/tags/#remote-services), [Windows Remote Management](/tags/#windows-remote-management) | TTP |
| [Java Class File download by Java User Agent](/endpoint/java_class_file_download_by_java_user_agent/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | TTP |
| [Jscript Execution Using Cscript App](/endpoint/jscript_execution_using_cscript_app/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [JavaScript](/tags/#javascript) | TTP |
| [Kerberoasting spn request with RC4 encryption](/endpoint/kerberoasting_spn_request_with_rc4_encryption/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Kerberoasting](/tags/#kerberoasting) | TTP |
| [Kerberos Pre-Authentication Flag Disabled in UserAccountControl](/endpoint/kerberos_pre-authentication_flag_disabled_in_useraccountcontrol/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [AS-REP Roasting](/tags/#as-rep-roasting) | TTP |
| [Kerberos Pre-Authentication Flag Disabled with PowerShell](/endpoint/kerberos_pre-authentication_flag_disabled_with_powershell/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [AS-REP Roasting](/tags/#as-rep-roasting) | TTP |
| [Known Services Killed by Ransomware](/endpoint/known_services_killed_by_ransomware/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | TTP |
| [Kubernetes AWS detect RBAC authorization by account]() | None | Hunting |
| [Kubernetes AWS detect most active service accounts by pod]() | None | Hunting |
| [Kubernetes AWS detect sensitive role access]() | None | Hunting |
| [Kubernetes AWS detect service accounts forbidden failure access]() | None | Hunting |
| [Kubernetes AWS detect suspicious kubectl calls]() | None | Hunting |
| [Kubernetes Azure active service accounts by pod namespace]() | None | Hunting |
| [Kubernetes Azure detect RBAC authorization by account]() | None | Hunting |
| [Kubernetes Azure detect sensitive object access]() | None | Hunting |
| [Kubernetes Azure detect sensitive role access]() | None | Hunting |
| [Kubernetes Azure detect service accounts forbidden failure access]() | None | Hunting |
| [Kubernetes Azure detect suspicious kubectl calls]() | None | Hunting |
| [Kubernetes Azure pod scan fingerprint]() | None | Hunting |
| [Kubernetes Azure scan fingerprint](/deprecated/kubernetes_azure_scan_fingerprint/) | [Cloud Service Discovery](/tags/#cloud-service-discovery) | Hunting |
| [Kubernetes GCP detect RBAC authorizations by account]() | None | Hunting |
| [Kubernetes GCP detect most active service accounts by pod]() | None | Hunting |
| [Kubernetes GCP detect sensitive object access]() | None | Hunting |
| [Kubernetes GCP detect sensitive role access]() | None | Hunting |
| [Kubernetes GCP detect service accounts forbidden failure access]() | None | Hunting |
| [Kubernetes GCP detect suspicious kubectl calls]() | None | Hunting |
| [Kubernetes Nginx Ingress LFI](/cloud/kubernetes_nginx_ingress_lfi/) | [Exploitation for Credential Access](/tags/#exploitation-for-credential-access) | TTP |
| [Kubernetes Nginx Ingress RFI](/cloud/kubernetes_nginx_ingress_rfi/) | [Exploitation for Credential Access](/tags/#exploitation-for-credential-access) | TTP |
| [Kubernetes Scanner Image Pulling](/cloud/kubernetes_scanner_image_pulling/) | [Cloud Service Discovery](/tags/#cloud-service-discovery) | TTP |
| [Large Volume of DNS ANY Queries](/network/large_volume_of_dns_any_queries/) | [Network Denial of Service](/tags/#network-denial-of-service), [Reflection Amplification](/tags/#reflection-amplification) | Anomaly |
| [Linux Add Files In Known Crontab Directories](/endpoint/linux_add_files_in_known_crontab_directories/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | Anomaly |
| [Linux Add User Account](/endpoint/linux_add_user_account/) | [Local Account](/tags/#local-account), [Create Account](/tags/#create-account) | Hunting |
| [Linux At Allow Config File Creation](/endpoint/linux_at_allow_config_file_creation/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | Anomaly |
| [Linux At Application Execution](/endpoint/linux_at_application_execution/) | [At (Linux)](/tags/#at-(linux)), [Scheduled Task/Job](/tags/#scheduled-task/job) | Anomaly |
| [Linux Change File Owner To Root](/endpoint/linux_change_file_owner_to_root/) | [Linux and Mac File and Directory Permissions Modification](/tags/#linux-and-mac-file-and-directory-permissions-modification), [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | Anomaly |
| [Linux Common Process For Elevation Control](/endpoint/linux_common_process_for_elevation_control/) | [Setuid and Setgid](/tags/#setuid-and-setgid), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | Hunting |
| [Linux DD File Overwrite](/endpoint/linux_dd_file_overwrite/) | [Data Destruction](/tags/#data-destruction) | TTP |
| [Linux Doas Conf File Creation](/endpoint/linux_doas_conf_file_creation/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | Anomaly |
| [Linux Doas Tool Execution](/endpoint/linux_doas_tool_execution/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | Anomaly |
| [Linux Edit Cron Table Parameter](/endpoint/linux_edit_cron_table_parameter/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | Hunting |
| [Linux File Created In Kernel Driver Directory](/endpoint/linux_file_created_in_kernel_driver_directory/) | [Kernel Modules and Extensions](/tags/#kernel-modules-and-extensions), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | Anomaly |
| [Linux File Creation In Init Boot Directory](/endpoint/linux_file_creation_in_init_boot_directory/) | [RC Scripts](/tags/#rc-scripts), [Boot or Logon Initialization Scripts](/tags/#boot-or-logon-initialization-scripts) | Anomaly |
| [Linux File Creation In Profile Directory](/endpoint/linux_file_creation_in_profile_directory/) | [Unix Shell Configuration Modification](/tags/#unix-shell-configuration-modification), [Event Triggered Execution](/tags/#event-triggered-execution) | Anomaly |
| [Linux Insert Kernel Module Using Insmod Utility](/endpoint/linux_insert_kernel_module_using_insmod_utility/) | [Kernel Modules and Extensions](/tags/#kernel-modules-and-extensions), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | Anomaly |
| [Linux Install Kernel Module Using Modprobe Utility](/endpoint/linux_install_kernel_module_using_modprobe_utility/) | [Kernel Modules and Extensions](/tags/#kernel-modules-and-extensions), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | Anomaly |
| [Linux Java Spawning Shell](/endpoint/linux_java_spawning_shell/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | TTP |
| [Linux NOPASSWD Entry In Sudoers File](/endpoint/linux_nopasswd_entry_in_sudoers_file/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | Anomaly |
| [Linux Possible Access Or Modification Of sshd Config File](/endpoint/linux_possible_access_or_modification_of_sshd_config_file/) | [SSH Authorized Keys](/tags/#ssh-authorized-keys), [Account Manipulation](/tags/#account-manipulation) | Anomaly |
| [Linux Possible Access To Credential Files](/endpoint/linux_possible_access_to_credential_files/) | [/etc/passwd and /etc/shadow](/tags/#/etc/passwd-and-/etc/shadow), [OS Credential Dumping](/tags/#os-credential-dumping) | Anomaly |
| [Linux Possible Access To Sudoers File](/endpoint/linux_possible_access_to_sudoers_file/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | Anomaly |
| [Linux Possible Append Command To At Allow Config File](/endpoint/linux_possible_append_command_to_at_allow_config_file/) | [At (Linux)](/tags/#at-(linux)), [Scheduled Task/Job](/tags/#scheduled-task/job) | Anomaly |
| [Linux Possible Append Command To Profile Config File](/endpoint/linux_possible_append_command_to_profile_config_file/) | [Unix Shell Configuration Modification](/tags/#unix-shell-configuration-modification), [Event Triggered Execution](/tags/#event-triggered-execution) | Anomaly |
| [Linux Possible Append Cronjob Entry on Existing Cronjob File](/endpoint/linux_possible_append_cronjob_entry_on_existing_cronjob_file/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | Hunting |
| [Linux Possible Cronjob Modification With Editor](/endpoint/linux_possible_cronjob_modification_with_editor/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | Hunting |
| [Linux Possible Ssh Key File Creation](/endpoint/linux_possible_ssh_key_file_creation/) | [SSH Authorized Keys](/tags/#ssh-authorized-keys), [Account Manipulation](/tags/#account-manipulation) | Anomaly |
| [Linux Preload Hijack Library Calls](/endpoint/linux_preload_hijack_library_calls/) | [Dynamic Linker Hijacking](/tags/#dynamic-linker-hijacking), [Hijack Execution Flow](/tags/#hijack-execution-flow) | TTP |
| [Linux Service File Created In Systemd Directory](/endpoint/linux_service_file_created_in_systemd_directory/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job) | Anomaly |
| [Linux Service Restarted](/endpoint/linux_service_restarted/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job) | Anomaly |
| [Linux Service Started Or Enabled](/endpoint/linux_service_started_or_enabled/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job) | Anomaly |
| [Linux Setuid Using Chmod Utility](/endpoint/linux_setuid_using_chmod_utility/) | [Setuid and Setgid](/tags/#setuid-and-setgid), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | Anomaly |
| [Linux Setuid Using Setcap Utility](/endpoint/linux_setuid_using_setcap_utility/) | [Setuid and Setgid](/tags/#setuid-and-setgid), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | Anomaly |
| [Linux Sudo OR Su Execution](/endpoint/linux_sudo_or_su_execution/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | Hunting |
| [Linux Sudoers Tmp File Creation](/endpoint/linux_sudoers_tmp_file_creation/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | Anomaly |
| [Linux System Network Discovery](/endpoint/linux_system_network_discovery/) | [System Network Configuration Discovery](/tags/#system-network-configuration-discovery) | Anomaly |
| [Linux Visudo Utility Execution](/endpoint/linux_visudo_utility_execution/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | Anomaly |
| [Linux pkexec Privilege Escalation](/endpoint/linux_pkexec_privilege_escalation/) | [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation) | TTP |
| [Loading Of Dynwrapx Module](/endpoint/loading_of_dynwrapx_module/) | [Process Injection](/tags/#process-injection), [Dynamic-link Library Injection](/tags/#dynamic-link-library-injection) | TTP |
| [Local Account Discovery With Wmic](/endpoint/local_account_discovery_with_wmic/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account) | Hunting |
| [Local Account Discovery with Net](/endpoint/local_account_discovery_with_net/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account) | Hunting |
| [Log4Shell CVE-2021-44228 Exploitation](/endpoint/log4shell_cve-2021-44228_exploitation/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer), [Exploit Public-Facing Application](/tags/#exploit-public-facing-application), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | Correlation |
| [Log4Shell JNDI Payload Injection Attempt](/web/log4shell_jndi_payload_injection_attempt/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | Anomaly |
| [Log4Shell JNDI Payload Injection with Outbound Connection](/web/log4shell_jndi_payload_injection_with_outbound_connection/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | Anomaly |
| [Logon Script Event Trigger Execution](/endpoint/logon_script_event_trigger_execution/) | [Boot or Logon Initialization Scripts](/tags/#boot-or-logon-initialization-scripts), [Logon Script (Windows)](/tags/#logon-script-(windows)) | TTP |
| [MS Exchange Mailbox Replication service writing Active Server Pages](/endpoint/ms_exchange_mailbox_replication_service_writing_active_server_pages/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell), [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | TTP |
| [MS Scripting Process Loading Ldap Module](/endpoint/ms_scripting_process_loading_ldap_module/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [JavaScript](/tags/#javascript) | Anomaly |
| [MS Scripting Process Loading WMI Module](/endpoint/ms_scripting_process_loading_wmi_module/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [JavaScript](/tags/#javascript) | Anomaly |
| [MSBuild Suspicious Spawned By Script Process](/endpoint/msbuild_suspicious_spawned_by_script_process/) | [MSBuild](/tags/#msbuild), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution) | TTP |
| [MSHTML Module Load in Office Product](/endpoint/mshtml_module_load_in_office_product/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [MSI Module Loaded by Non-System Binary](/endpoint/msi_module_loaded_by_non-system_binary/) | [DLL Side-Loading](/tags/#dll-side-loading), [Hijack Execution Flow](/tags/#hijack-execution-flow) | Hunting |
| [MacOS - Re-opened Applications]() | None | TTP |
| [MacOS LOLbin](/endpoint/macos_lolbin/) | [Unix Shell](/tags/#unix-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | TTP |
| [Mailsniper Invoke functions](/endpoint/mailsniper_invoke_functions/) | [Email Collection](/tags/#email-collection), [Local Email Collection](/tags/#local-email-collection) | TTP |
| [Malicious InProcServer32 Modification](/endpoint/malicious_inprocserver32_modification/) | [Regsvr32](/tags/#regsvr32), [Modify Registry](/tags/#modify-registry) | TTP |
| [Malicious PowerShell Process - Encoded Command](/endpoint/malicious_powershell_process_-_encoded_command/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information) | Hunting |
| [Malicious PowerShell Process - Execution Policy Bypass](/endpoint/malicious_powershell_process_-_execution_policy_bypass/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | TTP |
| [Malicious PowerShell Process With Obfuscation Techniques](/endpoint/malicious_powershell_process_with_obfuscation_techniques/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | TTP |
| [Malicious Powershell Executed As A Service](/endpoint/malicious_powershell_executed_as_a_service/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | TTP |
| [Mimikatz PassTheTicket CommandLine Parameters](/endpoint/mimikatz_passtheticket_commandline_parameters/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material), [Pass the Ticket](/tags/#pass-the-ticket) | TTP |
| [Mmc LOLBAS Execution Process Spawn](/endpoint/mmc_lolbas_execution_process_spawn/) | [Remote Services](/tags/#remote-services), [Distributed Component Object Model](/tags/#distributed-component-object-model) | TTP |
| [Modification Of Wallpaper](/endpoint/modification_of_wallpaper/) | [Defacement](/tags/#defacement) | TTP |
| [Modify ACL permission To Files Or Folder](/endpoint/modify_acl_permission_to_files_or_folder/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | TTP |
| [Monitor DNS For Brand Abuse]() | None | TTP |
| [Monitor Email For Brand Abuse]() | None | TTP |
| [Monitor Registry Keys for Print Monitors](/endpoint/monitor_registry_keys_for_print_monitors/) | [Port Monitors](/tags/#port-monitors), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | TTP |
| [Monitor Web Traffic For Brand Abuse]() | None | TTP |
| [Mshta spawning Rundll32 OR Regsvr32 Process](/endpoint/mshta_spawning_rundll32_or_regsvr32_process/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Mshta](/tags/#mshta) | TTP |
| [Msmpeng Application DLL Side Loading](/endpoint/msmpeng_application_dll_side_loading/) | [DLL Side-Loading](/tags/#dll-side-loading), [Hijack Execution Flow](/tags/#hijack-execution-flow) | TTP |
| [Multiple Archive Files Http Post Traffic](/network/multiple_archive_files_http_post_traffic/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | TTP |
| [Multiple Invalid Users Failing To Authenticate From Host Using NTLM](/endpoint/multiple_invalid_users_failing_to_authenticate_from_host_using_ntlm/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | Anomaly |
| [Multiple Okta Users With Invalid Credentials From The Same IP](/application/multiple_okta_users_with_invalid_credentials_from_the_same_ip/) | [Valid Accounts](/tags/#valid-accounts), [Default Accounts](/tags/#default-accounts) | TTP |
| [Multiple Users Failing To Authenticate From Host Using Kerberos](/endpoint/multiple_users_failing_to_authenticate_from_host_using_kerberos/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | Anomaly |
| [Multiple Users Failing To Authenticate From Host Using NTLM](/endpoint/multiple_users_failing_to_authenticate_from_host_using_ntlm/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | Anomaly |
| [Multiple Users Failing To Authenticate From Process](/endpoint/multiple_users_failing_to_authenticate_from_process/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | Anomaly |
| [Multiple Users Remotely Failing To Authenticate From Host](/endpoint/multiple_users_remotely_failing_to_authenticate_from_host/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | Anomaly |
| [NET Profiler UAC bypass](/endpoint/net_profiler_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [NLTest Domain Trust Discovery](/endpoint/nltest_domain_trust_discovery/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | TTP |
| [Net Localgroup Discovery](/endpoint/net_localgroup_discovery/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | Hunting |
| [Network Connection Discovery With Arp](/endpoint/network_connection_discovery_with_arp/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | Hunting |
| [Network Connection Discovery With Net](/endpoint/network_connection_discovery_with_net/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | Hunting |
| [Network Connection Discovery With Netstat](/endpoint/network_connection_discovery_with_netstat/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | Hunting |
| [Network Discovery Using Route Windows App](/endpoint/network_discovery_using_route_windows_app/) | [System Network Configuration Discovery](/tags/#system-network-configuration-discovery), [Internet Connection Discovery](/tags/#internet-connection-discovery) | Hunting |
| [New container uploaded to AWS ECR](/cloud/new_container_uploaded_to_aws_ecr/) | [Implant Internal Image](/tags/#implant-internal-image) | Hunting |
| [Nishang PowershellTCPOneLine](/endpoint/nishang_powershelltcponeline/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | TTP |
| [No Windows Updates in a time frame]() | None | Hunting |
| [Non Chrome Process Accessing Chrome Default Dir](/endpoint/non_chrome_process_accessing_chrome_default_dir/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | Anomaly |
| [Non Firefox Process Access Firefox Profile Dir](/endpoint/non_firefox_process_access_firefox_profile_dir/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | Anomaly |
| [Ntdsutil Export NTDS](/endpoint/ntdsutil_export_ntds/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [O365 Add App Role Assignment Grant User](/cloud/o365_add_app_role_assignment_grant_user/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account) | TTP |
| [O365 Added Service Principal](/cloud/o365_added_service_principal/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account) | TTP |
| [O365 Bypass MFA via Trusted IP](/cloud/o365_bypass_mfa_via_trusted_ip/) | [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [O365 Disable MFA](/cloud/o365_disable_mfa/) | [Modify Authentication Process](/tags/#modify-authentication-process) | TTP |
| [O365 Excessive Authentication Failures Alert](/cloud/o365_excessive_authentication_failures_alert/) | [Brute Force](/tags/#brute-force) | Anomaly |
| [O365 Excessive SSO logon errors](/cloud/o365_excessive_sso_logon_errors/) | [Modify Authentication Process](/tags/#modify-authentication-process) | Anomaly |
| [O365 New Federated Domain Added](/cloud/o365_new_federated_domain_added/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account) | TTP |
| [O365 PST export alert](/cloud/o365_pst_export_alert/) | [Email Collection](/tags/#email-collection) | TTP |
| [O365 Suspicious Admin Email Forwarding](/cloud/o365_suspicious_admin_email_forwarding/) | [Email Forwarding Rule](/tags/#email-forwarding-rule), [Email Collection](/tags/#email-collection) | Anomaly |
| [O365 Suspicious Rights Delegation](/cloud/o365_suspicious_rights_delegation/) | [Remote Email Collection](/tags/#remote-email-collection), [Email Collection](/tags/#email-collection) | TTP |
| [O365 Suspicious User Email Forwarding](/cloud/o365_suspicious_user_email_forwarding/) | [Email Forwarding Rule](/tags/#email-forwarding-rule), [Email Collection](/tags/#email-collection) | Anomaly |
| [Office Application Drop Executable](/endpoint/office_application_drop_executable/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Application Spawn Regsvr32 process](/endpoint/office_application_spawn_regsvr32_process/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Application Spawn rundll32 process](/endpoint/office_application_spawn_rundll32_process/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Document Creating Schedule Task](/endpoint/office_document_creating_schedule_task/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Document Executing Macro Code](/endpoint/office_document_executing_macro_code/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Document Spawned Child Process To Download](/endpoint/office_document_spawned_child_process_to_download/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Product Spawn CMD Process](/endpoint/office_product_spawn_cmd_process/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Mshta](/tags/#mshta) | TTP |
| [Office Product Spawning BITSAdmin](/endpoint/office_product_spawning_bitsadmin/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Product Spawning CertUtil](/endpoint/office_product_spawning_certutil/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Product Spawning MSHTA](/endpoint/office_product_spawning_mshta/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Product Spawning Rundll32 with no DLL](/endpoint/office_product_spawning_rundll32_with_no_dll/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Product Spawning Wmic](/endpoint/office_product_spawning_wmic/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Product Writing cab or inf](/endpoint/office_product_writing_cab_or_inf/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Spawning Control](/endpoint/office_spawning_control/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Okta Account Lockout Events](/application/okta_account_lockout_events/) | [Valid Accounts](/tags/#valid-accounts), [Default Accounts](/tags/#default-accounts) | Anomaly |
| [Okta Failed SSO Attempts](/application/okta_failed_sso_attempts/) | [Valid Accounts](/tags/#valid-accounts), [Default Accounts](/tags/#default-accounts) | Anomaly |
| [Okta User Logins From Multiple Cities](/application/okta_user_logins_from_multiple_cities/) | [Valid Accounts](/tags/#valid-accounts), [Default Accounts](/tags/#default-accounts) | Anomaly |
| [Open Redirect in Splunk Web]() | None | TTP |
| [Osquery pack - ColdRoot detection]() | None | TTP |
| [Outbound Network Connection from Java Using Default Ports](/endpoint/outbound_network_connection_from_java_using_default_ports/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | TTP |
| [Overwriting Accessibility Binaries](/endpoint/overwriting_accessibility_binaries/) | [Event Triggered Execution](/tags/#event-triggered-execution), [Accessibility Features](/tags/#accessibility-features) | TTP |
| [Password Policy Discovery with Net](/endpoint/password_policy_discovery_with_net/) | [Password Policy Discovery](/tags/#password-policy-discovery) | Hunting |
| [Permission Modification using Takeown App](/endpoint/permission_modification_using_takeown_app/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | TTP |
| [PetitPotam Network Share Access Request](/endpoint/petitpotam_network_share_access_request/) | [Forced Authentication](/tags/#forced-authentication) | TTP |
| [PetitPotam Suspicious Kerberos TGT Request](/endpoint/petitpotam_suspicious_kerberos_tgt_request/) | [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Ping Sleep Batch Command](/endpoint/ping_sleep_batch_command/) | [Virtualization/Sandbox Evasion](/tags/#virtualization/sandbox-evasion), [Time Based Evasion](/tags/#time-based-evasion) | Anomaly |
| [Plain HTTP POST Exfiltrated Data](/network/plain_http_post_exfiltrated_data/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | TTP |
| [Possible Browser Pass View Parameter](/endpoint/possible_browser_pass_view_parameter/) | [Credentials from Web Browsers](/tags/#credentials-from-web-browsers), [Credentials from Password Stores](/tags/#credentials-from-password-stores) | Hunting |
| [Possible Lateral Movement PowerShell Spawn](/endpoint/possible_lateral_movement_powershell_spawn/) | [Remote Services](/tags/#remote-services), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Remote Management](/tags/#windows-remote-management), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Scheduled Task](/tags/#scheduled-task), [Windows Service](/tags/#windows-service), [PowerShell](/tags/#powershell) | TTP |
| [Potentially malicious code on commandline](/endpoint/potentially_malicious_code_on_commandline/) | [Windows Command Shell](/tags/#windows-command-shell) | Anomaly |
| [PowerShell - Connect To Internet With Hidden Window](/endpoint/powershell_-_connect_to_internet_with_hidden_window/) | [PowerShell](/tags/#powershell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | Hunting |
| [PowerShell 4104 Hunting](/endpoint/powershell_4104_hunting/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | Hunting |
| [PowerShell Domain Enumeration](/endpoint/powershell_domain_enumeration/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | TTP |
| [PowerShell Get LocalGroup Discovery](/endpoint/powershell_get_localgroup_discovery/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | Hunting |
| [PowerShell Loading DotNET into Memory via Reflection](/endpoint/powershell_loading_dotnet_into_memory_via_reflection/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | TTP |
| [PowerShell Start-BitsTransfer](/endpoint/powershell_start-bitstransfer/) | [BITS Jobs](/tags/#bits-jobs) | TTP |
| [Powershell Creating Thread Mutex](/endpoint/powershell_creating_thread_mutex/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information), [Indicator Removal from Tools](/tags/#indicator-removal-from-tools) | TTP |
| [Powershell Disable Security Monitoring](/endpoint/powershell_disable_security_monitoring/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Powershell Enable SMB1Protocol Feature](/endpoint/powershell_enable_smb1protocol_feature/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information), [Indicator Removal from Tools](/tags/#indicator-removal-from-tools) | TTP |
| [Powershell Execute COM Object](/endpoint/powershell_execute_com_object/) | [Component Object Model Hijacking](/tags/#component-object-model-hijacking), [Event Triggered Execution](/tags/#event-triggered-execution) | TTP |
| [Powershell Fileless Process Injection via GetProcAddress](/endpoint/powershell_fileless_process_injection_via_getprocaddress/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Process Injection](/tags/#process-injection), [PowerShell](/tags/#powershell) | TTP |
| [Powershell Fileless Script Contains Base64 Encoded Content](/endpoint/powershell_fileless_script_contains_base64_encoded_content/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Obfuscated Files or Information](/tags/#obfuscated-files-or-information), [PowerShell](/tags/#powershell) | TTP |
| [Powershell Get LocalGroup Discovery with Script Block Logging](/endpoint/powershell_get_localgroup_discovery_with_script_block_logging/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | Hunting |
| [Powershell Processing Stream Of Data](/endpoint/powershell_processing_stream_of_data/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | TTP |
| [Powershell Remote Thread To Known Windows Process](/endpoint/powershell_remote_thread_to_known_windows_process/) | [Process Injection](/tags/#process-injection) | TTP |
| [Powershell Remove Windows Defender Directory](/endpoint/powershell_remove_windows_defender_directory/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Powershell Using memory As Backing Store](/endpoint/powershell_using_memory_as_backing_store/) | [Deobfuscate/Decode Files or Information](/tags/#deobfuscate/decode-files-or-information) | TTP |
| [Powershell Windows Defender Exclusion Commands](/endpoint/powershell_windows_defender_exclusion_commands/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Prevent Automatic Repair Mode using Bcdedit](/endpoint/prevent_automatic_repair_mode_using_bcdedit/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | TTP |
| [Print Processor Registry Autostart](/endpoint/print_processor_registry_autostart/) | [Print Processors](/tags/#print-processors), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | TTP |
| [Print Spooler Adding A Printer Driver](/endpoint/print_spooler_adding_a_printer_driver/) | [Print Processors](/tags/#print-processors), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | TTP |
| [Print Spooler Failed to Load a Plug-in](/endpoint/print_spooler_failed_to_load_a_plug-in/) | [Print Processors](/tags/#print-processors), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | TTP |
| [Process Creating LNK file in Suspicious Location](/endpoint/process_creating_lnk_file_in_suspicious_location/) | [Phishing](/tags/#phishing), [Spearphishing Link](/tags/#spearphishing-link) | TTP |
| [Process Deleting Its Process File Path](/endpoint/process_deleting_its_process_file_path/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host) | TTP |
| [Process Execution via WMI](/endpoint/process_execution_via_wmi/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | TTP |
| [Process Kill Base On File Path](/endpoint/process_kill_base_on_file_path/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Process Writing DynamicWrapperX](/endpoint/process_writing_dynamicwrapperx/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Component Object Model](/tags/#component-object-model) | Hunting |
| [Processes Tapping Keyboard Events]() | None | TTP |
| [Processes created by netsh](/deprecated/processes_created_by_netsh/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall) | TTP |
| [Processes launching netsh](/endpoint/processes_launching_netsh/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Prohibited Network Traffic Allowed](/network/prohibited_network_traffic_allowed/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | TTP |
| [Prohibited Software On Endpoint]() | None | Hunting |
| [Protocol or Port Mismatch](/network/protocol_or_port_mismatch/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | Anomaly |
| [Protocols passing authentication in cleartext]() | None | TTP |
| [Randomly Generated Scheduled Task Name](/endpoint/randomly_generated_scheduled_task_name/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [Scheduled Task](/tags/#scheduled-task) | Hunting |
| [Randomly Generated Windows Service Name](/endpoint/randomly_generated_windows_service_name/) | [Create or Modify System Process](/tags/#create-or-modify-system-process), [Windows Service](/tags/#windows-service) | Hunting |
| [Ransomware Notes bulk creation](/endpoint/ransomware_notes_bulk_creation/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | Anomaly |
| [Recon AVProduct Through Pwh or WMI](/endpoint/recon_avproduct_through_pwh_or_wmi/) | [Gather Victim Host Information](/tags/#gather-victim-host-information) | TTP |
| [Recon Using WMI Class](/endpoint/recon_using_wmi_class/) | [Gather Victim Host Information](/tags/#gather-victim-host-information) | TTP |
| [Recursive Delete of Directory In Batch CMD](/endpoint/recursive_delete_of_directory_in_batch_cmd/) | [File Deletion](/tags/#file-deletion), [Indicator Removal on Host](/tags/#indicator-removal-on-host) | TTP |
| [Reg exe Manipulating Windows Services Registry Keys](/endpoint/reg_exe_manipulating_windows_services_registry_keys/) | [Services Registry Permissions Weakness](/tags/#services-registry-permissions-weakness), [Hijack Execution Flow](/tags/#hijack-execution-flow) | TTP |
| [Reg exe used to hide files directories via registry keys](/deprecated/reg_exe_used_to_hide_files_directories_via_registry_keys/) | [Hidden Files and Directories](/tags/#hidden-files-and-directories) | TTP |
| [Registry Keys Used For Persistence](/endpoint/registry_keys_used_for_persistence/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | TTP |
| [Registry Keys Used For Privilege Escalation](/endpoint/registry_keys_used_for_privilege_escalation/) | [Image File Execution Options Injection](/tags/#image-file-execution-options-injection), [Event Triggered Execution](/tags/#event-triggered-execution) | TTP |
| [Registry Keys for Creating SHIM Databases](/endpoint/registry_keys_for_creating_shim_databases/) | [Application Shimming](/tags/#application-shimming), [Event Triggered Execution](/tags/#event-triggered-execution) | TTP |
| [Regsvr32 Silent and Install Param Dll Loading](/endpoint/regsvr32_silent_and_install_param_dll_loading/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvr32](/tags/#regsvr32) | Anomaly |
| [Regsvr32 with Known Silent Switch Cmdline](/endpoint/regsvr32_with_known_silent_switch_cmdline/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvr32](/tags/#regsvr32) | Anomaly |
| [Remcos RAT File Creation in Remcos Folder](/endpoint/remcos_rat_file_creation_in_remcos_folder/) | [Screen Capture](/tags/#screen-capture) | TTP |
| [Remcos client registry install entry](/endpoint/remcos_client_registry_install_entry/) | [Modify Registry](/tags/#modify-registry) | TTP |
| [Remote Desktop Network Bruteforce](/network/remote_desktop_network_bruteforce/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services) | TTP |
| [Remote Desktop Network Traffic](/network/remote_desktop_network_traffic/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services) | Anomaly |
| [Remote Desktop Process Running On System](/endpoint/remote_desktop_process_running_on_system/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services) | Hunting |
| [Remote Process Instantiation via DCOM and PowerShell](/endpoint/remote_process_instantiation_via_dcom_and_powershell/) | [Remote Services](/tags/#remote-services), [Distributed Component Object Model](/tags/#distributed-component-object-model) | TTP |
| [Remote Process Instantiation via DCOM and PowerShell Script Block](/endpoint/remote_process_instantiation_via_dcom_and_powershell_script_block/) | [Remote Services](/tags/#remote-services), [Distributed Component Object Model](/tags/#distributed-component-object-model) | TTP |
| [Remote Process Instantiation via WMI](/endpoint/remote_process_instantiation_via_wmi/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | TTP |
| [Remote Process Instantiation via WMI and PowerShell](/endpoint/remote_process_instantiation_via_wmi_and_powershell/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | TTP |
| [Remote Process Instantiation via WMI and PowerShell Script Block](/endpoint/remote_process_instantiation_via_wmi_and_powershell_script_block/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | TTP |
| [Remote Process Instantiation via WinRM and PowerShell](/endpoint/remote_process_instantiation_via_winrm_and_powershell/) | [Remote Services](/tags/#remote-services), [Windows Remote Management](/tags/#windows-remote-management) | TTP |
| [Remote Process Instantiation via WinRM and PowerShell Script Block](/endpoint/remote_process_instantiation_via_winrm_and_powershell_script_block/) | [Remote Services](/tags/#remote-services), [Windows Remote Management](/tags/#windows-remote-management) | TTP |
| [Remote Process Instantiation via WinRM and Winrs](/endpoint/remote_process_instantiation_via_winrm_and_winrs/) | [Remote Services](/tags/#remote-services), [Windows Remote Management](/tags/#windows-remote-management) | TTP |
| [Remote Registry Key modifications]() | None | TTP |
| [Remote System Discovery with Adsisearcher](/endpoint/remote_system_discovery_with_adsisearcher/) | [Remote System Discovery](/tags/#remote-system-discovery) | TTP |
| [Remote System Discovery with Dsquery](/endpoint/remote_system_discovery_with_dsquery/) | [Remote System Discovery](/tags/#remote-system-discovery) | Hunting |
| [Remote System Discovery with Net](/endpoint/remote_system_discovery_with_net/) | [Remote System Discovery](/tags/#remote-system-discovery) | Hunting |
| [Remote System Discovery with Wmic](/endpoint/remote_system_discovery_with_wmic/) | [Remote System Discovery](/tags/#remote-system-discovery) | TTP |
| [Remote WMI Command Attempt](/endpoint/remote_wmi_command_attempt/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | TTP |
| [Resize ShadowStorage volume](/endpoint/resize_shadowstorage_volume/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | TTP |
| [Revil Common Exec Parameter](/endpoint/revil_common_exec_parameter/) | [User Execution](/tags/#user-execution) | TTP |
| [Revil Registry Entry](/endpoint/revil_registry_entry/) | [Modify Registry](/tags/#modify-registry) | TTP |
| [Rubeus Command Line Parameters](/endpoint/rubeus_command_line_parameters/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material), [Pass the Ticket](/tags/#pass-the-ticket), [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Kerberoasting](/tags/#kerberoasting), [AS-REP Roasting](/tags/#as-rep-roasting) | TTP |
| [Rubeus Kerberos Ticket Exports Through Winlogon Access](/endpoint/rubeus_kerberos_ticket_exports_through_winlogon_access/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material), [Pass the Ticket](/tags/#pass-the-ticket) | TTP |
| [RunDLL Loading DLL By Ordinal](/endpoint/rundll_loading_dll_by_ordinal/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32) | TTP |
| [Runas Execution in CommandLine](/endpoint/runas_execution_in_commandline/) | [Access Token Manipulation](/tags/#access-token-manipulation), [Token Impersonation/Theft](/tags/#token-impersonation/theft) | Hunting |
| [Rundll32 Control RunDLL Hunt](/endpoint/rundll32_control_rundll_hunt/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32) | Hunting |
| [Rundll32 Control RunDLL World Writable Directory](/endpoint/rundll32_control_rundll_world_writable_directory/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32) | TTP |
| [Rundll32 Create Remote Thread To A Process](/endpoint/rundll32_create_remote_thread_to_a_process/) | [Process Injection](/tags/#process-injection) | TTP |
| [Rundll32 CreateRemoteThread In Browser](/endpoint/rundll32_createremotethread_in_browser/) | [Process Injection](/tags/#process-injection) | TTP |
| [Rundll32 DNSQuery](/endpoint/rundll32_dnsquery/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32) | TTP |
| [Rundll32 Process Creating Exe Dll Files](/endpoint/rundll32_process_creating_exe_dll_files/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32) | TTP |
| [Rundll32 Shimcache Flush](/endpoint/rundll32_shimcache_flush/) | [Modify Registry](/tags/#modify-registry) | TTP |
| [Rundll32 with no Command Line Arguments with Network](/endpoint/rundll32_with_no_command_line_arguments_with_network/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32) | TTP |
| [Ryuk Test Files Detected](/endpoint/ryuk_test_files_detected/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | TTP |
| [Ryuk Wake on LAN Command](/endpoint/ryuk_wake_on_lan_command/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Windows Command Shell](/tags/#windows-command-shell) | TTP |
| [SAM Database File Access Attempt](/endpoint/sam_database_file_access_attempt/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | Hunting |
| [SLUI RunAs Elevated](/endpoint/slui_runas_elevated/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [SLUI Spawning a Process](/endpoint/slui_spawning_a_process/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [SMB Traffic Spike](/network/smb_traffic_spike/) | [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Remote Services](/tags/#remote-services) | Anomaly |
| [SMB Traffic Spike - MLTK](/network/smb_traffic_spike_-_mltk/) | [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Remote Services](/tags/#remote-services) | Anomaly |
| [SQL Injection with Long URLs](/web/sql_injection_with_long_urls/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | TTP |
| [Samsam Test File Write](/endpoint/samsam_test_file_write/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | TTP |
| [Sc exe Manipulating Windows Services](/endpoint/sc_exe_manipulating_windows_services/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process) | TTP |
| [SchCache Change By App Connect And Create ADSI Object](/endpoint/schcache_change_by_app_connect_and_create_adsi_object/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | Anomaly |
| [Schedule Task with HTTP Command Arguments](/endpoint/schedule_task_with_http_command_arguments/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | TTP |
| [Schedule Task with Rundll32 Command Trigger](/endpoint/schedule_task_with_rundll32_command_trigger/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | TTP |
| [Scheduled Task Creation on Remote Endpoint using At](/endpoint/scheduled_task_creation_on_remote_endpoint_using_at/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [At (Windows)](/tags/#at-(windows)) | TTP |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/scheduled_task_deleted_or_created_via_cmd/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | TTP |
| [Scheduled Task Initiation on Remote Endpoint](/endpoint/scheduled_task_initiation_on_remote_endpoint/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [Scheduled Task](/tags/#scheduled-task) | TTP |
| [Scheduled tasks used in BadRabbit ransomware](/deprecated/scheduled_tasks_used_in_badrabbit_ransomware/) | [Scheduled Task](/tags/#scheduled-task) | TTP |
| [Schtasks Run Task On Demand](/endpoint/schtasks_run_task_on_demand/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | TTP |
| [Schtasks scheduling job on remote system](/endpoint/schtasks_scheduling_job_on_remote_system/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | TTP |
| [Schtasks used for forcing a reboot](/endpoint/schtasks_used_for_forcing_a_reboot/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | TTP |
| [Screensaver Event Trigger Execution](/endpoint/screensaver_event_trigger_execution/) | [Event Triggered Execution](/tags/#event-triggered-execution), [Screensaver](/tags/#screensaver) | TTP |
| [Script Execution via WMI](/endpoint/script_execution_via_wmi/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | TTP |
| [Sdclt UAC Bypass](/endpoint/sdclt_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Sdelete Application Execution](/endpoint/sdelete_application_execution/) | [Data Destruction](/tags/#data-destruction), [File Deletion](/tags/#file-deletion), [Indicator Removal on Host](/tags/#indicator-removal-on-host) | TTP |
| [SearchProtocolHost with no Command Line with Network](/endpoint/searchprotocolhost_with_no_command_line_with_network/) | [Process Injection](/tags/#process-injection) | TTP |
| [SecretDumps Offline NTDS Dumping Tool](/endpoint/secretdumps_offline_ntds_dumping_tool/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [ServicePrincipalNames Discovery with PowerShell](/endpoint/serviceprincipalnames_discovery_with_powershell/) | [Kerberoasting](/tags/#kerberoasting) | TTP |
| [ServicePrincipalNames Discovery with SetSPN](/endpoint/serviceprincipalnames_discovery_with_setspn/) | [Kerberoasting](/tags/#kerberoasting) | TTP |
| [Services Escalate Exe](/endpoint/services_escalate_exe/) | [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Services LOLBAS Execution Process Spawn](/endpoint/services_lolbas_execution_process_spawn/) | [Create or Modify System Process](/tags/#create-or-modify-system-process), [Windows Service](/tags/#windows-service) | TTP |
| [Set Default PowerShell Execution Policy To Unrestricted or Bypass](/endpoint/set_default_powershell_execution_policy_to_unrestricted_or_bypass/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | TTP |
| [Shim Database File Creation](/endpoint/shim_database_file_creation/) | [Application Shimming](/tags/#application-shimming), [Event Triggered Execution](/tags/#event-triggered-execution) | TTP |
| [Shim Database Installation With Suspicious Parameters](/endpoint/shim_database_installation_with_suspicious_parameters/) | [Application Shimming](/tags/#application-shimming), [Event Triggered Execution](/tags/#event-triggered-execution) | TTP |
| [Short Lived Scheduled Task](/endpoint/short_lived_scheduled_task/) | [Scheduled Task](/tags/#scheduled-task) | TTP |
| [Short Lived Windows Accounts](/endpoint/short_lived_windows_accounts/) | [Local Account](/tags/#local-account), [Create Account](/tags/#create-account) | TTP |
| [SilentCleanup UAC Bypass](/endpoint/silentcleanup_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Single Letter Process On Endpoint](/endpoint/single_letter_process_on_endpoint/) | [User Execution](/tags/#user-execution), [Malicious File](/tags/#malicious-file) | TTP |
| [Spectre and Meltdown Vulnerable Systems]() | None | TTP |
| [Spike in File Writes]() | None | Anomaly |
| [Splunk Enterprise Information Disclosure]() | None | TTP |
| [Spoolsv Spawning Rundll32](/endpoint/spoolsv_spawning_rundll32/) | [Print Processors](/tags/#print-processors), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | TTP |
| [Spoolsv Suspicious Loaded Modules](/endpoint/spoolsv_suspicious_loaded_modules/) | [Print Processors](/tags/#print-processors), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | TTP |
| [Spoolsv Suspicious Process Access](/endpoint/spoolsv_suspicious_process_access/) | [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation) | TTP |
| [Spoolsv Writing a DLL](/endpoint/spoolsv_writing_a_dll/) | [Print Processors](/tags/#print-processors), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | TTP |
| [Spoolsv Writing a DLL - Sysmon](/endpoint/spoolsv_writing_a_dll_-_sysmon/) | [Print Processors](/tags/#print-processors), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | TTP |
| [Sqlite Module In Temp Folder](/endpoint/sqlite_module_in_temp_folder/) | [Data from Local System](/tags/#data-from-local-system) | TTP |
| [Start Up During Safe Mode Boot](/endpoint/start_up_during_safe_mode_boot/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | TTP |
| [Sunburst Correlation DLL and Network Event](/endpoint/sunburst_correlation_dll_and_network_event/) | [Exploitation for Client Execution](/tags/#exploitation-for-client-execution) | TTP |
| [Supernova Webshell](/web/supernova_webshell/) | [Web Shell](/tags/#web-shell) | TTP |
| [Suspicious Changes to File Associations](/deprecated/suspicious_changes_to_file_associations/) | [Change Default File Association](/tags/#change-default-file-association) | TTP |
| [Suspicious Computer Account Name Change](/endpoint/suspicious_computer_account_name_change/) | [Valid Accounts](/tags/#valid-accounts), [Domain Accounts](/tags/#domain-accounts) | TTP |
| [Suspicious Copy on System32](/endpoint/suspicious_copy_on_system32/) | [Rename System Utilities](/tags/#rename-system-utilities), [Masquerading](/tags/#masquerading) | TTP |
| [Suspicious Curl Network Connection](/endpoint/suspicious_curl_network_connection/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | TTP |
| [Suspicious DLLHost no Command Line Arguments](/endpoint/suspicious_dllhost_no_command_line_arguments/) | [Process Injection](/tags/#process-injection) | TTP |
| [Suspicious Driver Loaded Path](/endpoint/suspicious_driver_loaded_path/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process) | TTP |
| [Suspicious Email - UBA Anomaly](/deprecated/suspicious_email_-_uba_anomaly/) | [Phishing](/tags/#phishing) | Anomaly |
| [Suspicious Email Attachment Extensions](/application/suspicious_email_attachment_extensions/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing) | Anomaly |
| [Suspicious Event Log Service Behavior](/endpoint/suspicious_event_log_service_behavior/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host), [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | TTP |
| [Suspicious File Write]() | None | Hunting |
| [Suspicious GPUpdate no Command Line Arguments](/endpoint/suspicious_gpupdate_no_command_line_arguments/) | [Process Injection](/tags/#process-injection) | TTP |
| [Suspicious IcedID Rundll32 Cmdline](/endpoint/suspicious_icedid_rundll32_cmdline/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32) | TTP |
| [Suspicious Image Creation In Appdata Folder](/endpoint/suspicious_image_creation_in_appdata_folder/) | [Screen Capture](/tags/#screen-capture) | TTP |
| [Suspicious Java Classes]() | None | Anomaly |
| [Suspicious Kerberos Service Ticket Request](/endpoint/suspicious_kerberos_service_ticket_request/) | [Valid Accounts](/tags/#valid-accounts), [Domain Accounts](/tags/#domain-accounts) | TTP |
| [Suspicious Linux Discovery Commands](/endpoint/suspicious_linux_discovery_commands/) | [Unix Shell](/tags/#unix-shell) | TTP |
| [Suspicious MSBuild Rename](/endpoint/suspicious_msbuild_rename/) | [Masquerading](/tags/#masquerading), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities), [MSBuild](/tags/#msbuild) | TTP |
| [Suspicious MSBuild Spawn](/endpoint/suspicious_msbuild_spawn/) | [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [MSBuild](/tags/#msbuild) | TTP |
| [Suspicious PlistBuddy Usage](/endpoint/suspicious_plistbuddy_usage/) | [Launch Agent](/tags/#launch-agent), [Create or Modify System Process](/tags/#create-or-modify-system-process) | TTP |
| [Suspicious PlistBuddy Usage via OSquery](/endpoint/suspicious_plistbuddy_usage_via_osquery/) | [Launch Agent](/tags/#launch-agent), [Create or Modify System Process](/tags/#create-or-modify-system-process) | TTP |
| [Suspicious Powershell Command-Line Arguments](/deprecated/suspicious_powershell_command-line_arguments/) | [PowerShell](/tags/#powershell) | TTP |
| [Suspicious Process DNS Query Known Abuse Web Services](/endpoint/suspicious_process_dns_query_known_abuse_web_services/) | [Visual Basic](/tags/#visual-basic), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | TTP |
| [Suspicious Process File Path](/endpoint/suspicious_process_file_path/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | TTP |
| [Suspicious Process With Discord DNS Query](/endpoint/suspicious_process_with_discord_dns_query/) | [Visual Basic](/tags/#visual-basic), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | Anomaly |
| [Suspicious Reg exe Process](/endpoint/suspicious_reg_exe_process/) | [Modify Registry](/tags/#modify-registry) | TTP |
| [Suspicious Regsvr32 Register Suspicious Path](/endpoint/suspicious_regsvr32_register_suspicious_path/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvr32](/tags/#regsvr32) | TTP |
| [Suspicious Rundll32 PluginInit](/endpoint/suspicious_rundll32_plugininit/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32) | TTP |
| [Suspicious Rundll32 Rename](/deprecated/suspicious_rundll32_rename/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Masquerading](/tags/#masquerading), [Rundll32](/tags/#rundll32), [Rename System Utilities](/tags/#rename-system-utilities) | Hunting |
| [Suspicious Rundll32 StartW](/endpoint/suspicious_rundll32_startw/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32) | TTP |
| [Suspicious Rundll32 dllregisterserver](/endpoint/suspicious_rundll32_dllregisterserver/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32) | TTP |
| [Suspicious Rundll32 no Command Line Arguments](/endpoint/suspicious_rundll32_no_command_line_arguments/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32) | TTP |
| [Suspicious SQLite3 LSQuarantine Behavior](/endpoint/suspicious_sqlite3_lsquarantine_behavior/) | [Data Staged](/tags/#data-staged) | TTP |
| [Suspicious Scheduled Task from Public Directory](/endpoint/suspicious_scheduled_task_from_public_directory/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | Anomaly |
| [Suspicious SearchProtocolHost no Command Line Arguments](/endpoint/suspicious_searchprotocolhost_no_command_line_arguments/) | [Process Injection](/tags/#process-injection) | TTP |
| [Suspicious Ticket Granting Ticket Request](/endpoint/suspicious_ticket_granting_ticket_request/) | [Valid Accounts](/tags/#valid-accounts), [Domain Accounts](/tags/#domain-accounts) | Hunting |
| [Suspicious WAV file in Appdata Folder](/endpoint/suspicious_wav_file_in_appdata_folder/) | [Screen Capture](/tags/#screen-capture) | TTP |
| [Suspicious microsoft workflow compiler rename](/endpoint/suspicious_microsoft_workflow_compiler_rename/) | [Masquerading](/tags/#masquerading), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities) | Hunting |
| [Suspicious microsoft workflow compiler usage](/endpoint/suspicious_microsoft_workflow_compiler_usage/) | [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution) | TTP |
| [Suspicious msbuild path](/endpoint/suspicious_msbuild_path/) | [Masquerading](/tags/#masquerading), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities), [MSBuild](/tags/#msbuild) | TTP |
| [Suspicious mshta child process](/endpoint/suspicious_mshta_child_process/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Mshta](/tags/#mshta) | TTP |
| [Suspicious mshta spawn](/endpoint/suspicious_mshta_spawn/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Mshta](/tags/#mshta) | TTP |
| [Suspicious wevtutil Usage](/endpoint/suspicious_wevtutil_usage/) | [Clear Windows Event Logs](/tags/#clear-windows-event-logs), [Indicator Removal on Host](/tags/#indicator-removal-on-host) | TTP |
| [Suspicious writes to System Volume Information](/deprecated/suspicious_writes_to_system_volume_information/) | [Masquerading](/tags/#masquerading) | Hunting |
| [Suspicious writes to windows Recycle Bin](/endpoint/suspicious_writes_to_windows_recycle_bin/) | [Masquerading](/tags/#masquerading) | TTP |
| [Svchost LOLBAS Execution Process Spawn](/endpoint/svchost_lolbas_execution_process_spawn/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [Scheduled Task](/tags/#scheduled-task) | TTP |
| [System Info Gathering Using Dxdiag Application](/endpoint/system_info_gathering_using_dxdiag_application/) | [Gather Victim Host Information](/tags/#gather-victim-host-information) | Hunting |
| [System Information Discovery Detection](/endpoint/system_information_discovery_detection/) | [System Information Discovery](/tags/#system-information-discovery) | TTP |
| [System Processes Run From Unexpected Locations](/endpoint/system_processes_run_from_unexpected_locations/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities) | TTP |
| [System User Discovery With Query](/endpoint/system_user_discovery_with_query/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | Hunting |
| [System User Discovery With Whoami](/endpoint/system_user_discovery_with_whoami/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | Hunting |
| [TOR Traffic](/network/tor_traffic/) | [Application Layer Protocol](/tags/#application-layer-protocol), [Web Protocols](/tags/#web-protocols) | TTP |
| [Time Provider Persistence Registry](/endpoint/time_provider_persistence_registry/) | [Time Providers](/tags/#time-providers), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | TTP |
| [Trickbot Named Pipe](/endpoint/trickbot_named_pipe/) | [Process Injection](/tags/#process-injection) | TTP |
| [UAC Bypass MMC Load Unsigned Dll](/endpoint/uac_bypass_mmc_load_unsigned_dll/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [UAC Bypass With Colorui COM Object](/endpoint/uac_bypass_with_colorui_com_object/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [CMSTP](/tags/#cmstp) | TTP |
| [USN Journal Deletion](/endpoint/usn_journal_deletion/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host) | TTP |
| [Uncommon Processes On Endpoint](/deprecated/uncommon_processes_on_endpoint/) | [Malicious File](/tags/#malicious-file) | Hunting |
| [Unified Messaging Service Spawning a Process](/endpoint/unified_messaging_service_spawning_a_process/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | TTP |
| [Uninstall App Using MsiExec](/endpoint/uninstall_app_using_msiexec/) | [Msiexec](/tags/#msiexec), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution) | TTP |
| [Unload Sysmon Filter Driver](/endpoint/unload_sysmon_filter_driver/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Unloading AMSI via Reflection](/endpoint/unloading_amsi_via_reflection/) | [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Unsigned Image Loaded by LSASS](/deprecated/unsigned_image_loaded_by_lsass/) | [LSASS Memory](/tags/#lsass-memory) | TTP |
| [Unsuccessful Netbackup backups]() | None | Hunting |
| [Unusual Number of Computer Service Tickets Requested](/endpoint/unusual_number_of_computer_service_tickets_requested/) | [Valid Accounts](/tags/#valid-accounts) | Hunting |
| [Unusual Number of Kerberos Service Tickets Requested](/endpoint/unusual_number_of_kerberos_service_tickets_requested/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Kerberoasting](/tags/#kerberoasting) | Anomaly |
| [Unusual Number of Remote Endpoint Authentication Events](/endpoint/unusual_number_of_remote_endpoint_authentication_events/) | [Valid Accounts](/tags/#valid-accounts) | Hunting |
| [Unusually Long Command Line]() | None | Anomaly |
| [Unusually Long Command Line - MLTK]() | None | Anomaly |
| [Unusually Long Content-Type Length]() | None | Anomaly |
| [User Discovery With Env Vars PowerShell](/endpoint/user_discovery_with_env_vars_powershell/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | Hunting |
| [User Discovery With Env Vars PowerShell Script Block](/endpoint/user_discovery_with_env_vars_powershell_script_block/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | Hunting |
| [Vbscript Execution Using Wscript App](/endpoint/vbscript_execution_using_wscript_app/) | [Visual Basic](/tags/#visual-basic), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | TTP |
| [Verclsid CLSID Execution](/endpoint/verclsid_clsid_execution/) | [Verclsid](/tags/#verclsid), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution) | Hunting |
| [W3WP Spawning Shell](/endpoint/w3wp_spawning_shell/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell) | TTP |
| [WBAdmin Delete System Backups](/endpoint/wbadmin_delete_system_backups/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | TTP |
| [WMI Permanent Event Subscription](/endpoint/wmi_permanent_event_subscription/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | TTP |
| [WMI Permanent Event Subscription - Sysmon](/endpoint/wmi_permanent_event_subscription_-_sysmon/) | [Windows Management Instrumentation Event Subscription](/tags/#windows-management-instrumentation-event-subscription), [Event Triggered Execution](/tags/#event-triggered-execution) | TTP |
| [WMI Recon Running Process Or Services](/endpoint/wmi_recon_running_process_or_services/) | [Gather Victim Host Information](/tags/#gather-victim-host-information) | TTP |
| [WMI Temporary Event Subscription](/endpoint/wmi_temporary_event_subscription/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | TTP |
| [WMIC XSL Execution via URL](/endpoint/wmic_xsl_execution_via_url/) | [XSL Script Processing](/tags/#xsl-script-processing) | TTP |
| [WSReset UAC Bypass](/endpoint/wsreset_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Wbemprox COM Object Execution](/endpoint/wbemprox_com_object_execution/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [CMSTP](/tags/#cmstp) | TTP |
| [Web Fraud - Account Harvesting](/deprecated/web_fraud_-_account_harvesting/) | [Create Account](/tags/#create-account) | TTP |
| [Web Fraud - Anomalous User Clickspeed](/deprecated/web_fraud_-_anomalous_user_clickspeed/) | [Valid Accounts](/tags/#valid-accounts) | Anomaly |
| [Web Fraud - Password Sharing Across Accounts]() | None | Anomaly |
| [Web Servers Executing Suspicious Processes](/application/web_servers_executing_suspicious_processes/) | [System Information Discovery](/tags/#system-information-discovery) | TTP |
| [Wermgr Process Connecting To IP Check Web Services](/endpoint/wermgr_process_connecting_to_ip_check_web_services/) | [Gather Victim Network Information](/tags/#gather-victim-network-information), [IP Addresses](/tags/#ip-addresses) | TTP |
| [Wermgr Process Create Executable File](/endpoint/wermgr_process_create_executable_file/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information) | TTP |
| [Wermgr Process Spawned CMD Or Powershell Process](/endpoint/wermgr_process_spawned_cmd_or_powershell_process/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | TTP |
| [Wget Download and Bash Execution](/endpoint/wget_download_and_bash_execution/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | TTP |
| [WinEvent Scheduled Task Created Within Public Path](/endpoint/winevent_scheduled_task_created_within_public_path/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | TTP |
| [WinEvent Scheduled Task Created to Spawn Shell](/endpoint/winevent_scheduled_task_created_to_spawn_shell/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | TTP |
| [WinEvent Windows Task Scheduler Event Action Started](/endpoint/winevent_windows_task_scheduler_event_action_started/) | [Scheduled Task](/tags/#scheduled-task) | Hunting |
| [WinRM Spawning a Process](/endpoint/winrm_spawning_a_process/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | TTP |
| [Windows AdFind Exe](/endpoint/windows_adfind_exe/) | [Remote System Discovery](/tags/#remote-system-discovery) | TTP |
| [Windows Curl Download to Suspicious Path](/endpoint/windows_curl_download_to_suspicious_path/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | TTP |
| [Windows Curl Upload to Remote Destination](/endpoint/windows_curl_upload_to_remote_destination/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | TTP |
| [Windows DISM Remove Defender](/endpoint/windows_dism_remove_defender/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Windows Defender Exclusion Registry Entry](/endpoint/windows_defender_exclusion_registry_entry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Windows Disable Change Password Through Registry](/endpoint/windows_disable_change_password_through_registry/) | [Modify Registry](/tags/#modify-registry) | Anomaly |
| [Windows Disable Lock Workstation Feature Through Registry](/endpoint/windows_disable_lock_workstation_feature_through_registry/) | [Modify Registry](/tags/#modify-registry) | Anomaly |
| [Windows Disable LogOff Button Through Registry](/endpoint/windows_disable_logoff_button_through_registry/) | [Modify Registry](/tags/#modify-registry) | Anomaly |
| [Windows Disable Memory Crash Dump](/endpoint/windows_disable_memory_crash_dump/) | [Data Destruction](/tags/#data-destruction) | TTP |
| [Windows Disable Notification Center](/endpoint/windows_disable_notification_center/) | [Modify Registry](/tags/#modify-registry) | Anomaly |
| [Windows Disable Shutdown Button Through Registry](/endpoint/windows_disable_shutdown_button_through_registry/) | [Modify Registry](/tags/#modify-registry) | Anomaly |
| [Windows Disable Windows Group Policy Features Through Registry](/endpoint/windows_disable_windows_group_policy_features_through_registry/) | [Modify Registry](/tags/#modify-registry) | Anomaly |
| [Windows DisableAntiSpyware Registry](/endpoint/windows_disableantispyware_registry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Windows Disabled Users Failing To Authenticate Kerberos](/endpoint/windows_disabled_users_failing_to_authenticate_kerberos/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | Anomaly |
| [Windows DiskCryptor Usage](/endpoint/windows_diskcryptor_usage/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | Hunting |
| [Windows Diskshadow Proxy Execution](/endpoint/windows_diskshadow_proxy_execution/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution) | TTP |
| [Windows DotNet Binary in Non Standard Path](/endpoint/windows_dotnet_binary_in_non_standard_path/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [InstallUtil](/tags/#installutil) | TTP |
| [Windows Event For Service Disabled](/endpoint/windows_event_for_service_disabled/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | Hunting |
| [Windows Event Log Cleared](/endpoint/windows_event_log_cleared/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host), [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | TTP |
| [Windows Excessive Disabled Services Event](/endpoint/windows_excessive_disabled_services_event/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Windows File Without Extension In Critical Folder](/endpoint/windows_file_without_extension_in_critical_folder/) | [Data Destruction](/tags/#data-destruction) | TTP |
| [Windows Hide Notification Features Through Registry](/endpoint/windows_hide_notification_features_through_registry/) | [Modify Registry](/tags/#modify-registry) | Anomaly |
| [Windows High File Deletion Frequency](/endpoint/windows_high_file_deletion_frequency/) | [Data Destruction](/tags/#data-destruction) | Anomaly |
| [Windows Hunting System Account Targeting Lsass](/endpoint/windows_hunting_system_account_targeting_lsass/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | Hunting |
| [Windows InstallUtil Credential Theft](/endpoint/windows_installutil_credential_theft/) | [InstallUtil](/tags/#installutil), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution) | TTP |
| [Windows InstallUtil Remote Network Connection](/endpoint/windows_installutil_remote_network_connection/) | [InstallUtil](/tags/#installutil), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution) | TTP |
| [Windows InstallUtil URL in Command Line](/endpoint/windows_installutil_url_in_command_line/) | [InstallUtil](/tags/#installutil), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution) | TTP |
| [Windows InstallUtil Uninstall Option](/endpoint/windows_installutil_uninstall_option/) | [InstallUtil](/tags/#installutil), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution) | TTP |
| [Windows InstallUtil Uninstall Option with Network](/endpoint/windows_installutil_uninstall_option_with_network/) | [InstallUtil](/tags/#installutil), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution) | TTP |
| [Windows InstallUtil in Non Standard Path](/endpoint/windows_installutil_in_non_standard_path/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [InstallUtil](/tags/#installutil) | TTP |
| [Windows Invalid Users Failed Authentication via Kerberos](/endpoint/windows_invalid_users_failed_authentication_via_kerberos/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | Anomaly |
| [Windows Java Spawning Shells](/endpoint/windows_java_spawning_shells/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | TTP |
| [Windows Modify Show Compress Color And Info Tip Registry](/endpoint/windows_modify_show_compress_color_and_info_tip_registry/) | [Modify Registry](/tags/#modify-registry) | TTP |
| [Windows NirSoft AdvancedRun](/endpoint/windows_nirsoft_advancedrun/) | [Tool](/tags/#tool) | TTP |
| [Windows NirSoft Utilities](/endpoint/windows_nirsoft_utilities/) | [Tool](/tags/#tool) | Hunting |
| [Windows Non-System Account Targeting Lsass](/endpoint/windows_non-system_account_targeting_lsass/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Windows Possible Credential Dumping](/endpoint/windows_possible_credential_dumping/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | TTP |
| [Windows Process With NamedPipe CommandLine](/endpoint/windows_process_with_namedpipe_commandline/) | [Process Injection](/tags/#process-injection) | Anomaly |
| [Windows Raccine Scheduled Task Deletion](/endpoint/windows_raccine_scheduled_task_deletion/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools) | TTP |
| [Windows Rasautou DLL Execution](/endpoint/windows_rasautou_dll_execution/) | [Dynamic-link Library Injection](/tags/#dynamic-link-library-injection), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Process Injection](/tags/#process-injection) | TTP |
| [Windows Raw Access To Disk Volume Partition](/endpoint/windows_raw_access_to_disk_volume_partition/) | [Disk Structure Wipe](/tags/#disk-structure-wipe), [Disk Wipe](/tags/#disk-wipe) | Anomaly |
| [Windows Raw Access To Master Boot Record Drive](/endpoint/windows_raw_access_to_master_boot_record_drive/) | [Disk Structure Wipe](/tags/#disk-structure-wipe), [Disk Wipe](/tags/#disk-wipe) | TTP |
| [Windows Remote Assistance Spawning Process](/endpoint/windows_remote_assistance_spawning_process/) | [Process Injection](/tags/#process-injection) | TTP |
| [Windows Schtasks Create Run As System](/endpoint/windows_schtasks_create_run_as_system/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | TTP |
| [Windows Security Account Manager Stopped](/endpoint/windows_security_account_manager_stopped/) | [Service Stop](/tags/#service-stop) | TTP |
| [Windows Service Created With Suspicious Service Path](/endpoint/windows_service_created_with_suspicious_service_path/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | TTP |
| [Windows Service Created Within Public Path](/endpoint/windows_service_created_within_public_path/) | [Create or Modify System Process](/tags/#create-or-modify-system-process), [Windows Service](/tags/#windows-service) | TTP |
| [Windows Service Creation Using Registry Entry](/endpoint/windows_service_creation_using_registry_entry/) | [Services Registry Permissions Weakness](/tags/#services-registry-permissions-weakness) | TTP |
| [Windows Service Creation on Remote Endpoint](/endpoint/windows_service_creation_on_remote_endpoint/) | [Create or Modify System Process](/tags/#create-or-modify-system-process), [Windows Service](/tags/#windows-service) | TTP |
| [Windows Service Initiation on Remote Endpoint](/endpoint/windows_service_initiation_on_remote_endpoint/) | [Create or Modify System Process](/tags/#create-or-modify-system-process), [Windows Service](/tags/#windows-service) | TTP |
| [Windows Users Authenticate Using Explicit Credentials](/endpoint/windows_users_authenticate_using_explicit_credentials/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | Anomaly |
| [Windows WMI Process Call Create](/endpoint/windows_wmi_process_call_create/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | Hunting |
| [Windows connhost exe started forcefully](/deprecated/windows_connhost_exe_started_forcefully/) | [Windows Command Shell](/tags/#windows-command-shell) | TTP |
| [Windows hosts file modification]() | None | TTP |
| [Winhlp32 Spawning a Process](/endpoint/winhlp32_spawning_a_process/) | [Process Injection](/tags/#process-injection) | TTP |
| [Winword Spawning Cmd](/endpoint/winword_spawning_cmd/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Winword Spawning PowerShell](/endpoint/winword_spawning_powershell/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Winword Spawning Windows Script Host](/endpoint/winword_spawning_windows_script_host/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Wmic Group Discovery](/endpoint/wmic_group_discovery/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | Hunting |
| [Wmic NonInteractive App Uninstallation](/endpoint/wmic_noninteractive_app_uninstallation/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | Hunting |
| [Wmiprsve LOLBAS Execution Process Spawn](/endpoint/wmiprsve_lolbas_execution_process_spawn/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | TTP |
| [Wscript Or Cscript Suspicious Child Process](/endpoint/wscript_or_cscript_suspicious_child_process/) | [Process Injection](/tags/#process-injection), [Create or Modify System Process](/tags/#create-or-modify-system-process), [Parent PID Spoofing](/tags/#parent-pid-spoofing), [Access Token Manipulation](/tags/#access-token-manipulation) | TTP |
| [Wsmprovhost LOLBAS Execution Process Spawn](/endpoint/wsmprovhost_lolbas_execution_process_spawn/) | [Remote Services](/tags/#remote-services), [Windows Remote Management](/tags/#windows-remote-management) | TTP |
| [XMRIG Driver Loaded](/endpoint/xmrig_driver_loaded/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process) | TTP |
| [XSL Script Execution With WMIC](/endpoint/xsl_script_execution_with_wmic/) | [XSL Script Processing](/tags/#xsl-script-processing) | TTP |
| [aws detect attach to role policy](/cloud/aws_detect_attach_to_role_policy/) | [Valid Accounts](/tags/#valid-accounts) | Hunting |
| [aws detect permanent key creation](/cloud/aws_detect_permanent_key_creation/) | [Valid Accounts](/tags/#valid-accounts) | Hunting |
| [aws detect role creation](/cloud/aws_detect_role_creation/) | [Valid Accounts](/tags/#valid-accounts) | Hunting |
| [aws detect sts assume role abuse](/cloud/aws_detect_sts_assume_role_abuse/) | [Valid Accounts](/tags/#valid-accounts) | Hunting |
| [aws detect sts get session token abuse](/cloud/aws_detect_sts_get_session_token_abuse/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material) | Hunting |
| [gcp detect oauth token abuse](/deprecated/gcp_detect_oauth_token_abuse/) | [Valid Accounts](/tags/#valid-accounts) | Hunting |