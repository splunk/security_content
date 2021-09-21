---
title: "Cobalt Strike"
last_modified_at: 2021-02-16
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Cobalt Strike is threat emulation software. Red teams and penetration testers use Cobalt Strike to demonstrate the risk of a breach and evaluate mature security programs. Most recently, Cobalt Strike has become the choice tool by threat groups due to its ease of use and extensibility.

- **ID**: bcfd17e8-5461-400a-80a2-3b7d1459220c
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-02-16
- **Author**: Michael Haag, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Anomalous usage of 7zip](/endpoint/anomalous_usage_of_7zip/) | None | Anomaly |
| [CMD Echo Pipe - Escalation](/endpoint/cmd_echo_pipe_-_escalation/) | None | TTP |
| [Cobalt Strike Named Pipes](/endpoint/cobalt_strike_named_pipes/) | None | TTP |
| [DLLHost with no Command Line Arguments with Network](/endpoint/dllhost_with_no_command_line_arguments_with_network/) | None | TTP |
| [Detect Regsvr32 Application Control Bypass](/endpoint/detect_regsvr32_application_control_bypass/) | None | TTP |
| [GPUpdate with no Command Line Arguments with Network](/endpoint/gpupdate_with_no_command_line_arguments_with_network/) | None | TTP |
| [Rundll32 with no Command Line Arguments with Network](/endpoint/rundll32_with_no_command_line_arguments_with_network/) | None | TTP |
| [SearchProtocolHost with no Command Line with Network](/endpoint/searchprotocolhost_with_no_command_line_with_network/) | None | TTP |
| [Services Escalate Exe](/endpoint/services_escalate_exe/) | None | TTP |
| [Suspicious DLLHost no Command Line Arguments](/endpoint/suspicious_dllhost_no_command_line_arguments/) | None | TTP |
| [Suspicious GPUpdate no Command Line Arguments](/endpoint/suspicious_gpupdate_no_command_line_arguments/) | None | TTP |
| [Suspicious MSBuild Rename](/endpoint/suspicious_msbuild_rename/) | None | TTP |
| [Suspicious Rundll32 StartW](/endpoint/suspicious_rundll32_startw/) | None | TTP |
| [Suspicious Rundll32 no Command Line Arguments](/endpoint/suspicious_rundll32_no_command_line_arguments/) | None | TTP |
| [Suspicious SearchProtocolHost no Command Line Arguments](/endpoint/suspicious_searchprotocolhost_no_command_line_arguments/) | None | TTP |
| [Suspicious microsoft workflow compiler rename](/endpoint/suspicious_microsoft_workflow_compiler_rename/) | None | TTP |
| [Suspicious msbuild path](/endpoint/suspicious_msbuild_path/) | None | TTP |

#### Reference

* [https://www.cobaltstrike.com/](https://www.cobaltstrike.com/)
* [https://www.infocyte.com/blog/2020/09/02/cobalt-strike-the-new-favorite-among-thieves/](https://www.infocyte.com/blog/2020/09/02/cobalt-strike-the-new-favorite-among-thieves/)
* [https://bluescreenofjeff.com/2017-01-24-how-to-write-malleable-c2-profiles-for-cobalt-strike/](https://bluescreenofjeff.com/2017-01-24-how-to-write-malleable-c2-profiles-for-cobalt-strike/)
* [https://blog.talosintelligence.com/2020/09/coverage-strikes-back-cobalt-strike-paper.html](https://blog.talosintelligence.com/2020/09/coverage-strikes-back-cobalt-strike-paper.html)
* [https://www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html](https://www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html)
* [https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence](https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence)
* [https://github.com/zer0yu/Awesome-CobaltStrike](https://github.com/zer0yu/Awesome-CobaltStrike)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/cobalt_strike.yml) | _version_: **1**