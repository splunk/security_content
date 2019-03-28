
# Detection Manifest Schema

```
https://api.splunkresearch.com/schemas/detections.json
```

A object that defines the parameters for detecting things using various Splunk capabilities

| Abstract | Extensible | Status | Identifiable | Custom Properties | Additional Properties | Defined In |
|----------|------------|--------|--------------|-------------------|-----------------------|------------|
| Can be instantiated | Yes | Experimental | No | Forbidden | Permitted |  |

# Detection Manifest Properties

| Property | Type | Required | Nullable | Defined by |
|----------|------|----------|----------|------------|
| [asset_type](#asset_type) | `string` | Optional  | No | Detection Manifest (this schema) |
| [baselines](#baselines) | `object[]` | Optional  | No | Detection Manifest (this schema) |
| [confidence](#confidence) | `enum` | **Required**  | No | Detection Manifest (this schema) |
| [creation_date](#creation_date) | `string` | **Required**  | No | Detection Manifest (this schema) |
| [data_metadata](#data_metadata) | `object` | **Required**  | No | Detection Manifest (this schema) |
| [description](#description) | `string` | **Required**  | No | Detection Manifest (this schema) |
| [detect](#detect) | complex | **Required**  | No | Detection Manifest (this schema) |
| [eli5](#eli5) | `string` | **Required**  | No | Detection Manifest (this schema) |
| [entities](#entities) | `enum[]` | Optional  | No | Detection Manifest (this schema) |
| [how_to_implement](#how_to_implement) | `string` | **Required**  | No | Detection Manifest (this schema) |
| [id](#id) | `string` | **Required**  | No | Detection Manifest (this schema) |
| [investigations](#investigations) | `object[]` | Optional  | No | Detection Manifest (this schema) |
| [known_false_positives](#known_false_positives) | `string` | **Required**  | No | Detection Manifest (this schema) |
| [maintainers](#maintainers) | `object[]` | **Required**  | No | Detection Manifest (this schema) |
| [mappings](#mappings) | `object` | Optional  | No | Detection Manifest (this schema) |
| [modification_date](#modification_date) | `string` | **Required**  | No | Detection Manifest (this schema) |
| [name](#name) | `string` | Optional  | No | Detection Manifest (this schema) |
| [original_authors](#original_authors) | `object[]` | **Required**  | No | Detection Manifest (this schema) |
| [product_type](#product_type) | `enum` | **Required**  | No | Detection Manifest (this schema) |
| [references](#references) | `string[]` | Optional  | No | Detection Manifest (this schema) |
| [responses](#responses) | `object[]` | Optional  | No | Detection Manifest (this schema) |
| [security_domain](#security_domain) | `enum` | **Required**  | No | Detection Manifest (this schema) |
| [spec_version](#spec_version) | `integer` | Optional  | No | Detection Manifest (this schema) |
| [version](#version) | `string` | **Required**  | No | Detection Manifest (this schema) |
| `*` | any | Additional | Yes | this schema *allows* additional properties |

## asset_type

Designates the type of asset being investigated

`asset_type`

* is optional
* type: `string`
* defined in this schema

### asset_type Type


`string`







## baselines

An array of the baseline objects to exectute before the detection

`baselines`

* is optional
* type: `object[]`
* defined in this schema

### baselines Type


Array type: `object[]`

All items must be of the type:
`object` with following properties:


| Property | Type | Required |
|----------|------|----------|
| `id`| string | **Required** |
| `name`| string | **Required** |
| `type`|  | Optional |



#### id

UUID of the baseline object

`id`

* is **required**
* type: `string`

##### id Type


`string`









#### name

name of baseline object

`name`

* is **required**
* type: `string`

##### name Type


`string`









#### type

Type of baseline to execute

`type`

* is optional
* type: `enum`

The value of this property **must** be equal to one of the [known values below](#baselines-known-values).

##### type Known Values
| Value | Description |
|-------|-------------|
| `phantom` |  |
| `splunk` |  |
| `uba` |  |












## confidence

Confidence that detected behavior is malicious

`confidence`

* is **required**
* type: `enum`
* defined in this schema

The value of this property **must** be equal to one of the [known values below](#confidence-known-values).

### confidence Known Values
| Value | Description |
|-------|-------------|
| `high` |  |
| `medium` |  |
| `low` |  |




## creation_date

The date the story manifest was created

`creation_date`

* is **required**
* type: `string`
* defined in this schema

### creation_date Type


`string`







## data_metadata

Information about the date being ingested

`data_metadata`

* is **required**
* type: `object`
* defined in this schema

### data_metadata Type


`object` with following properties:


| Property | Type | Required |
|----------|------|----------|
| `data_eventtypes`| array | Optional |
| `data_models`| array | Optional |
| `data_source`| array | **Required** |
| `data_sourcetypes`| array | Optional |
| `providing_technologies`| array | **Required** |



#### data_eventtypes

A list of eventtypes, if any, used by this search

`data_eventtypes`

* is optional
* type: `string[]`* at least `0` items in the array


##### data_eventtypes Type


Array type: `string[]`

All items must be of the type:
`string`












#### data_models

A list of data models, if any, used by this search

`data_models`

* is optional
* type: `enum[]`* at least `0` items in the array


##### data_models Type


Array type: `enum[]`

All items must be of the type:
Unknown type ``.

```json
{
  "description": "A list of data models, if any, used by this search",
  "items": {
    "enum": [
      "Alerts",
      "Application_State",
      "Authentication",
      "Certificates",
      "Change_Analysis",
      "Change",
      "Malware",
      "Email",
      "Identity_Management",
      "Network_Resolution",
      "Network_Traffic",
      "Vulnerabilities",
      "Web",
      "Network_Sessions",
      "Updates",
      "Risk",
      "Endpoint"
    ],
    "simpletype": "`enum`",
    "meta:enum": {
      "Alerts": "",
      "Application_State": "",
      "Authentication": "",
      "Certificates": "",
      "Change_Analysis": "",
      "Change": "",
      "Malware": "",
      "Email": "",
      "Identity_Management": "",
      "Network_Resolution": "",
      "Network_Traffic": "",
      "Vulnerabilities": "",
      "Web": "",
      "Network_Sessions": "",
      "Updates": "",
      "Risk": "",
      "Endpoint": ""
    }
  },
  "minItems": 0,
  "type": "array",
  "uniqueItems": true,
  "simpletype": "`enum[]`"
}
```










#### data_source

A high-level description of the type of data needed for this search to complete

`data_source`

* is **required**
* type: `string[]`* at least `0` items in the array


##### data_source Type


Array type: `string[]`

All items must be of the type:
`string`












#### data_sourcetypes

The list of sourcetypes, if any, used by this search

`data_sourcetypes`

* is optional
* type: `string[]`* at least `0` items in the array


##### data_sourcetypes Type


Array type: `string[]`

All items must be of the type:
`string`












#### providing_technologies

A list of technologies that provide this data

`providing_technologies`

* is **required**
* type: `enum[]`* at least `0` items in the array


##### providing_technologies Type


Array type: `enum[]`

All items must be of the type:
Unknown type ``.

```json
{
  "description": "A list of technologies that provide this data",
  "items": {
    "enum": [
      "Apache",
      "AWS",
      "Bro",
      "Microsoft Windows",
      "Linux",
      "macOS",
      "Netbackup",
      "Splunk Enterprise",
      "Splunk Enterprise Security",
      "Splunk Stream",
      "Active Directory",
      "Bluecoat",
      "Carbon Black Response",
      "Carbon Black Protect",
      "CrowdStrike Falcon",
      "Microsoft Exchange",
      "Nessus",
      "Palo Alto Firewall",
      "Qualys",
      "Sysmon",
      "Tanium",
      "Ziften",
      "OSquery"
    ],
    "simpletype": "`enum`",
    "meta:enum": {
      "Apache": "",
      "AWS": "",
      "Bro": "",
      "Microsoft Windows": "",
      "Linux": "",
      "macOS": "",
      "Netbackup": "",
      "Splunk Enterprise": "",
      "Splunk Enterprise Security": "",
      "Splunk Stream": "",
      "Active Directory": "",
      "Bluecoat": "",
      "Carbon Black Response": "",
      "Carbon Black Protect": "",
      "CrowdStrike Falcon": "",
      "Microsoft Exchange": "",
      "Nessus": "",
      "Palo Alto Firewall": "",
      "Qualys": "",
      "Sysmon": "",
      "Tanium": "",
      "Ziften": "",
      "OSquery": ""
    }
  },
  "minItems": 0,
  "type": "array",
  "uniqueItems": true,
  "simpletype": "`enum[]`"
}
```













## description

A description of what the detection is designed to find

`description`

* is **required**
* type: `string`
* defined in this schema

### description Type


`string`







## detect


`detect`

* is **required**
* type: complex
* defined in this schema

### detect Type


**One** of the following *conditions* need to be fulfilled.


#### Condition 1


* []() – `#/definitions/splunk`


#### Condition 2


* []() – `#/definitions/phantom`


#### Condition 3


* []() – `#/definitions/uba`






## eli5

Explain it like I am 5 - A detail description of the SPL of the search, written in a style that can be understood by a future Splunk expert

`eli5`

* is **required**
* type: `string`
* defined in this schema

### eli5 Type


`string`







## entities

A list of entities that is outputed by the search...

`entities`

* is optional
* type: `enum[]`
* at least `0` items in the array
* defined in this schema

### entities Type


Array type: `enum[]`

All items must be of the type:
Unknown type ``.

```json
{
  "description": "A list of entities that is outputed by the search...",
  "items": {
    "enum": [
      "accessKeyId",
      "arn",
      "awsRegion",
      "bucketName",
      "City",
      "Country",
      "dest_port",
      "dest",
      "event_id",
      "instanceId",
      "message_id",
      "networkAclId",
      "process_name",
      "process",
      "recipient",
      "Region",
      "resourceId",
      "session_id",
      "src_ip",
      "src_mac",
      "src_user",
      "src",
      "user"
    ],
    "simpletype": "`enum`",
    "meta:enum": {
      "accessKeyId": "",
      "arn": "",
      "awsRegion": "",
      "bucketName": "",
      "City": "",
      "Country": "",
      "dest_port": "",
      "dest": "",
      "event_id": "",
      "instanceId": "",
      "message_id": "",
      "networkAclId": "",
      "process_name": "",
      "process": "",
      "recipient": "",
      "Region": "",
      "resourceId": "",
      "session_id": "",
      "src_ip": "",
      "src_mac": "",
      "src_user": "",
      "src": "",
      "user": ""
    }
  },
  "minItems": 0,
  "type": "array",
  "uniqueItems": true,
  "simpletype": "`enum[]`"
}
```








## how_to_implement

A discussion on how to implement this search, from what needs to be ingested, config files modified, and suggested per site modifications

`how_to_implement`

* is **required**
* type: `string`
* defined in this schema

### how_to_implement Type


`string`







## id

The unique identifier for the detection

`id`

* is **required**
* type: `string`
* defined in this schema

### id Type


`string`







## investigations

An array of the investigation objects to exectute on the detection results

`investigations`

* is optional
* type: `object[]`
* defined in this schema

### investigations Type


Array type: `object[]`

All items must be of the type:
`object` with following properties:


| Property | Type | Required |
|----------|------|----------|
| `id`| string | **Required** |
| `name`| string | **Required** |
| `product_type`| string | **Required** |



#### id

UUID of the baseline object

`id`

* is **required**
* type: `string`

##### id Type


`string`









#### name

Name of baseline

`name`

* is **required**
* type: `string`

##### name Type


`string`









#### product_type

Type of baseline to execute

`product_type`

* is **required**
* type: `enum`

The value of this property **must** be equal to one of the [known values below](#investigations-known-values).

##### product_type Known Values
| Value | Description |
|-------|-------------|
| `phantom` |  |
| `splunk` |  |
| `uba` |  |












## known_false_positives

Scenarios in which detected behavior is benig, coupled with suggestions on how to verify the behavior

`known_false_positives`

* is **required**
* type: `string`
* defined in this schema

### known_false_positives Type


`string`







## maintainers

An array of the current maintainers of the Analytic Story.

`maintainers`

* is **required**
* type: `object[]`
* defined in this schema

### maintainers Type


Array type: `object[]`

All items must be of the type:
`object` with following properties:


| Property | Type | Required |
|----------|------|----------|
| `company`| string | **Required** |
| `email`| string | **Required** |
| `name`| string | **Required** |



#### company

Company associated with the person maintaining this search

`company`

* is **required**
* type: `string`

##### company Type


`string`









#### email

Email address of the person maintaining this search

`email`

* is **required**
* type: `string`

##### email Type


`string`









#### name

Name of the person maintaining this search

`name`

* is **required**
* type: `string`

##### name Type


`string`















## mappings

Mappings to various industry standards and frameworks

`mappings`

* is optional
* type: `object`
* defined in this schema

### mappings Type


`object` with following properties:


| Property | Type | Required |
|----------|------|----------|
| `cis20`| array | Optional |
| `emoji`| array | Optional |
| `kill_chain_phases`| array | Optional |
| `mitre_attack`| array | Optional |
| `nist`| array | Optional |



#### cis20

A list of critical security controls this search helps you implement

`cis20`

* is optional
* type: `enum[]`* at least `0` items in the array


##### cis20 Type


Array type: `enum[]`

All items must be of the type:
Unknown type ``.

```json
{
  "description": "A list of critical security controls this search helps you implement",
  "items": {
    "enum": [
      "CIS 1",
      "CIS 2",
      "CIS 3",
      "CIS 4",
      "CIS 5",
      "CIS 6",
      "CIS 7",
      "CIS 8",
      "CIS 9",
      "CIS 10",
      "CIS 11",
      "CIS 12",
      "CIS 13",
      "CIS 14",
      "CIS 15",
      "CIS 16",
      "CIS 17",
      "CIS 18",
      "CIS 19",
      "CIS 20"
    ],
    "simpletype": "`enum`",
    "meta:enum": {
      "CIS 1": "",
      "CIS 2": "",
      "CIS 3": "",
      "CIS 4": "",
      "CIS 5": "",
      "CIS 6": "",
      "CIS 7": "",
      "CIS 8": "",
      "CIS 9": "",
      "CIS 10": "",
      "CIS 11": "",
      "CIS 12": "",
      "CIS 13": "",
      "CIS 14": "",
      "CIS 15": "",
      "CIS 16": "",
      "CIS 17": "",
      "CIS 18": "",
      "CIS 19": "",
      "CIS 20": ""
    }
  },
  "minItems": 0,
  "type": "array",
  "uniqueItems": true,
  "simpletype": "`enum[]`"
}
```










#### emoji

A list of security emojis that will help UBA understand this alert as an external alarm

`emoji`

* is optional
* type: `enum[]`* at least `0` items in the array


##### emoji Type


Array type: `enum[]`

All items must be of the type:
Unknown type ``.

```json
{
  "description": "A list of security emojis that will help UBA understand this alert as an external alarm",
  "items": {
    "enum": [
      "EndPoint",
      "AD",
      "Firewall",
      "ApplicationLog",
      "IPS",
      "CloudData",
      "Correlation",
      "Printer",
      "Badge"
    ],
    "simpletype": "`enum`",
    "meta:enum": {
      "EndPoint": "",
      "AD": "",
      "Firewall": "",
      "ApplicationLog": "",
      "IPS": "",
      "CloudData": "",
      "Correlation": "",
      "Printer": "",
      "Badge": ""
    }
  },
  "minItems": 0,
  "type": "array",
  "uniqueItems": true,
  "simpletype": "`enum[]`"
}
```










#### kill_chain_phases

A list of kill-chain phases to which the search applies

`kill_chain_phases`

* is optional
* type: `enum[]`* at least `0` items in the array


##### kill_chain_phases Type


Array type: `enum[]`

All items must be of the type:
Unknown type ``.

```json
{
  "description": "A list of kill-chain phases to which the search applies",
  "items": {
    "enum": [
      "Reconnaissance",
      "Weaponization",
      "Delivery",
      "Exploitation",
      "Installation",
      "Command and Control",
      "Actions on Objectives"
    ],
    "simpletype": "`enum`",
    "meta:enum": {
      "Reconnaissance": "",
      "Weaponization": "",
      "Delivery": "",
      "Exploitation": "",
      "Installation": "",
      "Command and Control": "",
      "Actions on Objectives": ""
    }
  },
  "minItems": 0,
  "type": "array",
  "uniqueItems": true,
  "simpletype": "`enum[]`"
}
```










#### mitre_attack

A list of the techniques and tactics identified by the search

`mitre_attack`

* is optional
* type: `enum[]`* at least `0` items in the array


##### mitre_attack Type


Array type: `enum[]`

All items must be of the type:
Unknown type ``.

```json
{
  "description": "A list of the techniques and tactics identified by the search",
  "items": {
    "enum": [
      "Initial Access",
      "Execution",
      "Persistence",
      "Privilege Escalation",
      "Defense Evasion",
      "Credential Access",
      "Discovery",
      "Lateral Movement",
      "Collection",
      "Exfiltration",
      "Command and Control",
      "Command and Control Protocol",
      "Commonly Used Port",
      "Custom Cryptographic Protocol",
      "DLL Injection",
      "DLL Search Order Hijacking",
      "DLL Side-Loading",
      "Data Compressed",
      "Data Encrypted",
      "Data Obfuscation",
      "Data Staged",
      "Data Transfer Size Limits",
      "Data from Local System",
      "Data from Network Shared Drive",
      "Data from Removable Media",
      "Disabling Security Tools",
      "Email Collection",
      "Execution through API",
      "Exfiltration Over Alternative Protocol",
      "Exfiltration Over Command and Control Channel",
      "Exfiltration Over Other Network Medium",
      "Exfiltration Over Physical Medium",
      "Exploitation of Vulnerability",
      "Fallback Channels",
      "File Deletion",
      "File System Logical Offsets",
      "File System Permissions Weakness",
      "File and Directory Discovery",
      "Graphical User Interface",
      "Hypervisor",
      "Indicator Blocking",
      "Indicator Removal from Tools",
      "Indicator Removal on Host",
      "Input Capture",
      "InstallUtil",
      "Legitimate Credentials",
      "Local Network Configuration Discovery",
      "Local Network Connections Discovery",
      "Local Port Monitor",
      "Logon Scripts",
      "MSBuild",
      "Masquerading",
      "Modify Existing Service",
      "Modify Registry",
      "Multi-Stage Channels",
      "Multiband Communication",
      "Multilayer Encryption",
      "NTFS Extended Attributes",
      "Network Service Scanning",
      "Network Share Connection Removal",
      "Network Sniffing",
      "New Service",
      "Obfuscated Files or Information",
      "Pass the Hash",
      "Pass the Ticket",
      "Path Interception",
      "Peripheral Device Discovery",
      "Permission Groups Discovery",
      "PowerShell",
      "Process Discovery",
      "Process Hollowing",
      "Query Registry",
      "Redundant Access",
      "Registry Run Keys / Start Folder",
      "Regsvcs/Regasm",
      "Regsvr32",
      "Remote Desktop Protocol",
      "Create Account",
      "Remote File Copy",
      "Remote Services",
      "Remote System Discovery",
      "Replication Through Removable Media",
      "Rootkit",
      "Rundll32",
      "Scheduled Task",
      "Scheduled Transfer",
      "Screen Capture",
      "Scripting",
      "Security Software Discovery",
      "Security Support Provider",
      "Service Execution",
      "Service Registry Permissions Weakness",
      "Shared Webroot",
      "Shortcut Modification",
      "Software Packing",
      "Standard Application Layer Protocol",
      "Standard Cryptographic Protocol",
      "Standard Non-Application Layer Protocol",
      "System Information Discovery",
      "System Owner/User Discovery",
      "System Service Discovery",
      "System Time Discovery",
      "Taint Shared Content",
      "Third-party Software",
      "Timestomp",
      "Two-Factor Authentication Interception",
      "Uncommonly Used Port",
      "Video Capture",
      "Valid Accounts",
      "Web Service",
      "Web Shell",
      "Windows Admin Shares",
      "Windows Management Instrumentation Event Subscription",
      "Windows Management Instrumentation",
      "Windows Remote Management",
      "Winlogon Helper DLL",
      "Exploitation for Privilege Escalation"
    ],
    "simpletype": "`enum`",
    "meta:enum": {
      "Initial Access": "",
      "Execution": "",
      "Persistence": "",
      "Privilege Escalation": "",
      "Defense Evasion": "",
      "Credential Access": "",
      "Discovery": "",
      "Lateral Movement": "",
      "Collection": "",
      "Exfiltration": "",
      "Command and Control": "",
      "Command and Control Protocol": "",
      "Commonly Used Port": "",
      "Custom Cryptographic Protocol": "",
      "DLL Injection": "",
      "DLL Search Order Hijacking": "",
      "DLL Side-Loading": "",
      "Data Compressed": "",
      "Data Encrypted": "",
      "Data Obfuscation": "",
      "Data Staged": "",
      "Data Transfer Size Limits": "",
      "Data from Local System": "",
      "Data from Network Shared Drive": "",
      "Data from Removable Media": "",
      "Disabling Security Tools": "",
      "Email Collection": "",
      "Execution through API": "",
      "Exfiltration Over Alternative Protocol": "",
      "Exfiltration Over Command and Control Channel": "",
      "Exfiltration Over Other Network Medium": "",
      "Exfiltration Over Physical Medium": "",
      "Exploitation of Vulnerability": "",
      "Fallback Channels": "",
      "File Deletion": "",
      "File System Logical Offsets": "",
      "File System Permissions Weakness": "",
      "File and Directory Discovery": "",
      "Graphical User Interface": "",
      "Hypervisor": "",
      "Indicator Blocking": "",
      "Indicator Removal from Tools": "",
      "Indicator Removal on Host": "",
      "Input Capture": "",
      "InstallUtil": "",
      "Legitimate Credentials": "",
      "Local Network Configuration Discovery": "",
      "Local Network Connections Discovery": "",
      "Local Port Monitor": "",
      "Logon Scripts": "",
      "MSBuild": "",
      "Masquerading": "",
      "Modify Existing Service": "",
      "Modify Registry": "",
      "Multi-Stage Channels": "",
      "Multiband Communication": "",
      "Multilayer Encryption": "",
      "NTFS Extended Attributes": "",
      "Network Service Scanning": "",
      "Network Share Connection Removal": "",
      "Network Sniffing": "",
      "New Service": "",
      "Obfuscated Files or Information": "",
      "Pass the Hash": "",
      "Pass the Ticket": "",
      "Path Interception": "",
      "Peripheral Device Discovery": "",
      "Permission Groups Discovery": "",
      "PowerShell": "",
      "Process Discovery": "",
      "Process Hollowing": "",
      "Query Registry": "",
      "Redundant Access": "",
      "Registry Run Keys / Start Folder": "",
      "Regsvcs/Regasm": "",
      "Regsvr32": "",
      "Remote Desktop Protocol": "",
      "Create Account": "",
      "Remote File Copy": "",
      "Remote Services": "",
      "Remote System Discovery": "",
      "Replication Through Removable Media": "",
      "Rootkit": "",
      "Rundll32": "",
      "Scheduled Task": "",
      "Scheduled Transfer": "",
      "Screen Capture": "",
      "Scripting": "",
      "Security Software Discovery": "",
      "Security Support Provider": "",
      "Service Execution": "",
      "Service Registry Permissions Weakness": "",
      "Shared Webroot": "",
      "Shortcut Modification": "",
      "Software Packing": "",
      "Standard Application Layer Protocol": "",
      "Standard Cryptographic Protocol": "",
      "Standard Non-Application Layer Protocol": "",
      "System Information Discovery": "",
      "System Owner/User Discovery": "",
      "System Service Discovery": "",
      "System Time Discovery": "",
      "Taint Shared Content": "",
      "Third-party Software": "",
      "Timestomp": "",
      "Two-Factor Authentication Interception": "",
      "Uncommonly Used Port": "",
      "Video Capture": "",
      "Valid Accounts": "",
      "Web Service": "",
      "Web Shell": "",
      "Windows Admin Shares": "",
      "Windows Management Instrumentation Event Subscription": "",
      "Windows Management Instrumentation": "",
      "Windows Remote Management": "",
      "Winlogon Helper DLL": "",
      "Exploitation for Privilege Escalation": ""
    }
  },
  "minItems": 0,
  "type": "array",
  "uniqueItems": true,
  "simpletype": "`enum[]`"
}
```










#### nist

A list of the NIST controls the search helps you implement

`nist`

* is optional
* type: `enum[]`* at least `0` items in the array


##### nist Type


Array type: `enum[]`

All items must be of the type:
Unknown type ``.

```json
{
  "description": "A list of the NIST controls the search helps you implement",
  "items": {
    "enum": [
      "ID.AM",
      "ID.RA",
      "PR.DS",
      "PR.IP",
      "PR.AC",
      "PR.PT",
      "PR.AT",
      "PR.MA",
      "DE.CM",
      "DE.DP",
      "DE.AE",
      "RS.MI",
      "RS.AN",
      "RS.RP",
      "RS.IM",
      "RS.CO",
      "RC.IM",
      "RC.CO"
    ],
    "simpletype": "`enum`",
    "meta:enum": {
      "ID.AM": "",
      "ID.RA": "",
      "PR.DS": "",
      "PR.IP": "",
      "PR.AC": "",
      "PR.PT": "",
      "PR.AT": "",
      "PR.MA": "",
      "DE.CM": "",
      "DE.DP": "",
      "DE.AE": "",
      "RS.MI": "",
      "RS.AN": "",
      "RS.RP": "",
      "RS.IM": "",
      "RS.CO": "",
      "RC.IM": "",
      "RC.CO": ""
    }
  },
  "minItems": 0,
  "type": "array",
  "uniqueItems": true,
  "simpletype": "`enum[]`"
}
```













## modification_date

The date of the most recent modification to the search

`modification_date`

* is **required**
* type: `string`
* defined in this schema

### modification_date Type


`string`







## name

The name of the detection

`name`

* is optional
* type: `string`
* defined in this schema

### name Type


`string`







## original_authors

A list of the original authors of the search

`original_authors`

* is **required**
* type: `object[]`
* defined in this schema

### original_authors Type


Array type: `object[]`

All items must be of the type:
`object` with following properties:


| Property | Type | Required |
|----------|------|----------|
| `company`| string | **Required** |
| `email`| string | **Required** |
| `name`| string | **Required** |



#### company

Company associated with the person who originally authored the search

`company`

* is **required**
* type: `string`

##### company Type


`string`









#### email

Email address of the person who originally authored the search

`email`

* is **required**
* type: `string`

##### email Type


`string`









#### name

Name of the person who originally authored the search

`name`

* is **required**
* type: `string`

##### name Type


`string`















## product_type

The type of detection

`product_type`

* is **required**
* type: `enum`
* defined in this schema

The value of this property **must** be equal to one of the [known values below](#product_type-known-values).

### product_type Known Values
| Value | Description |
|-------|-------------|
| `uba` |  |
| `splunk` |  |
| `phantom` |  |




## references

A list of URLs that give more information about the search

`references`

* is optional
* type: `string[]`
* at least `0` items in the array
* defined in this schema

### references Type


Array type: `string[]`

All items must be of the type:
`string`










## responses

An array of the response objects to exectute on the detection results

`responses`

* is optional
* type: `object[]`
* defined in this schema

### responses Type


Array type: `object[]`

All items must be of the type:
`object` with following properties:


| Property | Type | Required |
|----------|------|----------|
| `id`| string | **Required** |
| `name`| string | **Required** |
| `product_type`|  | **Required** |



#### id

UUID of the baseline object

`id`

* is **required**
* type: `string`

##### id Type


`string`









#### name

name of baseline

`name`

* is **required**
* type: `string`

##### name Type


`string`









#### product_type

Type of baseline to execute

`product_type`

* is **required**
* type: `enum`

The value of this property **must** be equal to one of the [known values below](#responses-known-values).

##### product_type Known Values
| Value | Description |
|-------|-------------|
| `phantom` |  |
| `splunk` |  |
| `uba` |  |












## security_domain

The high-level security area to which the search belongs

`security_domain`

* is **required**
* type: `enum`
* defined in this schema

The value of this property **must** be equal to one of the [known values below](#security_domain-known-values).

### security_domain Known Values
| Value | Description |
|-------|-------------|
| `access` |  |
| `endpoint` |  |
| `network` |  |
| `threat` |  |




## spec_version

The version of the detection specification this manifest follows

`spec_version`

* is optional
* type: `integer`
* defined in this schema

### spec_version Type


`integer`







## version

The version of the detection

`version`

* is **required**
* type: `string`
* defined in this schema

### version Type


`string`







# Detection Manifest Definitions

| Property | Type | Group |
|----------|------|-------|
| [correlation_rule](#correlation_rule) | `object` | `https://api.splunkresearch.com/schemas/detections.json#/definitions/splunk` |
| [event_type](#event_type) | `string` | `https://api.splunkresearch.com/schemas/detections.json#/definitions/uba` |
| [model](#model) | `string` | `https://api.splunkresearch.com/schemas/detections.json#/definitions/uba` |
| [model_version](#model_version) | `string` | `https://api.splunkresearch.com/schemas/detections.json#/definitions/uba` |
| [phantom_server](#phantom_server) | `string` | `https://api.splunkresearch.com/schemas/detections.json#/definitions/phantom` |
| [playbook_display_name](#playbook_display_name) | `string` | `https://api.splunkresearch.com/schemas/detections.json#/definitions/phantom` |
| [playbook_name](#playbook_name) | `string` | `https://api.splunkresearch.com/schemas/detections.json#/definitions/phantom` |
| [playbook_url](#playbook_url) | `string` | `https://api.splunkresearch.com/schemas/detections.json#/definitions/phantom` |
| [scheduling](#scheduling) | `object` | `https://api.splunkresearch.com/schemas/detections.json#/definitions/splunk` |
| [search](#search) | `string` | `https://api.splunkresearch.com/schemas/detections.json#/definitions/uba` |
| [sensitivity](#sensitivity) | `string` | `https://api.splunkresearch.com/schemas/detections.json#/definitions/phantom` |
| [severity](#severity) | `string` | `https://api.splunkresearch.com/schemas/detections.json#/definitions/phantom` |
| [threat_category](#threat_category) | `string` | `https://api.splunkresearch.com/schemas/detections.json#/definitions/uba` |

## correlation_rule

Various fields to enhance usability in Enterprise Security

`correlation_rule`

* is optional
* type: `object`
* defined in this schema

### correlation_rule Type


`object` with following properties:


| Property | Type | Required |
|----------|------|----------|
| `notable`| object | Optional |
| `risk`| object | Optional |
| `suppress`| object | Optional |



#### notable

Various fields associated with creating a notable event

`notable`

* is optional
* type: `object`

##### notable Type


`object` with following properties:


| Property | Type | Required |
|----------|------|----------|
| `nes_fields`| string | **Required** |
| `rule_description`| string | **Required** |
| `rule_title`| string | **Required** |



#### nes_fields

A list of suggested fields to be used for notable-event suppression

`nes_fields`

* is **required**
* type: `string`

##### nes_fields Type


`string`









#### rule_description

Description of the notable event that will display in Incident Review

`rule_description`

* is **required**
* type: `string`

##### rule_description Type


`string`









#### rule_title

Title of the notable event that will display in Incident Review

`rule_title`

* is **required**
* type: `string`

##### rule_title Type


`string`














#### risk

Fields associated with assigning risk to objects

`risk`

* is optional
* type: `object`

##### risk Type


`object` with following properties:


| Property | Type | Required |
|----------|------|----------|
| `risk_object`| string | **Required** |
| `risk_object_type`| array | **Required** |
| `risk_score`| integer | **Required** |



#### risk_object

TThe field to which you are assigning risk

`risk_object`

* is **required**
* type: `string`

##### risk_object Type


`string`









#### risk_object_type

The type of object to which you are assigning risk

`risk_object_type`

* is **required**
* type: `enum[]`* between `0` and `1` items in the array


##### risk_object_type Type


Array type: `enum[]`

All items must be of the type:
`string`












#### risk_score

Score assigned to risk_object

`risk_score`

* is **required**
* type: `integer`

##### risk_score Type


`integer`














#### suppress

Fields associated with suppressing the creation of multiple alerts

`suppress`

* is optional
* type: `object`

##### suppress Type


`object` with following properties:


| Property | Type | Required |
|----------|------|----------|
| `suppress_fields`| string | **Required** |
| `suppress_period`| string | **Required** |



#### suppress_fields

The fields to base the suppression on

`suppress_fields`

* is **required**
* type: `string`

##### suppress_fields Type


`string`









#### suppress_period

The length of time the suppression should be in effect

`suppress_period`

* is **required**
* type: `string`

##### suppress_period Type


`string`

















## event_type

An anomaly or threat.

`event_type`

* is optional
* type: `string`
* defined in this schema

### event_type Type


`string`







## model

The name of the Splunk UBA model that detected the anomaly.

`model`

* is optional
* type: `string`
* defined in this schema

### model Type


`string`







## model_version

Url of the playbook on Phantom website.

`model_version`

* is optional
* type: `string`
* defined in this schema

### model_version Type


`string`







## phantom_server

IP address and username of the phantom server. Currently, we will ship this value as automation (hostname) and we encourage the users to modify those values according to their environment. Eg: automation (hostname)

`phantom_server`

* is optional
* type: `string`
* defined in this schema

### phantom_server Type


`string`







## playbook_display_name

Display Name of the playbook. Capitalize each letter and remove underscores from playbook_name field. Eg: Simple Network Enrichment

`playbook_display_name`

* is optional
* type: `string`
* defined in this schema

### playbook_display_name Type


`string`







## playbook_name

Name of the playbook. This name should be the same as the name on phantom community repository on github with underscores and appended with community/<playbook_name>. The playbooks are hosted on https://github.com/phantomcyber/playbooks. Eg: community/simple_network_enrichment

`playbook_name`

* is optional
* type: `string`
* defined in this schema

### playbook_name Type


`string`







## playbook_url

Url of the playbook on Phantom website.

`playbook_url`

* is optional
* type: `string`
* defined in this schema

### playbook_url Type


`string`







## scheduling

Various fields to assist in scheduling the search

`scheduling`

* is optional
* type: `object`
* defined in this schema

### scheduling Type


`object` with following properties:


| Property | Type | Required |
|----------|------|----------|
| `cron_schedule`| string | Optional |
| `earliest_time`| string | Optional |
| `latest_time`| string | Optional |



#### cron_schedule

Schedule of the search in cron format

`cron_schedule`

* is optional
* type: `string`

##### cron_schedule Type


`string`









#### earliest_time

The earliest time the search should run in Splunk format

`earliest_time`

* is optional
* type: `string`

##### earliest_time Type


`string`









#### latest_time

The latest time tes search should run against in Splunk format

`latest_time`

* is optional
* type: `string`

##### latest_time Type


`string`












## search

The search you will run against the UEBA index to idenfiy the threat.

`search`

* is optional
* type: `string`
* defined in this schema

### search Type


`string`







## sensitivity

TLP colors (White, Green, Amber or Red)

`sensitivity`

* is optional
* type: `string`
* defined in this schema

### sensitivity Type


`string`







## severity

Severity in phantom (High, Medium, Low)

`severity`

* is optional
* type: `string`
* defined in this schema

### severity Type


`string`







## threat_category

The category of a threat in Splunk UBA.

`threat_category`

* is optional
* type: `string`
* defined in this schema

### threat_category Type


`string`






