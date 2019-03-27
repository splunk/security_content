
# Baseline Manifest Schema

```
https://api.splunkresearch.com/schemas/baselines.json
```

The fields that make up the manifest of a version 2 baseline search

| Abstract | Extensible | Status | Identifiable | Custom Properties | Additional Properties | Defined In |
|----------|------------|--------|--------------|-------------------|-----------------------|------------|
| Can be instantiated | Yes | Experimental | No | Forbidden | Forbidden |  |

# Baseline Manifest Properties

| Property | Type | Required | Nullable | Defined by |
|----------|------|----------|----------|------------|
| [baseline](#baseline) | complex | **Required**  | No | Baseline Manifest (this schema) |
| [creation_date](#creation_date) | `string` | **Required**  | No | Baseline Manifest (this schema) |
| [data_metadata](#data_metadata) | `object` | **Required**  | No | Baseline Manifest (this schema) |
| [description](#description) | `string` | **Required**  | No | Baseline Manifest (this schema) |
| [eli5](#eli5) | `string` | **Required**  | No | Baseline Manifest (this schema) |
| [entities](#entities) | `enum[]` | Optional  | No | Baseline Manifest (this schema) |
| [how_to_implement](#how_to_implement) | `string` | **Required**  | No | Baseline Manifest (this schema) |
| [id](#id) | `string` | **Required**  | No | Baseline Manifest (this schema) |
| [known_false_positives](#known_false_positives) | `string` | **Required**  | No | Baseline Manifest (this schema) |
| [maintainers](#maintainers) | `object[]` | **Required**  | No | Baseline Manifest (this schema) |
| [modification_date](#modification_date) | `string` | **Required**  | No | Baseline Manifest (this schema) |
| [name](#name) | `string` | **Required**  | No | Baseline Manifest (this schema) |
| [original_authors](#original_authors) | `object[]` | **Required**  | No | Baseline Manifest (this schema) |
| [product_type](#product_type) | `enum` | **Required**  | No | Baseline Manifest (this schema) |
| [spec_version](#spec_version) | `integer` | **Required**  | No | Baseline Manifest (this schema) |
| [version](#version) | `string` | **Required**  | No | Baseline Manifest (this schema) |

## baseline


`baseline`

* is **required**
* type: complex
* defined in this schema

### baseline Type


**One** of the following *conditions* need to be fulfilled.


#### Condition 1


* []() – `#/definitions/splunk`


#### Condition 2


* []() – `#/definitions/phantom`






## creation_date

The date the baseline manifest was created

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
      "Ziften"
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
      "Ziften": ""
    }
  },
  "minItems": 0,
  "type": "array",
  "uniqueItems": true,
  "simpletype": "`enum[]`"
}
```













## description

A description of what the search is is doing to create a baseline

`description`

* is **required**
* type: `string`
* defined in this schema

### description Type


`string`







## eli5

Explain it like I’m 5 - A detail description of the SPL of the search, written in a style that can be understood by a future Splunk expert

`eli5`

* is **required**
* type: `string`
* defined in this schema

### eli5 Type


`string`







## entities

A list of entities that will used in the story flow or are relevant to the security investigation.

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
  "description": "A list of entities that will used in the story flow or are relevant to the security investigation.",
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

The unique identifier for the search

`id`

* is **required**
* type: `string`
* defined in this schema

### id Type


`string`







## known_false_positives

Describe the known false postives while the analyst builds the baseline.

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















## modification_date

The date of the most recent modification to the search

`modification_date`

* is **required**
* type: `string`
* defined in this schema

### modification_date Type


`string`







## name

The name of the search that creates the baseline

`name`

* is **required**
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

The type of baseline

`product_type`

* is **required**
* type: `enum`
* defined in this schema

The value of this property **must** be equal to one of the [known values below](#product_type-known-values).

### product_type Known Values
| Value | Description |
|-------|-------------|
| `splunk` |  |
| `phantom` |  |
| `uba` |  |




## spec_version

The version of the detection search specification this manifest follows

`spec_version`

* is **required**
* type: `integer`
* defined in this schema

### spec_version Type


`integer`







## version

The version of the search

`version`

* is **required**
* type: `string`
* defined in this schema

### version Type


`string`







# Baseline Manifest Definitions

| Property | Type | Group |
|----------|------|-------|
| [phantom_server](#phantom_server) | `string` | `https://api.splunkresearch.com/schemas/baselines.json#/definitions/phantom` |
| [playbook_display_name](#playbook_display_name) | `string` | `https://api.splunkresearch.com/schemas/baselines.json#/definitions/phantom` |
| [playbook_name](#playbook_name) | `string` | `https://api.splunkresearch.com/schemas/baselines.json#/definitions/phantom` |
| [playbook_url](#playbook_url) | `string` | `https://api.splunkresearch.com/schemas/baselines.json#/definitions/phantom` |
| [scheduling](#scheduling) | `object` | `https://api.splunkresearch.com/schemas/baselines.json#/definitions/splunk` |
| [search](#search) | `string` | `https://api.splunkresearch.com/schemas/baselines.json#/definitions/splunk` |
| [sensitivity](#sensitivity) | `string` | `https://api.splunkresearch.com/schemas/baselines.json#/definitions/phantom` |
| [severity](#severity) | `string` | `https://api.splunkresearch.com/schemas/baselines.json#/definitions/phantom` |

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
| `earliest_time`| string | Optional |
| `latest_time`| string | Optional |



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

The search (in SPL) executed within core Splunk for creating a baseline

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






