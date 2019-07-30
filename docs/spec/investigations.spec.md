
# Investigative Search Manifest Schema

```
https://api.splunkresearch.com/schemas/investigations.json
```

The fields that make up the manifest of a version 2 investigative object

| Abstract | Extensible | Status | Identifiable | Custom Properties | Additional Properties | Defined In |
|----------|------------|--------|--------------|-------------------|-----------------------|------------|
| Can be instantiated | No | Experimental | No | Forbidden | Permitted |  |

# Investigative Search Manifest Properties

| Property | Type | Required | Nullable | Defined by |
|----------|------|----------|----------|------------|
| [creation_date](#creation_date) | `string` | **Required**  | No | Investigative Search Manifest (this schema) |
| [data_metadata](#data_metadata) | `object` | **Required**  | No | Investigative Search Manifest (this schema) |
| [definitions](#definitions) | complex | Optional  | No | Investigative Search Manifest (this schema) |
| [description](#description) | `string` | **Required**  | No | Investigative Search Manifest (this schema) |
| [entities](#entities) | `enum[]` | Optional  | No | Investigative Search Manifest (this schema) |
| [how_to_implement](#how_to_implement) | `string` | **Required**  | No | Investigative Search Manifest (this schema) |
| [id](#id) | `string` | **Required**  | No | Investigative Search Manifest (this schema) |
| [investigate](#investigate) | complex | **Required**  | No | Investigative Search Manifest (this schema) |
| [maintainers](#maintainers) | `object[]` | **Required**  | No | Investigative Search Manifest (this schema) |
| [modification_date](#modification_date) | `string` | **Required**  | No | Investigative Search Manifest (this schema) |
| [name](#name) | `string` | Optional  | No | Investigative Search Manifest (this schema) |
| [original_authors](#original_authors) | `object[]` | **Required**  | No | Investigative Search Manifest (this schema) |
| [product_type](#product_type) | `enum` | **Required**  | No | Investigative Search Manifest (this schema) |
| [spec_version](#spec_version) | `integer` | **Required**  | No | Investigative Search Manifest (this schema) |
| [version](#version) | `string` | **Required**  | No | Investigative Search Manifest (this schema) |
| `*` | any | Additional | Yes | this schema *allows* additional properties |

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
  "type": "array",
  "minItems": 0,
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













## definitions


`definitions`

* is optional
* type: complex
* defined in this schema

### definitions Type

Unknown type ``.

```json
{
  "phantom": {
    "properties": {
      "phantom_server": {
        "description": "IP address and username of the phantom server. Currently, we will ship this value as automation (hostname) and we encourage the users to modify those values according to their environment. Eg: automation (hostname)",
        "type": "string"
      },
      "playbook_display_name": {
        "description": "Display Name of the playbook. Capitalize each letter and remove underscores from playbook_name field. Eg: Simple Network Enrichment",
        "type": "string"
      },
      "playbook_name": {
        "description": "Name of the playbook. This name should be the same as the name on phantom community repository on github with underscores and appended with community/<playbook_name>. The playbooks are hosted on https://github.com/phantomcyber/playbooks. Eg: community/simple_network_enrichment",
        "type": "string"
      },
      "playbook_url": {
        "description": "Url of the playbook on Phantom website.",
        "type": "string"
      },
      "sensitivity": {
        "description": "TLP colors (White, Green, Amber or Red)",
        "type": "string"
      },
      "severity": {
        "description": "Severity in phantom (High, Medium, Low)",
        "type": "string"
      }
    },
    "required": [
      "phantom_server",
      "playbook_name",
      "playbook_url",
      "playbook_display_name"
    ],
    "type": "object"
  },
  "splunk": {
    "properties": {
      "investigate_window": {
        "additionalProperties": false,
        "description": "The fields associated on when this search should run relative to the detection event",
        "properties": {
          "earliest_time_offset": {
            "description": "The number of seconds into the past from the event time the search should cover",
            "type": "integer"
          },
          "latest_time_offset": {
            "description": "The number of seconds into the future from the event time the search should cover",
            "type": "integer"
          }
        },
        "required": [
          "latest_time_offset",
          "earliest_time_offset"
        ],
        "type": "object"
      },
      "search": {
        "description": "The search (in SPL) executed within core Splunk for investgation.",
        "type": "string"
      }
    },
    "required": [
      "search",
      "investigate_window"
    ],
    "type": "object"
  },
  "simpletype": "complex"
}
```





## description

A description of what the search is designed to detect

`description`

* is **required**
* type: `string`
* defined in this schema

### description Type


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
  "description": "A list of entities that will used in the story flow or are relevant to the security investigation. ",
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







## investigate


`investigate`

* is **required**
* type: complex
* defined in this schema

### investigate Type


**One** of the following *conditions* need to be fulfilled.


#### Condition 1


* []() – `#/definitions/splunk`


#### Condition 2


* []() – `#/definitions/phantom`






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

The name of the search

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

Type of product that will support this investigate object.

`product_type`

* is **required**
* type: `enum`
* defined in this schema

The value of this property **must** be equal to one of the [known values below](#product_type-known-values).

### product_type Known Values
| Value | Description |
|-------|-------------|
| `phantom` |  |
| `splunk` |  |
| `uba` |  |




## spec_version

The version of the investigative search specification this manifest follows

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






