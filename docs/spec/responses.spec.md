
# Response Manifest Schema

```
https://api.splunkresearch.com/schemas/investigations.json
```

The fields that make up the manifest of a version 1 reponse spec

| Abstract | Extensible | Status | Identifiable | Custom Properties | Additional Properties | Defined In |
|----------|------------|--------|--------------|-------------------|-----------------------|------------|
| Can be instantiated | Yes | Experimental | No | Forbidden | Forbidden |  |

# Response Manifest Properties

| Property | Type | Required | Nullable | Defined by |
|----------|------|----------|----------|------------|
| [creation_date](#creation_date) | `string` | **Required**  | No | Response Manifest (this schema) |
| [data_metadata](#data_metadata) | `object` | **Required**  | No | Response Manifest (this schema) |
| [description](#description) | `string` | **Required**  | No | Response Manifest (this schema) |
| [entities](#entities) | `enum[]` | Optional  | No | Response Manifest (this schema) |
| [fields_required](#fields_required) | `string[]` | Optional  | No | Response Manifest (this schema) |
| [how_to_implement](#how_to_implement) | `string` | **Required**  | No | Response Manifest (this schema) |
| [id](#id) | `string` | **Required**  | No | Response Manifest (this schema) |
| [maintainers](#maintainers) | `object[]` | **Required**  | No | Response Manifest (this schema) |
| [modification_date](#modification_date) | `string` | **Required**  | No | Response Manifest (this schema) |
| [name](#name) | `string` | Optional  | No | Response Manifest (this schema) |
| [original_authors](#original_authors) | `object[]` | **Required**  | No | Response Manifest (this schema) |
| [product_type](#product_type) | `enum` | **Required**  | No | Response Manifest (this schema) |
| [response](#response) | complex | **Required**  | No | Response Manifest (this schema) |
| [spec_version](#spec_version) | `integer` | **Required**  | No | Response Manifest (this schema) |
| [version](#version) | `string` | **Required**  | No | Response Manifest (this schema) |

## creation_date

The date the story manifest was created

`creation_date`

* is **required**
* type: `string`
* defined in this schema

### creation_date Type


`string`







## data_metadata

Information about the date being used to run the response

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
* type: `string[]`* at least `0` items in the array


##### data_models Type


Array type: `string[]`

All items must be of the type:
`string`












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

A description of what this reponse object will do

`description`

* is **required**
* type: `string`
* defined in this schema

### description Type


`string`







## entities

A list of entities that is either an input or an output for the security workflow.

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
  "description": "A list of entities that is either an input or an output for the security workflow.",
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








## fields_required

A list of fields that need to be in the result of the detection search for the search to be successful

`fields_required`

* is optional
* type: `string[]`
* at least `0` items in the array
* defined in this schema

### fields_required Type


Array type: `string[]`

All items must be of the type:
`string`










## how_to_implement

A discussion on how to implement this reponse object, the config files, etc

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







## maintainers

An array of the current maintainers of the reponse spec

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

A list of the original authors of the reponse object

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
| `splunk` |  |
| `phantom` |  |




## response


`response`

* is **required**
* type: complex
* defined in this schema

### response Type


**One** of the following *conditions* need to be fulfilled.


#### Condition 1


* []() – `#/definitions/splunk`


#### Condition 2


* []() – `#/definitions/phantom`






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







# Response Manifest Definitions

| Property | Type | Group |
|----------|------|-------|
| [investigate_window](#investigate_window) | `object` | `https://api.splunkresearch.com/schemas/investigations.json#/definitions/splunk` |
| [phantom_server](#phantom_server) | `string` | `https://api.splunkresearch.com/schemas/investigations.json#/definitions/phantom` |
| [playbook_display_name](#playbook_display_name) | `string` | `https://api.splunkresearch.com/schemas/investigations.json#/definitions/phantom` |
| [playbook_name](#playbook_name) | `string` | `https://api.splunkresearch.com/schemas/investigations.json#/definitions/phantom` |
| [playbook_url](#playbook_url) | `string` | `https://api.splunkresearch.com/schemas/investigations.json#/definitions/phantom` |
| [search](#search) | `string` | `https://api.splunkresearch.com/schemas/investigations.json#/definitions/splunk` |
| [sensitivity](#sensitivity) | `string` | `https://api.splunkresearch.com/schemas/investigations.json#/definitions/phantom` |
| [severity](#severity) | `string` | `https://api.splunkresearch.com/schemas/investigations.json#/definitions/phantom` |

## investigate_window

The fields associated on when this search should run relative to the detection event

`investigate_window`

* is optional
* type: `object`
* defined in this schema

### investigate_window Type


`object` with following properties:


| Property | Type | Required |
|----------|------|----------|
| `earliest_time_offset`| integer | **Required** |
| `latest_time_offset`| integer | **Required** |



#### earliest_time_offset

The number of seconds into the past from the event time the search should cover

`earliest_time_offset`

* is **required**
* type: `integer`

##### earliest_time_offset Type


`integer`









#### latest_time_offset

The number of seconds into the future from the event time the search should cover

`latest_time_offset`

* is **required**
* type: `integer`

##### latest_time_offset Type


`integer`












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







## search

A reponse action exectued in splunk

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






