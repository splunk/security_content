# Detection Schema Schema

```txt
http://example.com/example.json
```

schema for detections

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                    |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [detections.spec.json](../../out/detections.spec.json "open original schema") |

## Detection Schema Type

`object` ([Detection Schema](detections.md))

# Detection Schema Properties

| Property                                        | Type      | Required | Nullable       | Defined by                                                                                                                                |
| :---------------------------------------------- | :-------- | :------- | :------------- | :---------------------------------------------------------------------------------------------------------------------------------------- |
| [author](#author)                               | `string`  | Required | cannot be null | [Detection Schema](detections-properties-author.md "#/properties/author#/properties/author")                                              |
| [date](#date)                                   | `string`  | Required | cannot be null | [Detection Schema](detections-properties-date.md "#/properties/date#/properties/date")                                                    |
| [description](#description)                     | `string`  | Required | cannot be null | [Detection Schema](detections-properties-description.md "#/properties/description#/properties/description")                               |
| [how_to_implement](#how_to_implement)           | `string`  | Optional | cannot be null | [Detection Schema](detections-properties-how_to_implement.md "#/properties/how_to_implement#/properties/how_to_implement")                |
| [id](#id)                                       | `string`  | Required | cannot be null | [Detection Schema](detections-properties-id.md "#/properties/id#/properties/id")                                                          |
| [known_false_positives](#known_false_positives) | `string`  | Required | cannot be null | [Detection Schema](detections-properties-known_false_positives.md "#/properties/knwon_false_positives#/properties/known_false_positives") |
| [name](#name)                                   | `string`  | Required | cannot be null | [Detection Schema](detections-properties-name-of-detection.md "#/properties/name#/properties/name")                                       |
| [references](#references)                       | `array`   | Optional | cannot be null | [Detection Schema](detections-properties-references.md "#/properties/references#/properties/references")                                  |
| [search](#search)                               | `string`  | Required | cannot be null | [Detection Schema](detections-properties-search.md "#/properties/search#/properties/search")                                              |
| [tags](#tags)                                   | `object`  | Required | cannot be null | [Detection Schema](detections-properties-tags.md "#/properties/tags#/properties/tags")                                                    |
| [type](#type)                                   | `string`  | Required | cannot be null | [Detection Schema](detections-properties-type.md "#/properties/type#/properties/type")                                                    |
| [datamodel](#datamodel)                         | `array`   | Optional | cannot be null | [Detection Schema](detections-properties-datamodel.md "#/properties/datamodel#/properties/datamodel")                                     |
| [version](#version)                             | `integer` | Required | cannot be null | [Detection Schema](detections-properties-version.md "#/properties/version#/properties/version")                                           |
| Additional Properties                           | Any       | Optional | can be null    |                                                                                                                                           |

## author

Author of the detection

`author`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Detection Schema](detections-properties-author.md "#/properties/author#/properties/author")

### author Type

`string`

### author Examples

```yaml
Patrick Bareiss, Splunk

```

## date

date of creation or modification, format yyyy-mm-dd

`date`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Detection Schema](detections-properties-date.md "#/properties/date#/properties/date")

### date Type

`string`

### date Examples

```yaml
'2019-12-06'

```

## description

A detailed description of the detection

`description`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Detection Schema](detections-properties-description.md "#/properties/description#/properties/description")

### description Type

`string`

### description Examples

```yaml
>-
  dbgcore.dll is a specifc DLL for Windows core debugging. It is used to obtain
  a memory dump of a process. This search detects the usage of this DLL for
  creating a memory dump of LSASS process. Memory dumps of the LSASS process can
  be created with tools such as Windows Task Manager or procdump.

```

## how_to_implement

information about how to implement. Only needed for non standard implementations.

`how_to_implement`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Detection Schema](detections-properties-how_to_implement.md "#/properties/how_to_implement#/properties/how_to_implement")

### how_to_implement Type

`string`

### how_to_implement Examples

```yaml
>-
  This search requires Sysmon Logs and a Sysmon configuration, which includes
  EventCode 10 for lsass.exe.

```

## id

UUID as unique identifier

`id`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Detection Schema](detections-properties-id.md "#/properties/id#/properties/id")

### id Type

`string`

### id Examples

```yaml
fb4c31b0-13e8-4155-8aa5-24de4b8d6717

```

## known_false_positives

known false postives

`known_false_positives`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Detection Schema](detections-properties-known_false_positives.md "#/properties/knwon_false_positives#/properties/known_false_positives")

### known_false_positives Type

`string`

### known_false_positives Examples

```yaml
>-
  Administrators can create memory dumps for debugging purposes, but memory
  dumps of the LSASS process would be unusual.

```

## name



`name`

*   is required

*   Type: `string` ([Name of detection](detections-properties-name-of-detection.md))

*   cannot be null

*   defined in: [Detection Schema](detections-properties-name-of-detection.md "#/properties/name#/properties/name")

### name Type

`string` ([Name of detection](detections-properties-name-of-detection.md))

### name Examples

```yaml
Access LSASS Memory for Dump Creation

```

## references

A list of references for this detection

`references`

*   is optional

*   Type: `string[]` ([The Items Schema](detections-properties-references-the-items-schema.md))

*   cannot be null

*   defined in: [Detection Schema](detections-properties-references.md "#/properties/references#/properties/references")

### references Type

`string[]` ([The Items Schema](detections-properties-references-the-items-schema.md))

### references Default Value

The default value is:

```json
[]
```

### references Examples

```yaml
- >-
  https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf

```

## search

The Splunk search for the detection

`search`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Detection Schema](detections-properties-search.md "#/properties/search#/properties/search")

### search Type

`string`

### search Examples

```yaml
>-
  `sysmon` EventCode=10 TargetImage=*lsass.exe CallTrace=*dbgcore.dll* OR
  CallTrace=*dbghelp.dll* | stats count min(_time) as firstTime max(_time) as
  lastTime by Computer, TargetImage, TargetProcessId, SourceImage,
  SourceProcessId | rename Computer as dest |
  `security_content_ctime(firstTime)`| `security_content_ctime(lastTime)` |
  `access_lsass_memory_for_dump_creation_filter`

```

## tags

An array of key value pairs for tagging

`tags`

*   is required

*   Type: `object` ([Details](detections-properties-tags.md))

*   cannot be null

*   defined in: [Detection Schema](detections-properties-tags.md "#/properties/tags#/properties/tags")

### tags Type

`object` ([Details](detections-properties-tags.md))

### tags Constraints

**minimum number of items**: the minimum number of items for this array is: `1`

**unique items**: all items in this array must be unique. Duplicates are not allowed.

### tags Default Value

The default value is:

```json
{}
```

### tags Examples

```yaml
analytic_story: credential_dumping
kill_chain_phases: Action on Objectives
mitre_attack_id: T1078.004
cis20: CIS 13
nist: DE.DP
security domain: network
asset_type: AWS Instance
risk_object: user
risk_object_type: network_artifacts
risk score: '60'
custom_key: custom_value

```

## type

type of detection

`type`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Detection Schema](detections-properties-type.md "#/properties/type#/properties/type")

### type Type

`string`

### type Examples

```yaml
streaming

```

## datamodel

datamodel used in the search

`datamodel`

*   is optional

*   Type: `string[]`

*   cannot be null

*   defined in: [Detection Schema](detections-properties-datamodel.md "#/properties/datamodel#/properties/datamodel")

### datamodel Type

`string[]`

### datamodel Examples

```yaml
Endpoint

```

## version

version of detection, e.g. 1 or 2 ...

`version`

*   is required

*   Type: `integer`

*   cannot be null

*   defined in: [Detection Schema](detections-properties-version.md "#/properties/version#/properties/version")

### version Type

`integer`

### version Examples

```yaml
2

```

## Additional Properties

Additional properties are allowed and do not have to follow a specific schema
