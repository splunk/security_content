# Response Schema Schema

```txt
http://example.com/example.json
```

schema for phase

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                               |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :--------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [responses_phase.spec.json](../../spec/responses_phase.spec.json "open original schema") |

## Response Schema Type

`object` ([Response Schema](responses_phase.md))

## Response Schema Default Value

The default value is:

```json
{}
```

# Response Schema Properties

| Property                        | Type      | Required | Nullable       | Defined by                                                                                                            |
| :------------------------------ | :-------- | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------- |
| [author](#author)               | `string`  | Required | cannot be null | [Response Schema](responses_phase-properties-author.md "#/properties/author#/properties/author")                      |
| [date](#date)                   | `string`  | Required | cannot be null | [Response Schema](responses_phase-properties-date.md "#/properties/date#/properties/date")                            |
| [description](#description)     | `string`  | Required | cannot be null | [Response Schema](responses_phase-properties-description.md "#/properties/description#/properties/description")       |
| [id](#id)                       | `string`  | Required | cannot be null | [Response Schema](responses_phase-properties-id.md "#/properties/id#/properties/id")                                  |
| [name](#name)                   | `string`  | Required | cannot be null | [Response Schema](responses_phase-properties-name.md "#/properties/name#/properties/name")                            |
| [response_task](#response_task) | `array`   | Required | cannot be null | [Response Schema](responses_phase-properties-response_task.md "#/properties/response_task#/properties/response_task") |
| [tags](#tags)                   | `object`  | Required | cannot be null | [Response Schema](responses_phase-properties-tags.md "#/properties/tags#/properties/tags")                            |
| [version](#version)             | `integer` | Required | cannot be null | [Response Schema](responses_phase-properties-version.md "#/properties/version#/properties/version")                   |
| [sla](#sla)                     | `integer` | Optional | cannot be null | [Response Schema](responses_phase-properties-sla.md "#/properties/sla#/properties/sla")                               |
| [sla_type](#sla_type)           | `string`  | Optional | cannot be null | [Response Schema](responses_phase-properties-sla_type.md "#/properties/sla_type#/properties/sla_type")                |
| [references](#references)       | `array`   | Optional | cannot be null | [Response Schema](responses_phase-properties-references.md "#/properties/references#/properties/references")          |
| Additional Properties           | Any       | Optional | can be null    |                                                                                                                       |

## author

Author of the phase

`author`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Response Schema](responses_phase-properties-author.md "#/properties/author#/properties/author")

### author Type

`string`

### author Examples

```yaml
Rico Valdez, Patrick Bareiß, Splunk

```

## date

date of creation or modification, format yyyy-mm-dd

`date`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Response Schema](responses_phase-properties-date.md "#/properties/date#/properties/date")

### date Type

`string`

### date Examples

```yaml
'2019-12-06'

```

## description

Description of phase

`description`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Response Schema](responses_phase-properties-description.md "#/properties/description#/properties/description")

### description Type

`string`

### description Examples

```yaml
Response phase descripion.

```

## id

UUID as unique identifier

`id`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Response Schema](responses_phase-properties-id.md "#/properties/id#/properties/id")

### id Type

`string`

### id Examples

```yaml
fb4c31b0-13e8-4155-8aa5-24de4b8d6717

```

## name

Name of phase

`name`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Response Schema](responses_phase-properties-name.md "#/properties/name#/properties/name")

### name Type

`string`

### name Examples

```yaml
Preparation

```

## response_task

Response phase is divided into task(s) to be completed. These will used to referenced known response_task parameters. Order is as positioned and with unique name.

`response_task`

*   is required

*   Type: `array`

*   cannot be null

*   defined in: [Response Schema](responses_phase-properties-response_task.md "#/properties/response_task#/properties/response_task")

### response_task Type

`array`

### response_task Constraints

**minimum number of items**: the minimum number of items for this array is: `1`

### response_task Default Value

The default value is:

```json
{}
```

### response_task Examples

```yaml
id: 7c72d944-3995-4485-8e57-67b4c353989b
name: Prepare for Incident Handling

```

```yaml
id: c36f3f48-e0bb-4c20-a62a-cdc8f6418892
name: Preventing Incidents

```

```yaml
id: 0dc849b2-2eb4-4fd2-add1-b6cc475765f0
name: Practice

```

## tags

An array of key value pairs for tagging

`tags`

*   is required

*   Type: `object` ([Details](responses_phase-properties-tags.md))

*   cannot be null

*   defined in: [Response Schema](responses_phase-properties-tags.md "#/properties/tags#/properties/tags")

### tags Type

`object` ([Details](responses_phase-properties-tags.md))

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

```

## version

version of detection, e.g. 1 or 2 ...

`version`

*   is required

*   Type: `integer`

*   cannot be null

*   defined in: [Response Schema](responses_phase-properties-version.md "#/properties/version#/properties/version")

### version Type

`integer`

### version Examples

```yaml
1

```

## sla

Measured integer for Service Level Agreement for completion of the phase

`sla`

*   is optional

*   Type: `integer`

*   cannot be null

*   defined in: [Response Schema](responses_phase-properties-sla.md "#/properties/sla#/properties/sla")

### sla Type

`integer`

### sla Examples

```yaml
5

```

```yaml
30

```

## sla_type

Duration for measured integer for Service Level Agreement for completion of the phase (e.g. minutes, or hours, etc)

`sla_type`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Response Schema](responses_phase-properties-sla_type.md "#/properties/sla_type#/properties/sla_type")

### sla_type Type

`string`

### sla_type Default Value

The default value is:

```json
"minutes"
```

### sla_type Examples

```yaml
minutes

```

```yaml
hours

```

```yaml
days

```

## references

A list of references for this response, phase or task (e.g. web or printed citation)

`references`

*   is optional

*   Type: `string[]` ([3.1 Preparation](responses_phase-properties-references-31-preparation.md))

*   cannot be null

*   defined in: [Response Schema](responses_phase-properties-references.md "#/properties/references#/properties/references")

### references Type

`string[]` ([3.1 Preparation](responses_phase-properties-references-31-preparation.md))

### references Default Value

The default value is:

```json
[]
```

### references Examples

```yaml
https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf

```

## Additional Properties

Additional properties are allowed and do not have to follow a specific schema
