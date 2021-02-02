# Response Schema Schema

```txt
https://raw.githubusercontent.com/splunk/security_content/develop/docs/spec/response.spec.json
```

schema for response

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                  |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :-------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [responses.spec.json](../../out/responses.spec.json "open original schema") |

## Response Schema Type

`object` ([Response Schema](responses.md))

## Response Schema Default Value

The default value is:

```json
{}
```

# Response Schema Properties

| Property                              | Type      | Required | Nullable       | Defined by                                                                                                               |
| :------------------------------------ | :-------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------- |
| [author](#author)                     | `string`  | Required | cannot be null | [Response Schema](responses-properties-author.md "#/properties/author#/properties/author")                               |
| [date](#date)                         | `string`  | Required | cannot be null | [Response Schema](responses-properties-date.md "#/properties/date#/properties/date")                                     |
| [description](#description)           | `string`  | Required | cannot be null | [Response Schema](responses-properties-description.md "#/properties/description#/properties/description")                |
| [id](#id)                             | `string`  | Required | cannot be null | [Response Schema](responses-properties-id.md "#/properties/id#/properties/id")                                           |
| [name](#name)                         | `string`  | Required | cannot be null | [Response Schema](responses-properties-name.md "#/properties/name#/properties/name")                                     |
| [response_phase](#response_phase)     | `array`   | Required | cannot be null | [Response Schema](responses-properties-response_phase.md "#/properties/response_phases#/properties/response_phase")      |
| [tags](#tags)                         | `object`  | Required | cannot be null | [Response Schema](responses-properties-tags.md "#/properties/tags#/properties/tags")                                     |
| [version](#version)                   | `integer` | Required | cannot be null | [Response Schema](responses-properties-version.md "#/properties/version#/properties/version")                            |
| [is_note_required](#is_note_required) | `boolean` | Optional | cannot be null | [Response Schema](responses-properties-is_note_required.md "#/properties/is_note_required#/properties/is_note_required") |
| [references](#references)             | `array`   | Optional | cannot be null | [Response Schema](responses-properties-references.md "#/properties/references#/properties/references")                   |
| Additional Properties                 | Any       | Optional | can be null    |                                                                                                                          |

## author

Author of the response

`author`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Response Schema](responses-properties-author.md "#/properties/author#/properties/author")

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

*   defined in: [Response Schema](responses-properties-date.md "#/properties/date#/properties/date")

### date Type

`string`

### date Examples

```yaml
'2019-12-06'

```

## description

Description of response

`description`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Response Schema](responses-properties-description.md "#/properties/description#/properties/description")

### description Type

`string`

### description Examples

```yaml
Response example.

```

## id

UUID as unique identifier

`id`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Response Schema](responses-properties-id.md "#/properties/id#/properties/id")

### id Type

`string`

### id Examples

```yaml
fb4c31b0-13e8-4155-8aa5-24de4b8d6717

```

## name

Name of response

`name`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Response Schema](responses-properties-name.md "#/properties/name#/properties/name")

### name Type

`string`

### name Examples

```yaml
Response Example

```

## response_phase

Response divided into phases. These will used to referenced known response_phase parameters

`response_phase`

*   is required

*   Type: `array`

*   cannot be null

*   defined in: [Response Schema](responses-properties-response_phase.md "#/properties/response_phases#/properties/response_phase")

### response_phase Type

`array`

### response_phase Constraints

**minimum number of items**: the minimum number of items for this array is: `1`

### response_phase Default Value

The default value is:

```json
{}
```

### response_phase Examples

```yaml
preparation:
  - id: 7c72d944-3995-4485-8e57-67b4c353989b
    name: Preparation NIST
identification:
  - id: c36f3f48-e0bb-4c20-a62a-cdc8f6418892
    name: Detection and Analysis
  - id: 0dc849b2-2eb4-4fd2-add1-b6cc475765f0
    name: Analysis

```

## tags

An array of key value pairs for tagging

`tags`

*   is required

*   Type: `object` ([Details](responses-properties-tags.md))

*   cannot be null

*   defined in: [Response Schema](responses-properties-tags.md "#/properties/tags#/properties/tags")

### tags Type

`object` ([Details](responses-properties-tags.md))

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
analytics_story: credential_dumping

```

## version

version of detection, e.g. 1 or 2 ...

`version`

*   is required

*   Type: `integer`

*   cannot be null

*   defined in: [Response Schema](responses-properties-version.md "#/properties/version#/properties/version")

### version Type

`integer`

### version Examples

```yaml
1

```

## is_note_required

Global assignment for notes being required for tasks, can be individually set in the task

`is_note_required`

*   is optional

*   Type: `boolean`

*   cannot be null

*   defined in: [Response Schema](responses-properties-is_note_required.md "#/properties/is_note_required#/properties/is_note_required")

### is_note_required Type

`boolean`

### is_note_required Examples

```yaml
true

```

```yaml
false

```

## references

A list of references for this response, phase or task (e.g. web or printed citation)

`references`

*   is optional

*   Type: `string[]` ([Blue Team Handbook by Don Murdoch - Amazon](responses-properties-references-blue-team-handbook-by-don-murdoch---amazon.md))

*   cannot be null

*   defined in: [Response Schema](responses-properties-references.md "#/properties/references#/properties/references")

### references Type

`string[]` ([Blue Team Handbook by Don Murdoch - Amazon](responses-properties-references-blue-team-handbook-by-don-murdoch---amazon.md))

### references Default Value

The default value is:

```json
[]
```

### references Examples

```yaml
- Blue Team Handbook by Don Murdoch - Alarm Triage Overview pages 146-148
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf

```

## Additional Properties

Additional properties are allowed and do not have to follow a specific schema
