# Analytics Story Schema Schema

```txt
http://example.com/example.json
```

schema analytics story

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                              |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [stories.spec.json](../../out/stories.spec.json "open original schema") |

## Analytics Story Schema Type

`object` ([Analytics Story Schema](stories.md))

## Analytics Story Schema Default Value

The default value is:

```json
{}
```

# Analytics Story Schema Properties

| Property                    | Type      | Required | Nullable       | Defined by                                                                                                     |
| :-------------------------- | :-------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------- |
| [author](#author)           | `string`  | Required | cannot be null | [Analytics Story Schema](stories-properties-author.md "#/properties/author#/properties/author")                |
| [date](#date)               | `string`  | Required | cannot be null | [Analytics Story Schema](stories-properties-date.md "#/properties/date#/properties/date")                      |
| [description](#description) | `string`  | Required | cannot be null | [Analytics Story Schema](stories-properties-description.md "#/properties/description#/properties/description") |
| [id](#id)                   | `string`  | Required | cannot be null | [Analytics Story Schema](stories-properties-id.md "#/properties/id#/properties/id")                            |
| [name](#name)               | `string`  | Required | cannot be null | [Analytics Story Schema](stories-properties-name.md "#/properties/name#/properties/name")                      |
| [narrative](#narrative)     | `string`  | Required | cannot be null | [Analytics Story Schema](stories-properties-narrative.md "#/properties/narrative#/properties/narrative")       |
| [search](#search)           | `string`  | Optional | cannot be null | [Analytics Story Schema](stories-properties-search.md "#/properties/search#/properties/search")                |
| [tags](#tags)               | `object`  | Required | cannot be null | [Analytics Story Schema](stories-properties-tags.md "#/properties/tags#/properties/tags")                      |
| [version](#version)         | `integer` | Required | cannot be null | [Analytics Story Schema](stories-properties-version.md "#/properties/version#/properties/version")             |
| Additional Properties       | Any       | Optional | can be null    |                                                                                                                |

## author

Author of the analytics story

`author`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Analytics Story Schema](stories-properties-author.md "#/properties/author#/properties/author")

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

*   defined in: [Analytics Story Schema](stories-properties-date.md "#/properties/date#/properties/date")

### date Type

`string`

### date Examples

```yaml
'2019-12-06'

```

## description

description of the analytics story

`description`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Analytics Story Schema](stories-properties-description.md "#/properties/description#/properties/description")

### description Type

`string`

### description Examples

```yaml
>-
  Uncover activity consistent with credential dumping, a technique where
  attackers compromise systems and attempt to obtain and exfiltrate passwords.

```

## id

UUID as unique identifier

`id`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Analytics Story Schema](stories-properties-id.md "#/properties/id#/properties/id")

### id Type

`string`

### id Examples

```yaml
fb4c31b0-13e8-4155-8aa5-24de4b8d6717

```

## name

Name of the Analytics Story

`name`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Analytics Story Schema](stories-properties-name.md "#/properties/name#/properties/name")

### name Type

`string`

### name Examples

```yaml
Credential Dumping

```

## narrative

narrative of the analytics story

`narrative`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Analytics Story Schema](stories-properties-narrative.md "#/properties/narrative#/properties/narrative")

### narrative Type

`string`

### narrative Examples

```yaml
>-
  gathering credentials from a target system, often hashed or encrypted, is a
  common attack technique. Even though the credentials may not be in plain text,
  an attacker can still exfiltrate the data and set to cracking it offline, on
  their own systems.

```

## search

An additional Splunk search, which uses the result of the detections

`search`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Analytics Story Schema](stories-properties-search.md "#/properties/search#/properties/search")

### search Type

`string`

### search Examples

```yaml
>-
  index=asx mitre_id=t1003 | stats values(source) as detections values(process)
  as processes values(user) as users values(_time) as time count by dest

```

## tags

An explanation about the purpose of this instance.

`tags`

*   is required

*   Type: `object` ([Details](stories-properties-tags.md))

*   cannot be null

*   defined in: [Analytics Story Schema](stories-properties-tags.md "#/properties/tags#/properties/tags")

### tags Type

`object` ([Details](stories-properties-tags.md))

### tags Constraints

**minimum number of items**: the minimum number of items for this array is: `1`

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

version of analytics story, e.g. 1 or 2 ...

`version`

*   is required

*   Type: `integer`

*   cannot be null

*   defined in: [Analytics Story Schema](stories-properties-version.md "#/properties/version#/properties/version")

### version Type

`integer`

### version Examples

```yaml
1

```

## Additional Properties

Additional properties are allowed and do not have to follow a specific schema
