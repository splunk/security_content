# Lookup Manifest Schema

```txt
https://api.splunkresearch.com/schemas/lookups.json
```

A object that defines a lookup file and its properties.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                               |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :----------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [lookups.spec.json](../../spec/lookups.spec.json "open original schema") |

## Lookup Manifest Type

`object` ([Lookup Manifest](lookups.md))

one (and only one) of

*   [Untitled undefined type in Lookup Manifest](lookups-oneof-0.md "check type definition")

*   [Untitled undefined type in Lookup Manifest](lookups-oneof-1.md "check type definition")

# Lookup Manifest Properties

| Property                                      | Type      | Required | Nullable       | Defined by                                                                                                                                           |
| :-------------------------------------------- | :-------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------- |
| [case_sensitive_match](#case_sensitive_match) | `string`  | Optional | cannot be null | [Lookup Manifest](lookups-properties-case_sensitive_match.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/case_sensitive_match") |
| [collection](#collection)                     | `string`  | Optional | cannot be null | [Lookup Manifest](lookups-properties-collection.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/collection")                     |
| [default_match](#default_match)               | `string`  | Optional | cannot be null | [Lookup Manifest](lookups-properties-default_match.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/default_match")               |
| [description](#description)                   | `string`  | Optional | cannot be null | [Lookup Manifest](lookups-properties-description.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/description")                   |
| [fields_list](#fields_list)                   | `string`  | Optional | cannot be null | [Lookup Manifest](lookups-properties-fields_list.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/fields_list")                   |
| [filename](#filename)                         | `string`  | Optional | cannot be null | [Lookup Manifest](lookups-properties-filename.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/filename")                         |
| [filter](#filter)                             | `string`  | Optional | cannot be null | [Lookup Manifest](lookups-properties-filter.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/filter")                             |
| [match_type](#match_type)                     | `string`  | Optional | cannot be null | [Lookup Manifest](lookups-properties-match_type.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/match_type")                     |
| [max_matches](#max_matches)                   | `integer` | Optional | cannot be null | [Lookup Manifest](lookups-properties-max_matches.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/max_matches")                   |
| [min_matches](#min_matches)                   | `integer` | Optional | cannot be null | [Lookup Manifest](lookups-properties-min_matches.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/min_matches")                   |
| [name](#name)                                 | `string`  | Optional | cannot be null | [Lookup Manifest](lookups-properties-name.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/name")                                 |

## case_sensitive_match

What the macro is intended to filter

`case_sensitive_match`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Lookup Manifest](lookups-properties-case_sensitive_match.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/case_sensitive_match")

### case_sensitive_match Type

`string`

### case_sensitive_match Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value     | Explanation |
| :-------- | :---------- |
| `"true"`  |             |
| `"false"` |             |

### case_sensitive_match Examples

```yaml
'true'

```

## collection

Name of the collection to use for this lookup

`collection`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Lookup Manifest](lookups-properties-collection.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/collection")

### collection Type

`string`

### collection Examples

```yaml
prohibited_apps_launching_cmd

```

## default_match

The default value if no match is found

`default_match`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Lookup Manifest](lookups-properties-default_match.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/default_match")

### default_match Type

`string`

### default_match Examples

```yaml
'true'

```

## description

The description of this lookup

`description`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Lookup Manifest](lookups-properties-description.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/description")

### description Type

`string`

### description Examples

```yaml
This lookup contains file names that exist in the Windows\System32 directory

```

## fields_list

A comma and space separated list of field names

`fields_list`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Lookup Manifest](lookups-properties-fields_list.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/fields_list")

### fields_list Type

`string`

### fields_list Examples

```yaml
_key, dest, process_name

```

## filename

The name of the file to use for this lookup

`filename`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Lookup Manifest](lookups-properties-filename.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/filename")

### filename Type

`string`

### filename Examples

```yaml
prohibited_apps_launching_cmd.csv

```

## filter

Use this attribute to improve search performance when working with significantly large KV

`filter`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Lookup Manifest](lookups-properties-filter.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/filter")

### filter Type

`string`

### filter Examples

```yaml
dest="SPLK_*"

```

## match_type

A comma and space-delimited list of \<match_type>(\<field_name>) specification to allow for non-exact matching

`match_type`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Lookup Manifest](lookups-properties-match_type.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/match_type")

### match_type Type

`string`

### match_type Examples

```yaml
WILDCARD(process)

```

## max_matches

The maximum number of possible matches for each input lookup value

`max_matches`

*   is optional

*   Type: `integer`

*   cannot be null

*   defined in: [Lookup Manifest](lookups-properties-max_matches.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/max_matches")

### max_matches Type

`integer`

### max_matches Examples

```yaml
'100'

```

## min_matches

Minimum number of possible matches for each input lookup value

`min_matches`

*   is optional

*   Type: `integer`

*   cannot be null

*   defined in: [Lookup Manifest](lookups-properties-min_matches.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/min_matches")

### min_matches Type

`integer`

### min_matches Examples

```yaml
'1'

```

## name

The name of the lookup to be used in searches

`name`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Lookup Manifest](lookups-properties-name.md "https://api.splunkresearch.com/schemas/lookups.json#/properties/name")

### name Type

`string`

### name Examples

```yaml
isWindowsSystemFile_lookup

```
