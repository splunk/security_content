# Macro Manifest Schema

```txt
https://api.splunkresearch.com/schemas/macros.json
```

An object that defines the parameters for a Splunk Macro

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                            |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :-------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [macros.spec.json](../../out/macros.spec.json "open original schema") |

## Macro Manifest Type

`object` ([Macro Manifest](macros.md))

# Macro Manifest Properties

| Property                    | Type     | Required | Nullable       | Defined by                                                                                                                      |
| :-------------------------- | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------ |
| [arguments](#arguments)     | `array`  | Optional | cannot be null | [Macro Manifest](macros-properties-arguments.md "https://api.splunkresearch.com/schemas/macros.json#/properties/arguments")     |
| [definition](#definition)   | `string` | Optional | cannot be null | [Macro Manifest](macros-properties-definition.md "https://api.splunkresearch.com/schemas/macros.json#/properties/definition")   |
| [description](#description) | `string` | Required | cannot be null | [Macro Manifest](macros-properties-description.md "https://api.splunkresearch.com/schemas/macros.json#/properties/description") |
| [name](#name)               | `string` | Required | cannot be null | [Macro Manifest](macros-properties-name.md "https://api.splunkresearch.com/schemas/macros.json#/properties/name")               |

## arguments

A list of the arguments being passed to this macro

`arguments`

*   is optional

*   Type: `string[]`

*   cannot be null

*   defined in: [Macro Manifest](macros-properties-arguments.md "https://api.splunkresearch.com/schemas/macros.json#/properties/arguments")

### arguments Type

`string[]`

### arguments Constraints

**minimum number of items**: the minimum number of items for this array is: `0`

**unique items**: all items in this array must be unique. Duplicates are not allowed.

## definition

The macro definition

`definition`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Macro Manifest](macros-properties-definition.md "https://api.splunkresearch.com/schemas/macros.json#/properties/definition")

### definition Type

`string`

### definition Examples

```yaml
(query=fls-na* AND query = www* AND query=images*)

```

## description

What the macro is intended to filter

`description`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Macro Manifest](macros-properties-description.md "https://api.splunkresearch.com/schemas/macros.json#/properties/description")

### description Type

`string`

### description Examples

```yaml
Use this macro to filter out known good objects

```

## name

The name of the macro

`name`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Macro Manifest](macros-properties-name.md "https://api.splunkresearch.com/schemas/macros.json#/properties/name")

### name Type

`string`

### name Examples

```yaml
detection_search_output_filter

```
