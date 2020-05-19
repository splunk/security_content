
# Macro Manifest Schema

```
https://api.splunkresearch.com/schemas/macros.json
```

An object that defines the parameters for a Splunk Macro

| Abstract | Extensible | Status | Identifiable | Custom Properties | Additional Properties | Defined In |
|----------|------------|--------|--------------|-------------------|-----------------------|------------|
| Can be instantiated | No | Experimental | No | Forbidden | Permitted |  |

# Macro Manifest Properties

| Property | Type | Required | Nullable | Defined by |
|----------|------|----------|----------|------------|
| [arguments](#arguments) | `string[]` | Optional  | No | Macro Manifest (this schema) |
| [definition](#definition) | `string` | Optional  | No | Macro Manifest (this schema) |
| [description](#description) | `string` | **Required**  | No | Macro Manifest (this schema) |
| [name](#name) | `string` | **Required**  | No | Macro Manifest (this schema) |
| `*` | any | Additional | Yes | this schema *allows* additional properties |

## arguments

A list of the arguments being passed to this macro

`arguments`

* is optional
* type: `string[]`
* at least `0` items in the array
* defined in this schema

### arguments Type


Array type: `string[]`

All items must be of the type:
`string`










## definition

The macro definition

`definition`

* is optional
* type: `string`
* defined in this schema

### definition Type


`string`






### definition Example

```json
"(query=fls-na* AND query = www* AND query=images*)"
```


## description

What the macro is intended to filter

`description`

* is **required**
* type: `string`
* defined in this schema

### description Type


`string`






### description Example

```json
"Use this macro to filter out known good objects"
```


## name

The name of the macro

`name`

* is **required**
* type: `string`
* defined in this schema

### name Type


`string`






### name Example

```json
"detection_search_output_filter"
```

