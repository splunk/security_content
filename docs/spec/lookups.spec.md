
# Lookup Manifest Schema

```
https://api.splunkresearch.com/schemas/lookups.json
```

A object that defines a lookup file and its properties.

| Abstract | Extensible | Status | Identifiable | Custom Properties | Additional Properties | Defined In |
|----------|------------|--------|--------------|-------------------|-----------------------|------------|
| Can be instantiated | No | Experimental | No | Forbidden | Permitted |  |

# Lookup Manifest Properties

| Property | Type | Required | Nullable | Defined by |
|----------|------|----------|----------|------------|
| [case_sensitive_match](#case_sensitive_match) | `enum` | Optional  | No | Lookup Manifest (this schema) |
| [collection](#collection) | `string` | Optional  | No | Lookup Manifest (this schema) |
| [default_match](#default_match) | `string` | Optional  | No | Lookup Manifest (this schema) |
| [description](#description) | `string` | Optional  | No | Lookup Manifest (this schema) |
| [filename](#filename) | `string` | Optional  | No | Lookup Manifest (this schema) |
| [match_type](#match_type) | `string` | Optional  | No | Lookup Manifest (this schema) |
| [max_matches](#max_matches) | `integer` | Optional  | No | Lookup Manifest (this schema) |
| [min_matches](#min_matches) | `integer` | Optional  | No | Lookup Manifest (this schema) |
| [name](#name) | `string` | Optional  | No | Lookup Manifest (this schema) |
| `*` | any | Additional | Yes | this schema *allows* additional properties |

## case_sensitive_match

What the macro is intended to filter

`case_sensitive_match`

* is optional
* type: `enum`
* defined in this schema

The value of this property **must** be equal to one of the [known values below](#case_sensitive_match-known-values).

### case_sensitive_match Known Values
| Value | Description |
|-------|-------------|
| `true` |  |
| `false` |  |



### case_sensitive_match Example

```json
"true"
```


## collection

Name of the collection to use for this lookup

`collection`

* is optional
* type: `string`
* defined in this schema

### collection Type


`string`






### collection Example

```json
"prohibited_apps_launching_cmd"
```


## default_match

The default value if no match is found

`default_match`

* is optional
* type: `string`
* defined in this schema

### default_match Type


`string`






### default_match Example

```json
"true"
```


## description

The description of this lookup

`description`

* is optional
* type: `string`
* defined in this schema

### description Type


`string`






### description Example

```json
"This lookup contains file names that exist in the Windows\\System32 directory"
```


## filename

The name of the file to use for this lookup

`filename`

* is optional
* type: `string`
* defined in this schema

### filename Type


`string`






### filename Example

```json
"prohibited_apps_launching_cmd.csv"
```


## match_type

A comma and space-delimited list of <match_type>(<field_name>) specification to allow for non-exact matching

`match_type`

* is optional
* type: `string`
* defined in this schema

### match_type Type


`string`






### match_type Example

```json
"WILDCARD(process)"
```


## max_matches

The maximum number of possible matches for each input lookup value

`max_matches`

* is optional
* type: `integer`
* defined in this schema

### max_matches Type


`integer`






### max_matches Example

```json
"100"
```


## min_matches

Minimum number of possible matches for each input lookup value

`min_matches`

* is optional
* type: `integer`
* defined in this schema

### min_matches Type


`integer`






### min_matches Example

```json
"1"
```


## name

The name of the lookup to be used in searches

`name`

* is optional
* type: `string`
* defined in this schema

### name Type


`string`






### name Example

```json
"isWindowsSystemFile_lookup"
```



**One** of the following *conditions* need to be fulfilled.


#### Condition 1



#### Condition 2


