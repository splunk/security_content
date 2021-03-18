# Lookup Manifest


*A object that defines a lookup file and its properties.*


## Properties


- **`case_sensitive_match`** *(string)*: What the macro is intended to filter. Must be one of: `['true', 'false']`.

- **`collection`** *(string)*: Name of the collection to use for this lookup.

- **`default_match`** *(string)*: The default value if no match is found.

- **`description`** *(string)*: The description of this lookup.

- **`fields_list`** *(string)*: A comma and space separated list of field names.

- **`filename`** *(string)*: The name of the file to use for this lookup.

- **`filter`** *(string)*: Use this attribute to improve search performance when working with significantly large KV.

- **`match_type`** *(string)*: A comma and space-delimited list of <match_type>(<field_name>) specification to allow for non-exact matching.

- **`max_matches`** *(integer)*: The maximum number of possible matches for each input lookup value.

- **`min_matches`** *(integer)*: Minimum number of possible matches for each input lookup value.

- **`name`** *(string)*: The name of the lookup to be used in searches.
