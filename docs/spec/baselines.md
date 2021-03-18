# Baseline Schema


*schema for baselines*


## Properties


- **`author`** *(string)*: Author of the baseline. Default: ``.

- **`date`** *(string)*: date of creation or modification, format yyyy-mm-dd. Default: ``.

- **`description`** *(string)*: A detailed description of the baseline . Default: ``.

- **`how_to_implement`** *(string)*: information about how to implement. Only needed for non standard implementations. Default: ``.

- **`id`** *(string)*: UUID as unique identifier. Default: ``.

- **`name`** *(string)*: Default: ``.

- **`search`** *(string)*: The Splunk search for the baseline. Default: ``.

- **`tags`** *(object)*: An array of key value pairs for tagging. Can contain additional properties. Default: `{}`.

- **`datamodel`** *(array)*: datamodel used in the search. Default: ``.

  - **Items** *(string)*: Must be one of: `['Endpoint', 'Network_Traffic', 'Authentication', 'Change', 'Change_Analysis', 'Email', 'Endpoint', 'Network_Resolution', 'Network_Sessions', 'Network_Traffic', 'UEBA', 'Updates', 'Vulnerabilities', 'Web']`.

- **`version`** *(integer)*: version of baseline, e.g. 1 or 2 ... Default: `0`.
