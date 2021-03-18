# Detection Schema


*schema for detections*


## Properties


- **`author`** *(string)*: Author of the detection. Default: ``.

- **`date`** *(string)*: date of creation or modification, format yyyy-mm-dd. Default: ``.

- **`description`** *(string)*: A detailed description of the detection. Default: ``.

- **`how_to_implement`** *(string)*: information about how to implement. Only needed for non standard implementations. Default: ``.

- **`id`** *(string)*: UUID as unique identifier. Default: ``.

- **`known_false_positives`** *(string)*: known false postives. Default: ``.

- **`name`** *(string)*: Default: ``.

- **`references`** *(array)*: A list of references for this detection. Default: `[]`.

  - **Items** *(string)*: An explanation about the purpose of this instance. Default: ``.

- **`search`** *(string)*: The Splunk search for the detection. Default: ``.

- **`tags`** *(object)*: An array of key value pairs for tagging. Can contain additional properties. Default: `{}`.

- **`type`** *(string)*: type of detection. Default: ``.

  - **Items** *(string)*: Must be one of: `['batch', 'streaming']`.

- **`datamodel`** *(array)*: datamodel used in the search. Default: ``.

  - **Items** *(string)*: Must be one of: `['Endpoint', 'Network_Traffic', 'Authentication', 'Change', 'Change_Analysis', 'Email', 'Endpoint', 'Network_Resolution', 'Network_Sessions', 'Network_Traffic', 'UEBA', 'Updates', 'Vulnerabilities', 'Web']`.

- **`version`** *(integer)*: version of detection, e.g. 1 or 2 ... Default: `0`.
