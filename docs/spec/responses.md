# Response Schema


*schema for response*


## Properties


- **`author`** *(string)*: Author of the response. Default: ``.

- **`date`** *(string)*: date of creation or modification, format yyyy-mm-dd. Default: ``.

- **`description`** *(string)*: Description of response. Default: ``.

- **`id`** *(string)*: UUID as unique identifier. Default: ``.

- **`name`** *(string)*: Name of response. Default: ``.

- **`response_phase`** *(array)*: Response divided into phases. These will used to referenced known response_phase parameters. Can contain additional properties. Default: `{}`.

- **`tags`** *(object)*: An array of key value pairs for tagging. Can contain additional properties. Default: `{}`.

- **`version`** *(integer)*: version of detection, e.g. 1 or 2 ... Default: `0`.

- **`is_note_required`** *(boolean)*: Global assignment for notes being required for tasks, can be individually set in the task. Default: `False`.

- **`references`** *(array)*: A list of references for this response, phase or task (e.g. web or printed citation). Default: `[]`.

  - **Items** *(string)*: An explanation about the purpose of this instance. Default: ``.
