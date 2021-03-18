# Response Schema


*schema for phase*


## Properties


- **`author`** *(string)*: Author of the phase. Default: ``.

- **`date`** *(string)*: date of creation or modification, format yyyy-mm-dd. Default: ``.

- **`description`** *(string)*: Description of phase. Default: ``.

- **`id`** *(string)*: UUID as unique identifier. Default: ``.

- **`name`** *(string)*: Name of phase. Default: ``.

- **`response_task`** *(array)*: Response phase is divided into task(s) to be completed. These will used to referenced known response_task parameters. Order is as positioned and with unique name. Can contain additional properties. Default: `{}`.

- **`tags`** *(object)*: An array of key value pairs for tagging. Can contain additional properties. Default: `{}`.

- **`version`** *(integer)*: version of detection, e.g. 1 or 2 ... Default: `0`.

- **`sla`** *(integer)*: Measured integer for Service Level Agreement for completion of the phase. Default: `None`.

- **`sla_type`** *(string)*: Duration for measured integer for Service Level Agreement for completion of the phase (e.g. minutes, or hours, etc). Default: `minutes`.

- **`references`** *(array)*: A list of references for this response, phase or task (e.g. web or printed citation). Default: `[]`.

  - **Items** *(string)*: An explanation about the purpose of this instance. Default: ``.
