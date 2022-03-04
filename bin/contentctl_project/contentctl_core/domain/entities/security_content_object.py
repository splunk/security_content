import abc

from contentctl_core.domain.entities.enums.enums import SecurityContentType


class SecurityContentObject(abc.ABC):
    type: SecurityContentType
